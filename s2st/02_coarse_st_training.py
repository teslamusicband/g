"""
Этап 2: Coarse ST Training — основной этап обучения base-модели.

Цель (из optimal_neural_codec_s2st_architecture.md, "Этап 1: Coarse ST Training"):
  Обучить Temporal + Depth Transformer предсказывать target audio-токены conditioned
  на source audio-токенах (multistream), используя sentence-level aligned пары с
  silence insertion. Это создаёт base-модель, которая уже умеет переводить, но с
  высоким (неоптимальным) latency — тайминг далее улучшается GRPO (этап 3).

Параметры обучения (из статей):
  - Инициализация: Helium-1 (Temporal, frozen Mimi codec)
  - LR (Temporal): 3e-6
  - LR (Depth):    5e-5
  - Batch: ~96-144 sequences
  - Steps: 150-500K (Hibiki-Zero: 400K updates для multilingual)
  - Multistream: да (concat source + target), loss на обоих потоках
  - Данные: sentence-aligned S2ST пары с silence insertion (delta=0.5, mu=2)

Loss (multitask):
  L = L_text (Inner Monologue) + L_target_audio (CE по codebooks) + alpha * L_source_audio
  - L_text:         CE на текстовых токенах W_t
  - L_target_audio: CE на target RVQ-токенах (основной сигнал)
  - L_source_audio: CE на source RVQ-токенах (вспомогательный, alpha — малый вес)

Распределённое обучение: FSDP (Fully Sharded Data Parallel) + bf16 на 8× H200.

Источники: arXiv:2410.00037 (Moshi, LR 3e-6/5e-5), arXiv:2602.11072 (Hibiki-Zero, 400K updates).
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader


# =============================================================================
# 2.1. Конфигурация обучения
# =============================================================================
TRAIN_CONFIG = {
    # Оптимизатор
    "lr_temporal": 3e-6,         # Moshi: LR для Temporal
    "lr_depth": 5e-5,            # Moshi: LR для Depth
    "weight_decay": 0.01,
    "betas": (0.9, 0.95),
    "grad_clip": 1.0,

    # Batch / расписание
    "batch_size": 8,             # [в проде] 96-144 (per-GPU меньше, с grad accumulation)
    "grad_accum_steps": 12,      # для эффективного batch ~96 на 8 GPU
    "max_steps": 400_000,        # Hibiki-Zero: 400K updates (multilingual)
    "warmup_steps": 2000,
    "lr_schedule": "cosine",

    # Loss
    "loss_weight_text": 1.0,
    "loss_weight_target": 1.0,
    "loss_weight_source": 0.1,   # вспомогательный loss на source-потоке

    # Precision / распределение
    "dtype": "bfloat16",
    "fsdp": True,                # FSDP на 8× H200

    # Длина последовательности
    "max_seq_len": 4096,         # токенов (time × per_step)
}


# =============================================================================
# 2.2. Multitask loss
# =============================================================================
def compute_multitask_loss(
    output: dict,
    target_text: torch.Tensor | None,
    target_audio: torch.Tensor,
    source_audio: torch.Tensor,
    kinds: torch.Tensor,
    cfg: dict = TRAIN_CONFIG,
) -> tuple[torch.Tensor, dict]:
    """
    Вычисляет multitask loss.

    Аргументы:
        output: словарь {kind: (mask, logits)} из MultiKindOutputHead.
        target_text:  (B, T) — ground-truth текстовые токены (или None).
        target_audio: (B, Q, T) — ground-truth target RVQ (с acoustic delay).
        source_audio: (B, Q, T) — actual source RVQ (с acoustic delay).
        kinds: (B, S) — kind_ids последовательности.
        cfg:   конфигурация с весами loss.

    Возвращает:
        loss: скаляр.
        log:  словарь с компонентами loss для логирования.
    """
    log = {}
    total = torch.tensor(0.0, device=next(iter(output.values()))[1].device)

    # Здесь output — словарь {kind: (mask, logits)}.
    # Для корректного подсчёта нужны ground-truth target IDs, выровненные с маской.
    # В упрощённом виде: для каждого kind считаем CE между предсказанием и соответствующим GT.
    #
    # [warn] В реальной реализации нужно выровнять позиции: output[kind] содержит logits
    # для токенов этого kind в порядке их появления; GT должен быть собран в том же порядке
    # из flatten-последовательности. Ниже — структурный каркас.

    Q = target_audio.shape[1]

    # Text loss (Inner Monologue)
    if target_text is not None and 0 in output:
        mask, logits = output[0]
        # GT text tokens, собранные по маске
        gt_text = target_text.reshape(-1)[:logits.shape[0]]
        l_text = F.cross_entropy(logits, gt_text)
        total = total + cfg["loss_weight_text"] * l_text
        log["loss_text"] = l_text.item()

    # Target audio loss (по codebooks)
    tgt_losses = []
    for q in range(Q):
        kind = 1 + q
        if kind in output:
            mask, logits = output[kind]
            gt_q = target_audio[:, q].reshape(-1)[:logits.shape[0]]
            l_q = F.cross_entropy(logits, gt_q)
            tgt_losses.append(l_q)
    if tgt_losses:
        l_target = torch.stack(tgt_losses).mean()
        total = total + cfg["loss_weight_target"] * l_target
        log["loss_target"] = l_target.item()

    # Source audio loss (вспомогательный)
    src_losses = []
    for q in range(Q):
        kind = 1 + Q + q
        if kind in output:
            mask, logits = output[kind]
            gt_q = source_audio[:, q].reshape(-1)[:logits.shape[0]]
            l_q = F.cross_entropy(logits, gt_q)
            src_losses.append(l_q)
    if src_losses:
        l_source = torch.stack(src_losses).mean()
        total = total + cfg["loss_weight_source"] * l_source
        log["loss_source"] = l_source.item()

    log["loss_total"] = total.item()
    return total, log


# =============================================================================
# 2.3. Расписание LR (cosine with warmup)
# =============================================================================
def get_lr(step: int, cfg: dict = TRAIN_CONFIG) -> float:
    """Cosine LR schedule с linear warmup. Возвращает множитель (0..1)."""
    if step < cfg["warmup_steps"]:
        return step / cfg["warmup_steps"]
    progress = (step - cfg["warmup_steps"]) / max(1, cfg["max_steps"] - cfg["warmup_steps"])
    return 0.5 * (1 + torch.cos(torch.tensor(progress * 3.14159)).item())


# =============================================================================
# 2.4. Тренировочный цикл (с FSDP)
# =============================================================================
def train_coarse_st(
    model: nn.Module,
    dataloader: DataLoader,
    cfg: dict = TRAIN_CONFIG,
    device: str = "cuda",
):
    """
    Основной тренировочный цикл Coarse ST Training.

    Аргументы:
        model:     NeuralCodecS2ST (см. 01e_full_model.py).
        dataloader: загрузчик sentence-aligned пар (source_tokens, target_tokens, text_tokens).
        cfg:       конфигурация обучения.
        device:    'cuda'.

    Особенности:
      - Разные LR для Temporal (3e-6) и Depth (5e-5) — через param groups.
      - FSDP шардирование параметров/градиентов/optimizer-states по 8 GPU.
      - bf16 mixed precision.
      - Gradient accumulation для эффективного batch.
    """
    import os
    world_size = int(os.environ.get("WORLD_SIZE", 1))
    rank = int(os.environ.get("RANK", 0))

    # --- FSDP-обёртка (на 8 GPU) ---
    if cfg["fsdp"] and world_size > 1:
        from torch.distributed.fsdp import FullyShardedDataParallel as FSDP
        from torch.distributed.fsdp import MixedPrecision, ShardingStrategy
        mp = MixedPrecision(param_dtype=torch.bfloat16,
                            reduce_dtype=torch.bfloat16, buffer_dtype=torch.bfloat16)
        model = FSDP(model, sharding_strategy=ShardingStrategy.FULL_SHARD,
                     mixed_precision=mp, device_id=rank)

    # --- Param groups: разные LR для Temporal и Depth ---
    temporal_params = list(model.temporal.parameters())
    depth_params = list(model.depth.parameters())
    other_params = [p for n, p in model.named_parameters()
                    if not n.startswith("temporal") and not n.startswith("depth")
                    and p.requires_grad]
    optimizer = torch.optim.AdamW([
        {"params": temporal_params, "lr": cfg["lr_temporal"]},
        {"params": depth_params, "lr": cfg["lr_depth"]},
        {"params": other_params, "lr": cfg["lr_temporal"]},
    ], betas=cfg["betas"], weight_decay=cfg["weight_decay"])

    model.train()
    step = 0
    optimizer.zero_grad()

    while step < cfg["max_steps"]:
        for batch in dataloader:
            if step >= cfg["max_steps"]:
                break
            source_tokens, target_tokens, text_tokens = batch
            source_tokens = source_tokens.to(device)
            target_tokens = target_tokens.to(device)
            if text_tokens is not None:
                text_tokens = text_tokens.to(device)

            # Forward (bf16 autocast)
            with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                output = model(source_tokens, target_tokens, text_tokens)
                loss, log = compute_multitask_loss(
                    output, text_tokens, target_tokens, source_tokens,
                    kinds=None, cfg=cfg
                )
                loss = loss / cfg["grad_accum_steps"]

            # Backward
            loss.backward()

            # Gradient accumulation
            if (step + 1) % cfg["grad_accum_steps"] == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), cfg["grad_clip"])
                # Обновление LR
                lr_mul = get_lr(step, cfg)
                for pg in optimizer.param_groups:
                    pg["lr"] = pg["lr"] * lr_mul if step == 0 else pg["lr"]
                optimizer.step()
                optimizer.zero_grad()

            if rank == 0 and step % 100 == 0:
                print(f"[step {step}] {log}")
            step += 1

    # Сохранение финального чекпоинта
    if rank == 0:
        torch.save(model.state_dict(), "/data/checkpoints/coarse_st_final.pt")
        print("[done] Coarse ST training завершён, чекпоинт сохранён.")


# =============================================================================
# 2.5. Запуск через torchrun (8 GPU)
# =============================================================================
# Команда запуска:
#   torchrun --nproc_per_node=8 02_coarse_st_training.py
#
if __name__ == "__main__":
    import os
    if "RANK" in os.environ:
        import torch.distributed as dist
        dist.init_process_group(backend="nccl")
        torch.cuda.set_device(int(os.environ["LOCAL_RANK"]))

    print("Этап 2: Coarse ST Training")
    print(f"  LR: temporal={TRAIN_CONFIG['lr_temporal']}, depth={TRAIN_CONFIG['lr_depth']}")
    print(f"  Steps: {TRAIN_CONFIG['max_steps']}, batch≈{TRAIN_CONFIG['batch_size']*TRAIN_CONFIG['grad_accum_steps']}")
    print("  [warn] Подключите реальный dataloader (sentence-aligned пары).")
    # train_coarse_st(model, dataloader)  # раскомментировать в проде
