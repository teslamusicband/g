"""
Этап 4: Адаптация к русскому голосу и домену.

Цель (из optimal_neural_codec_s2st_architecture.md, "Этап 3: Адаптация"):
  После GRPO (этап 3) выполнить финальную адаптацию под:
  1. Русский язык/домен (звонки) — light fine-tuning на имеющихся 2K часов.
  2. Voice transfer — сохранение голоса говорящего через 10-сек speaker conditioning.
  3. (Опционально) Align2Speak-style preference optimization для качества TTS-части.

Data-efficiency (обоснование из статей):
  - Hibiki-Zero (arXiv:2602.11072): адаптация к новому языку на <1000 ч (итальянский — 850 ч).
  - arXiv:1809.01431: предобучение на 300 ч EN ASR подняло BLEU ES→EN с 10.8 → 20.2 при 20 ч.
  - arXiv:2410.13445: адаптеры SeamlessM4T на 5 ч дают заметный рост WER.
  - arXiv:2505.21527 (VietASR): SSL-pretrain 70K ч + 50 ч fine-tune превосходит Whisper Large-v3.
  - VALL-E (arXiv:2301.02111): zero-shot voice cloning из 3-сек энролла.
  → 2K часов русского — более чем достаточно при pretrained backbone.

Параметры:
  - Light fine-tuning: 2K ч (есть) → 20K ч (цель); малый LR (~1e-6...2e-6).
  - Speaker conditioning: 10-сек аудио диктора (Hibiki-Zero).
  - Voice transfer: опционально Align2Speak (arXiv:2509.21718), несколько часов на диктора.
"""

import torch
import torch.nn as nn


# =============================================================================
# 4.1. Конфигурация адаптации
# =============================================================================
ADAPT_CONFIG = {
    # Light fine-tuning
    "lr": 2e-6,                 # малый LR для финальной адаптации
    "max_steps": 10_000,
    "batch_size": 8,
    "grad_accum_steps": 4,

    # Voice transfer
    "speaker_cond_seconds": 10.0,   # Hibiki-Zero: 10-сек speaker conditioning
    "speaker_cond_sample_rate": 24000,
    "use_speaker_embedding": True,

    # Align2Speak (опционально)
    "use_align2speak": False,
    "align2speak_hours_per_speaker": 5,
}


# =============================================================================
# 4.2. Speaker conditioning: извлечение и инъекция эмбеддинга диктора
# =============================================================================
# Voice transfer в Hibiki-Zero: «TTS to perform voice transfer from a short audio
# conditioning of maximum 10 seconds». Эмбеддинг диктора извлекается из референс-аудио
# (через WavLM-large + average pooling, как в Moshi) и инъецируется в модель.
class SpeakerConditioner(nn.Module):
    """
    Извлекает speaker embedding из референс-аудио и инъецирует в модель через
    classifier-free guidance ( conditioning на генерацию target-голоса ).

    Источник: arXiv:2410.00037 (Moshi: «WavLM large on each segment to extract
              the speaker embeddings»), arXiv:2301.02111 (VALL-E, 3-сек enrol).
    """

    def __init__(self, embed_dim: int = 256, cfg: dict = ADAPT_CONFIG):
        super().__init__()
        self.cfg = cfg
        # [в проде] загрузить WavLM-large для извлечения speaker embedding
        # from transformers import WavLMModel
        # self.wavlm = WavLMModel.from_pretrained("microsoft/wavlm-large")
        # self.proj = nn.Linear(1024, embed_dim)
        self.embed_dim = embed_dim
        self.proj = nn.Linear(1024, embed_dim, bias=False)  # [в проде] подключить WavLM

    @torch.no_grad()
    def extract_speaker_embedding(self, ref_audio: torch.Tensor) -> torch.Tensor:
        """
        Извлекает speaker embedding из 10-сек референс-аудио.

        Аргументы:
            ref_audio: (1, S) — референс-аудио диктора (24kHz, ~10 сек).
        Возвращает:
            embedding: (embed_dim,) — speaker embedding.
        """
        # Moshi: WavLM embeddings + average pooling (stride 4, kernel 8)
        raise NotImplementedError("[в проде] Подключите WavLM-large для speaker embedding.")

    def forward(self, ref_audio: torch.Tensor) -> torch.Tensor:
        return self.extract_speaker_embedding(ref_audio)


# =============================================================================
# 4.3. Light fine-tuning на русских звонках
# =============================================================================
def finetune_on_russian(
    model: nn.Module,
    speaker_conditioner: SpeakerConditioner,
    dataloader,
    cfg: dict = ADAPT_CONFIG,
    device: str = "cuda",
):
    """
    Light fine-tuning модели на русских звонках с speaker conditioning.

    Аргументы:
        model:              модель после GRPO (этап 3).
        speaker_conditioner: извлекатель speaker embedding.
        dataloader:         пары (source_audio, target_audio, ref_speaker_audio).
        cfg:                конфигурация.
        device:             'cuda'.

    Особенности:
      - Малый LR (2e-6) — только финальная подстройка.
      - Speaker embedding инъецируется как conditioning (не обучается backbone голоса).
      - Mimi codec остаётся frozen.
    """
    # Только Temporal + Depth обучаются (codec frozen)
    trainable = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW(trainable, lr=cfg["lr"])

    model.train()
    step = 0
    optimizer.zero_grad()

    while step < cfg["max_steps"]:
        for batch in dataloader:
            if step >= cfg["max_steps"]:
                break
            source_tokens, target_tokens, ref_speaker_audio = batch
            source_tokens = source_tokens.to(device)
            target_tokens = target_tokens.to(device)
            ref_speaker_audio = ref_speaker_audio.to(device)

            # Извлекаем speaker embedding (frozen WavLM)
            with torch.no_grad():
                speaker_emb = speaker_conditioner.extract_speaker_embedding(ref_speaker_audio)

            # Forward с speaker conditioning
            with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                # [warn] inject speaker_emb в model (через cross-attention или FiLM)
                output = model(source_tokens, target_tokens, None)
                from importlib import import_module
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                loss_mod = import_module("02_coarse_st_training")
                loss, log = loss_mod.compute_multitask_loss(
                    output, None, target_tokens, source_tokens, kinds=None,
                )
                loss = loss / cfg["grad_accum_steps"]

            loss.backward()

            if (step + 1) % cfg["grad_accum_steps"] == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                optimizer.zero_grad()

            if step % 100 == 0:
                print(f"[ru-ft step {step}] {log}")
            step += 1

    torch.save(model.state_dict(), "/data/checkpoints/ru_adapted.pt")
    print("[done] Адаптация к русскому завершена.")


# =============================================================================
# 4.4. (Опционально) Align2Speak preference optimization
# =============================================================================
# Align2Speak (arXiv:2509.21718): дообучение TTS под целевой голос/язык через
# ASR-guided online preference optimization. Применяется к TTS-части (Depth + Mimi decoder),
# если качество голоса недостаточно после speaker conditioning.
def align2speak_optimization(model: nn.Module, dataloader, cfg: dict = ADAPT_CONFIG, device="cuda"):
    """
    Align2Speak-style preference optimization для качества голоса.

    [warn] В проде: реализовать DPO/preference loop с ASR-guided наградами
    (см. arXiv:2509.21718). Здесь — каркас.
    """
    print("[align2speak] Опциональная preference optimization (arXiv:2509.21718)")
    print("  [warn] Требует нескольких часов данных на диктора.")
    # ... DPO loop ...
    raise NotImplementedError("[в проде] Реализуйте Align2Speak DPO loop.")


# =============================================================================
# 4.5. Запуск
# =============================================================================
if __name__ == "__main__":
    print("Этап 4: Адаптация к русскому голосу/домену")
    print(f"  Light fine-tuning: LR={ADAPT_CONFIG['lr']}, steps={ADAPT_CONFIG['max_steps']}")
    print(f"  Speaker conditioning: {ADAPT_CONFIG['speaker_cond_seconds']} сек (Hibiki-Zero)")
    print(f"  Align2Speak: {'вкл' if ADAPT_CONFIG['use_align2speak'] else 'выкл (опционально)'}")
    print("  [warn] Подключите модель (после GRPO), WavLM, русские данные.")
