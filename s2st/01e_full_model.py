"""
Этап 1 (часть E): Полная модель Neural-Codec Streaming S2ST.

Цель: собрать все компоненты (Mimi codec, Temporal Transformer, Depth Transformer,
Multistream + Inner Monologue) в единую end-to-end модель.

Архитектура (из optimal_neural_codec_s2st_architecture.md):

  Входящее аудио (24kHz)
      │
      ▼
  Mimi Encoder ──► source RVQ-токены A^X (Q, T)
      │
      ▼
  [Multistream: concat target + source + text, с Inner Monologue]
      │
      ▼
  Temporal Transformer ──► Z_t (контекст на каждый time-step)
      │
      ▼
  Depth Transformer (по codebook-оси) ──► logits для target токенов A^Y_{t,q}
      │
      ▼
  Mimi Decoder ◄── предсказанные target токены A^Y
      │
      ▼
  Исходящее переведённое аудио (24kHz)

Размер модели: Temporal ~2B + Depth ~0.5-1B + Mimi (frozen) ≈ 3B trainable.

На обучении: loss = CE(text) + CE(target audio codebooks) + опц. CE(source audio).
На инференсе: source токены актуальные, target предсказываются авторегрессионно.

Источники: arXiv:2410.00037 (Moshi), arXiv:2602.11072 (Hibiki-Zero).
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


# =============================================================================
# 1E.1. Конфигурация полной модели
# =============================================================================
MODEL_CONFIG = {
    # Mimi (frozen)
    "sample_rate": 24000,
    "num_codebooks": 8,          # Q
    "codebook_size": 2048,
    "codec_latent_dim": 512,
    "acoustic_delay": 2,

    # Temporal Transformer
    "temporal_dim": 2048,
    "temporal_gating_dim": 8192,
    "temporal_layers": 28,
    "temporal_heads": 16,
    "attention_window": 3000,

    # Depth Transformer
    "depth_dim": 1024,
    "depth_gating_dim": 4096,
    "depth_layers": 6,
    "depth_heads": 16,

    # Inner Monologue / text
    "text_vocab_size": 32000,
    "use_inner_monologue": True,
}


# =============================================================================
# 1E.2. Полная модель
# =============================================================================
class NeuralCodecS2ST(nn.Module):
    """
    End-to-end Neural-Codec Streaming S2ST модель.

    Компоненты:
      - codec: Mimi (frozen) — кодирует входное аудио в source-токены,
                                 декодирует target-токены в выходное аудио.
      - temporal: Temporal Transformer — контекст по time-оси.
      - depth: Depth Transformer — предсказание по codebook-оси.
      - embed / head: per-kind эмбеддинги и выходные головы (text + target/source codebooks).
    """

    def __init__(self, cfg: dict = MODEL_CONFIG, codec: nn.Module | None = None):
        super().__init__()
        self.cfg = cfg
        self.Q = cfg["num_codebooks"]
        self.use_text = cfg["use_inner_monologue"]

        # --- Кодек (frozen) ---
        # [в проде] codec = MimiCodec(...) с загруженными весами kyutai/mimi
        self.codec = codec
        if codec is not None:
            for p in self.codec.parameters():
                p.requires_grad_(False)

        # --- Импортируем компоненты локально, чтобы файл был самодостаточным ---
        # В реальном проекте: from . import TemporalTransformer, DepthTransformer, ...
        # Здесь используем прямые импорты из модулей этапа 1.
        import importlib, sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

        # Per-kind эмбеддинги и головы
        from importlib import import_module
        m_d = import_module("01d_multistream_inner_monologue")
        stream_cfg = {
            "num_codebooks": cfg["num_codebooks"],
            "codebook_size": cfg["codebook_size"],
            "text_vocab_size": cfg["text_vocab_size"],
            "num_streams": 2,
            "acoustic_delay": cfg["acoustic_delay"],
        }
        self.embed = m_d.MultiKindTokenEmbedding(stream_cfg, dim=cfg["temporal_dim"])
        self.head = m_d.MultiKindOutputHead(stream_cfg, dim=cfg["temporal_dim"])

        # Temporal Transformer (используем упрощённый из 01b)
        t_cfg = {
            "latent_dim": cfg["temporal_dim"],
            "silu_gating_dim": cfg["temporal_gating_dim"],
            "num_layers": cfg["temporal_layers"],
            "num_heads": cfg["temporal_heads"],
            "attention_window": cfg["attention_window"],
            "dropout": 0.0,
        }
        temporal_mod = import_module("01b_temporal_transformer")
        # переопределяем token_embed, т.к. используем MultiKindTokenEmbedding
        self.temporal = temporal_mod.TemporalTransformer(t_cfg, vocab_size=cfg["codebook_size"])
        # заменяем token_embed на наш multi-kind
        self.temporal.token_embed = None  # используем внешний embed

        # Depth Transformer
        d_cfg = {
            "latent_dim": cfg["depth_dim"],
            "gating_dim": cfg["depth_gating_dim"],
            "num_layers": cfg["depth_layers"],
            "num_heads": cfg["depth_heads"],
            "dropout": 0.0,
            "num_codebooks": cfg["num_codebooks"],
            "codebook_size": cfg["codebook_size"],
        }
        depth_mod = import_module("01c_depth_transformer")
        self.depth = depth_mod.DepthTransformer(d_cfg, temporal_dim=cfg["temporal_dim"])

    # -------------------------------------------------------------------------
    # Обучающий forward: предсказание target токенов (teacher forcing)
    # -------------------------------------------------------------------------
    def forward(
        self,
        source_tokens: torch.Tensor,      # (B, Q, T_x) — actual source RVQ
        target_tokens: torch.Tensor,      # (B, Q, T_y) — ground-truth target RVQ
        text_tokens: torch.Tensor | None = None,  # (B, T_y) — Inner Monologue text
    ) -> dict:
        """
        Обучающий forward. Возвращает словарь логитов для подсчёта loss.

        Возвращает:
            {
              "text_logits":   (N_text, text_vocab)   если use_inner_monologue,
              "target_logits": (N_tgt, codebook_size) для target audio токенов,
              "source_logits": (N_src, codebook_size) для source audio токенов (опц.),
            }
        """
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from importlib import import_module
        m_d = import_module("01d_multistream_inner_monologue")

        # 1. Применяем acoustic delay к обоим потокам
        apply_delay = m_d.apply_acoustic_delay if hasattr(m_d, "apply_acoustic_delay") else None
        # (acoustic_delay определён в 01a; для самодостаточности импортируем)
        mimi_mod = import_module("01a_mimi_codec")
        tgt_delayed = mimi_mod.apply_acoustic_delay(target_tokens, self.cfg["acoustic_delay"])
        src_delayed = mimi_mod.apply_acoustic_delay(source_tokens, self.cfg["acoustic_delay"])

        # 2. Строим multistream последовательность
        flat_ids, kind_ids = m_d.build_multistream_sequence(
            tgt_delayed, src_delayed, text_tokens
        )

        # 3. Эмбеддинги (per-kind)
        x = self.embed(flat_ids, kind_ids)  # (B, S, temporal_dim)

        # 4. Temporal Transformer (causal по time)
        #    Подменяем token_embed-логику: передаём уже готовые эмбеддинги.
        #    Для простоты вызываем блоки напрямую.
        T = x.shape[1]
        h = x + self.temporal.pos_table[:T][None]
        new_caches = []
        for block in self.temporal.blocks:
            h, nc = block(h, None)
            new_caches.append(nc)
        z = self.temporal.norm_f(h)  # (B, S, temporal_dim)

        # 5. Выходные головы (per-kind логиты)
        out = self.head(z, kind_ids)
        return out

    # -------------------------------------------------------------------------
    # Инференс: генерация target аудио из source аудио (streaming)
    # -------------------------------------------------------------------------
    @torch.no_grad()
    def translate_streaming(self, source_tokens: torch.Tensor, max_steps: int) -> torch.Tensor:
        """
        Streaming-инференс: по входящим source-токенам генерирует target-токены.

        Аргументы:
            source_tokens: (Q, T_x) — actual source RVQ (от Mimi-энкодера).
            max_steps:     макс. число time-steps для генерации target.

        Возвращает:
            target_tokens: (Q, T_gen) — предсказанные target RVQ-токены.

        [warn] Это упрощённый цикл генерации. Полный streaming-пайплайн
        (поэтапная подача source-чанков + KV-cache) — в файле 06_streaming_inference.py.
        """
        device = source_tokens.device
        Q = self.Q
        src = source_tokens.unsqueeze(0)  # (1, Q, T_x)

        gen_target = []
        # Инициализация: пустой target
        cur_target = torch.zeros(1, Q, 0, dtype=torch.long, device=device)

        for t in range(max_steps):
            # Текущий target (с acoustic delay)
            from importlib import import_module
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            mimi_mod = import_module("01a_mimi_codec")
            tgt_d = mimi_mod.apply_acoustic_delay(cur_target, self.cfg["acoustic_delay"])
            src_d = mimi_mod.apply_acoustic_delay(src[:, :, :t + 1], self.cfg["acoustic_delay"])

            # Берём последний time-step контекста
            flat_ids, kind_ids = import_module("01d_multistream_inner_monologue").build_multistream_sequence(
                tgt_d, src_d, None
            )
            x = self.embed(flat_ids, kind_ids)
            T = x.shape[1]
            h = x + self.temporal.pos_table[:T][None]
            for block in self.temporal.blocks:
                h, _ = block(h, None)
            z = self.temporal.norm_f(h)
            z_t = z[:, -1]  # (1, temporal_dim) — контекст на последний step

            # Depth Transformer: предсказываем Q токенов для нового time-step
            new_tokens = self.depth.step(z_t, torch.empty(1, 0, dtype=torch.long, device=device))
            gen_target.append(new_tokens)  # (1, Q)
            cur_target = torch.cat([cur_target, new_tokens.unsqueeze(2)], dim=2)

        target_tokens = torch.cat(gen_target, dim=0).T  # (Q, T_gen)
        # Снимаем acoustic delay для декодирования
        target_tokens = mimi_mod.remove_acoustic_delay(target_tokens.unsqueeze(0), self.cfg["acoustic_delay"])[0]
        return target_tokens

    # -------------------------------------------------------------------------
    # Подсчёт параметров
    # -------------------------------------------------------------------------
    def count_parameters(self) -> dict:
        """Возвращает число параметров по блокам."""
        counts = {}
        for name, mod in [("temporal", self.temporal), ("depth", self.depth),
                          ("embed", self.embed), ("head", self.head)]:
            counts[name] = sum(p.numel() for p in mod.parameters() if p.requires_grad)
        if self.codec is not None:
            counts["codec (frozen)"] = sum(p.numel() for p in self.codec.parameters())
        counts["total_trainable"] = sum(v for k, v in counts.items() if "frozen" not in k)
        return counts


# =============================================================================
# 1E.3. Sanity-check
# =============================================================================
def _sanity_check():
    cfg = {**MODEL_CONFIG,
           "temporal_dim": 64, "temporal_gating_dim": 128, "temporal_layers": 2,
           "temporal_heads": 4, "attention_window": 8,
           "depth_dim": 64, "depth_gating_dim": 128, "depth_layers": 2, "depth_heads": 4}
    model = NeuralCodecS2ST(cfg, codec=None)
    counts = model.count_parameters()
    print(f"[model] params: {counts}")

    B, Q, T = 2, 8, 5
    src = torch.randint(0, 2048, (B, Q, T))
    tgt = torch.randint(0, 2048, (B, Q, T))
    txt = torch.randint(0, 32000, (B, T))
    out = model(src, tgt, txt)
    print(f"[ok] forward: {len(out)} kinds with logits")


if __name__ == "__main__":
    _sanity_check()
    print("Этап 1E: Полная модель NeuralCodecS2ST готова.")
