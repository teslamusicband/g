"""
Этап 1 (часть D): Multistream modeling и Inner Monologue.

Цель:
  1. Multistream — объединить source (входящее аудио) и target (исходящее переведённое
     аудио) потоки RVQ-токенов в единую последовательность, чтобы модель учитывала
     акустический контекст обоих участников разговора.
  2. Inner Monologue — вставить time-aligned текстовые токены W_t как ПРЕФИКС к
     аудио-токенам по codebook-оси. Это "scaffolding" для лингвистического качества:
     модель сначала "думает" текстом, потом генерирует аудио.

Multistream (arXiv:2602.11072, Hibiki-Zero; arXiv:2410.00037, Moshi):
    Ā = concat_q[tau(A^Y), tau(A^X)]
    - Обучение: loss на обоих потоках (target предсказывается, source — actual).
    - Инференс: source-токены подменяются актуальными (от Mimi-энкодера входящего аудио),
      target генерируется авторегрессионно.

Inner Monologue (arXiv:2410.00037, Moshi):
    ... -> W_t (text) -> A_{t,1} (semantic) -> A_{t,2..Q} (acoustic)
    - Текстовые токены предшествуют аудио-токенам по codebook-оси.
    - Предсказываются Temporal Transformer'ом (логиты для W_t).
    - Эффект: значительный рост лингвистического качества генерируемой речи.
    - Дополнительно: даёт streaming ASR/TTS как побочный продукт.
    - НЕ создаёт текстового bottleneck: текст — часть output, не промежуточный шаг.

Эти два механизма — ключевые отличия Moshi/Hibiki от plain codec-LM. Именно multistream
решает замечание коллеги "у MT нет аудио-контекста", а Inner Monologue компенсирует
фактическую точность чисто audio-языковых моделей.
"""

import torch
import torch.nn as nn


# =============================================================================
# 1D.1. Конфигурация потоков
# =============================================================================
STREAM_CONFIG = {
    "num_codebooks": 8,         # Q (Mimi)
    "codebook_size": 2048,
    "text_vocab_size": 32000,   # [в проде] вокабулярий Helium-1 (BPE)
    "num_streams": 2,           # target + source
    "acoustic_delay": 2,
}


# =============================================================================
# 1D.2. Multistream: построение объединённой последовательности токенов
# =============================================================================
# Последовательность на один time-step t (по codebook-оси):
#   [W_t (text), A^Y_{t,1} (target semantic), A^Y_{t,2..Q} (target acoustic),
#    A^X_{t,1} (source semantic), A^X_{t,2..Q} (source acoustic)]
#
# На уровне всей последовательности (по time-оси): для каждого t идёт блок из
# (1 + 2*Q) токенов. Temporal Transformer обрабатывает их последовательно (flatten).
def build_multistream_sequence(
    target_tokens: torch.Tensor,
    source_tokens: torch.Tensor,
    text_tokens: torch.Tensor | None = None,
) -> tuple[torch.Tensor, torch.Tensor]:
    """
    Строит объединённую multistream-последовательность с Inner Monologue.

    Аргументы:
        target_tokens: (B, Q, T) — RVQ target-аудио (перевод).
        source_tokens: (B, Q, T) — RVQ source-аудио (входящий).
        text_tokens:   (B, T)    — time-aligned текстовые токены (Inner Monologue) или None.

    Возвращает:
        flat_ids: (B, S) — flatten-последовательность ID токенов для Temporal Transformer.
                          Порядок: для каждого t: [W_t, target_q0..q{Q-1}, source_q0..q{Q-1}].
        kind_ids: (B, S) — "вид" каждого токена (для выбора эмбеддинг-таблицы/головы):
                          0 = text, 1..Q = target codebook q, Q+1..2Q = source codebook q.
    """
    B, Q, T = target_tokens.shape
    device = target_tokens.device

    # Число токенов на один time-step
    per_step = (1 if text_tokens is not None else 0) + 2 * Q

    # Сдвигаем target/source для выравнивания по time (если T различаются)
    if source_tokens.shape[2] < T:
        pad = torch.zeros(B, Q, T - source_tokens.shape[2], dtype=source_tokens.dtype, device=device)
        source_tokens = torch.cat([source_tokens, pad], dim=2)

    steps = []
    kinds = []
    for t in range(T):
        block = []
        kind = []
        # Inner Monologue: текстовый токен первым
        if text_tokens is not None:
            block.append(text_tokens[:, t])  # (B,)
            kind.append(torch.full((B,), 0, dtype=torch.long, device=device))
        # Target stream (q = 0..Q-1)
        for q in range(Q):
            block.append(target_tokens[:, q, t])
            kind.append(torch.full((B,), 1 + q, dtype=torch.long, device=device))
        # Source stream (q = 0..Q-1)
        for q in range(Q):
            block.append(source_tokens[:, q, t])
            kind.append(torch.full((B,), 1 + Q + q, dtype=torch.long, device=device))
        steps.append(torch.stack(block, dim=1))  # (B, per_step)
        kinds.append(torch.stack(kind, dim=1))    # (B, per_step)

    flat_ids = torch.cat(steps, dim=1)   # (B, T * per_step)
    kind_ids = torch.cat(kinds, dim=1)   # (B, T * per_step)
    return flat_ids, kind_ids


# =============================================================================
# 1D.3. Per-kind эмбеддинги (отдельная таблица на каждый вид токена)
# =============================================================================
# В Moshi используются отдельные эмбеддинг-таблицы на каждый codebook и поток,
# т.к. семантика токенов разных codebook'ов различна. Это даёт модели возможность
# различать "тот же ID в разных codebook означает разное".
class MultiKindTokenEmbedding(nn.Module):
    """
    Эмбеддинги с отдельной таблицей на каждый "вид" токена.

    kind 0:                text (Inner Monologue), vocab = text_vocab_size
    kind 1..Q:             target audio codebook q, vocab = codebook_size
    kind Q+1..2Q:          source audio codebook q, vocab = codebook_size
    """

    def __init__(self, cfg: dict = STREAM_CONFIG, dim: int = 2048):
        super().__init__()
        self.Q = cfg["num_codebooks"]
        self.embeds = nn.ModuleList()
        # text
        self.embeds.append(nn.Embedding(cfg["text_vocab_size"], dim))
        # target codebooks
        for _ in range(self.Q):
            self.embeds.append(nn.Embedding(cfg["codebook_size"], dim))
        # source codebooks
        for _ in range(self.Q):
            self.embeds.append(nn.Embedding(cfg["codebook_size"], dim))

    def forward(self, ids: torch.Tensor, kinds: torch.Tensor) -> torch.Tensor:
        """
        ids:   (B, S)
        kinds: (B, S) — индекс таблицы для каждого токена.
        Возвращает: (B, S, dim).
        """
        B, S = ids.shape
        out = torch.zeros(B, S, self.embeds[0].embedding_dim, device=ids.device)
        for k, emb in enumerate(self.embeds):
            mask = kinds == k
            if mask.any():
                out[mask] = emb(ids[mask])
        return out


# =============================================================================
# 1D.4. Per-kind выходные головы (логиты)
# =============================================================================
# Каждому "виду" токена соответствует своя выходная голова (logits):
# для text — text_vocab_size, для каждого codebook — codebook_size.
class MultiKindOutputHead(nn.Module):
    """Выходные головы: отдельная linear на каждый вид токена."""

    def __init__(self, cfg: dict = STREAM_CONFIG, dim: int = 2048):
        super().__init__()
        self.Q = cfg["num_codebooks"]
        self.heads = nn.ModuleList()
        # text
        self.heads.append(nn.Linear(dim, cfg["text_vocab_size"], bias=False))
        # target codebooks
        for _ in range(self.Q):
            self.heads.append(nn.Linear(dim, cfg["codebook_size"], bias=False))
        # source codebooks
        for _ in range(self.Q):
            self.heads.append(nn.Linear(dim, cfg["codebook_size"], bias=False))

    def forward(self, z: torch.Tensor, kinds: torch.Tensor) -> torch.Tensor:
        """
        z:     (B, S, dim) — выход Temporal Transformer.
        kinds: (B, S).
        Возвращает: (B, S, max_vocab) — logits, где для каждого токена заполнена
                   только соответствующая ему голова (остальное 0). max_vocab — максимум
                   по всем головам. На практике лучше возвращать словарь {kind: logits}.
        """
        # Для простоты возвращаем словарь kind -> (indices, logits)
        out = {}
        for k, head in enumerate(self.heads):
            mask = kinds == k
            if mask.any():
                out[k] = (mask, head(z[mask]))
        return out


# =============================================================================
# 1D.5. Sanity-check
# =============================================================================
def _sanity_check():
    from importlib import import_module
    # standalone: импортируем apply_acoustic_delay из 01a
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    cfg = STREAM_CONFIG
    B, Q, T = 2, 8, 5
    tgt = torch.randint(0, 2048, (B, Q, T))
    src = torch.randint(0, 2048, (B, Q, T))
    txt = torch.randint(0, 32000, (B, T))

    flat_ids, kind_ids = build_multistream_sequence(tgt, src, txt)
    per_step = 1 + 2 * Q  # 17
    assert flat_ids.shape == (B, T * per_step), f"flat_ids: {flat_ids.shape}"
    assert kind_ids.shape == flat_ids.shape
    print(f"[ok] multistream seq: {flat_ids.shape}, per_step={per_step}")

    emb = MultiKindTokenEmbedding(cfg, dim=64)
    e = emb(flat_ids, kind_ids)
    assert e.shape == (B, T * per_step, 64)
    print(f"[ok] embeddings: {e.shape}")

    head = MultiKindOutputHead(cfg, dim=64)
    z = torch.randn(B, T * per_step, 64)
    out = head(z, kind_ids)
    print(f"[ok] output heads: {len(out)} kinds active")


if __name__ == "__main__":
    _sanity_check()
    print("Этап 1D: Multistream + Inner Monologue готовы.")
