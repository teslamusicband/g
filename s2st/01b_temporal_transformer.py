"""
Этап 1 (часть B): Temporal Transformer — большой causal-трансформер.

Цель: моделировать temporal-зависимости между audio-фреймами. На каждом шаге t
принимает все токены всех потоков до момента t-1 и выдаёт контекстное
представление Z_t, которое затем передаётся в Depth Transformer.

Параметры (из arXiv:2602.11072, Hibiki-Zero):
  - latent_dim = 2048
  - SiLU-gating dim = 8192
  - layers = 28
  - heads = 16
  - causal local attention, окно 3000 токенов (≈4 мин при 12.5 Hz)
  - инициализация из Helium-1 (2B текстовый LLM)
  - параметры ≈ 2B

Функция:
    Z_t = Temporal(A_0, ..., A_{t-1}) ∈ R^D

Temporal Transformer — это decoder-only (causal) трансформер. Local attention
означает, что каждый токен смотрит только на окно из `attention_window`
предыдущих токенов (а не на всю историю) — это даёт O(T * window) вместо O(T^2)
и стабильно работает на длинных разговорах.

Источник: arXiv:2410.00037 (Moshi), arXiv:2602.11072 (Hibiki-Zero).
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# =============================================================================
# 1B.1. Конфигурация Temporal Transformer
# =============================================================================
TEMPORAL_CONFIG = {
    "latent_dim": 2048,         # D
    "silu_gating_dim": 8192,    # размерность gating в feed-forward (SiLU)
    "num_layers": 28,
    "num_heads": 16,
    "attention_window": 3000,   # local attention окно (≈4 мин @ 12.5 Hz)
    "dropout": 0.0,
    # Число "потоков" токенов, подаваемых на один time-step:
    #   multistream: 2 (target + source) × Q codebooks + 1 text (Inner Monologue)
    #   на инференсе источником для target служат предсказанные токены.
    "num_token_kinds": None,    # задаётся динамически (зависит от Q и числа потоков)
}


# =============================================================================
# 1B.2. Causal local self-attention
# =============================================================================
# Каждый токен attends к максимум `window` предыдущим токенам (включая себя).
# Реализуется через ограничение маски attention: разрешены позиции [i-window+1, i].
# Causality: будущие позиции замаскированы (-inf).
class CausalLocalAttention(nn.Module):
    """
    Causal self-attention с локальным окном.

    Аргументы:
        dim: размерность модели.
        num_heads: число голов.
        window: размер локального окна (число предыдущих токенов, включая текущий).
    """

    def __init__(self, dim: int, num_heads: int, window: int, dropout: float = 0.0):
        super().__init__()
        assert dim % num_heads == 0
        self.dim = dim
        self.num_heads = num_heads
        self.head_dim = dim // num_heads
        self.window = window
        self.qkv = nn.Linear(dim, 3 * dim, bias=False)
        self.proj = nn.Linear(dim, dim, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, kv_cache: torch.Tensor | None = None):
        """
        x:      (B, T, D)
        kv_cache: (B, cache_len, 2, num_heads, head_dim) или None
                  хранит past K,V для streaming-инференса.

        Возвращает:
            out: (B, T, D)
            new_kv_cache: обновлённый кэш (обрезанный до window).
        """
        B, T, D = x.shape
        qkv = self.qkv(x)  # (B, T, 3D)
        qkv = qkv.reshape(B, T, 3, self.num_heads, self.head_dim)
        q, k, v = qkv.unbind(dim=2)  # каждый (B, T, H, hd)

        # Объединение с KV-cache (streaming)
        if kv_cache is not None:
            past_k, past_v = kv_cache.unbind(dim=2)  # (B, cache_len, H, hd)
            k = torch.cat([past_k, k], dim=1)        # (B, cache_len+T, H, hd)
            v = torch.cat([past_v, v], dim=1)
        cache_len = k.shape[1] - T
        new_cache = torch.stack([k, v], dim=2)  # (B, cache_len+T, 2, H, hd)

        # Транспонирование к (B, H, T, hd)
        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        # Causal + local mask: позиция i attends к [max(0, i-window+1), i]
        # Здесь строим маску для текущего чанка с учётом cache_len.
        attn_scores = torch.matmul(q, k.transpose(-2, -1)) / math.sqrt(self.head_dim)
        total_len = k.shape[-2]  # cache_len + T
        # индекс текущего токена в полной последовательности
        idx = torch.arange(cache_len, cache_len + T, device=x.device)  # (T,)
        # разрешённые позиции j: idx - window + 1 <= j <= idx  И  j <= idx (causal)
        j = torch.arange(total_len, device=x.device)  # (total_len,)
        # local: j >= idx[:,None] - window + 1
        local_ok = j[None, :] >= (idx[:, None] - self.window + 1)
        # causal: j <= idx[:,None]
        causal_ok = j[None, :] <= idx[:, None]
        mask = local_ok & causal_ok  # (T, total_len)
        attn_scores = attn_scores.masked_fill(~mask[None, None, :, :], float("-inf"))

        attn = F.softmax(attn_scores, dim=-1)
        attn = self.dropout(attn)
        out = torch.matmul(attn, v)  # (B, H, T, hd)
        out = out.transpose(1, 2).reshape(B, T, D)
        out = self.proj(out)

        # Обрезаем кэш до window для следующего шага
        if new_cache.shape[1] > self.window:
            new_cache = new_cache[:, -self.window:, :, :, :]
        return out, new_cache


# =============================================================================
# 1B.3. Feed-forward с SiLU-gating (как в Moshi/Helium)
# =============================================================================
class SiLUGatedFFN(nn.Module):
    """
    Feed-forward блок с SiLU-gating: gating_dim обычно >> latent_dim (8192 vs 2048).
    Структура: gate = SiLU(linear_gate(x)); out = linear_out(gate * linear_up(x)).
    """

    def __init__(self, dim: int, gating_dim: int, dropout: float = 0.0):
        super().__init__()
        # В Moshi используется gated линейный блок: out = W2 * (SiLU(W1*x) * (W3*x))
        self.linear_gate = nn.Linear(dim, gating_dim, bias=False)
        self.linear_up = nn.Linear(dim, gating_dim, bias=False)
        self.linear_out = nn.Linear(gating_dim, dim, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        gate = F.silu(self.linear_gate(x))
        up = self.linear_up(x)
        return self.dropout(self.linear_out(gate * up))


# =============================================================================
# 1B.4. Блок Temporal Transformer
# =============================================================================
class TemporalBlock(nn.Module):
    """Один блок: LayerNorm -> CausalLocalAttention -> residual; LN -> FFN -> residual."""

    def __init__(self, cfg: dict = TEMPORAL_CONFIG):
        super().__init__()
        self.norm1 = nn.LayerNorm(cfg["latent_dim"])
        self.attn = CausalLocalAttention(
            cfg["latent_dim"], cfg["num_heads"], cfg["attention_window"], cfg["dropout"]
        )
        self.norm2 = nn.LayerNorm(cfg["latent_dim"])
        self.ffn = SiLUGatedFFN(cfg["latent_dim"], cfg["silu_gating_dim"], cfg["dropout"])

    def forward(self, x: torch.Tensor, kv_cache: torch.Tensor | None = None):
        # Pre-norm
        h = self.norm1(x)
        h, new_cache = self.attn(h, kv_cache)
        x = x + h
        h = self.norm2(x)
        x = x + self.ffn(h)
        return x, new_cache


# =============================================================================
# 1B.5. Полный Temporal Transformer
# =============================================================================
def _sinusoidal_pos_table(max_len: int, dim: int) -> torch.Tensor:
    """Синусоидальные позиционные эмбеддинги (max_len, dim), как в Transformer/Attention Is All You Need."""
    pe = torch.zeros(max_len, dim)
    position = torch.arange(0, max_len).unsqueeze(1).float()
    div_term = torch.exp(torch.arange(0, dim, 2).float() * (-math.log(10000.0) / dim))
    pe[:, 0::2] = torch.sin(position * div_term)
    pe[:, 1::2] = torch.cos(position * div_term)
    return pe


class TemporalTransformer(nn.Module):
    """
    Большой causal Temporal Transformer.

    Input:  последовательность эмбеддингов токенов (B, T, D)
            (токены всех потоков, flatten по time x codebook x stream)
    Output: Z = (B, T, D) — контекстное представление на каждый time-step.

    На шаге t: Z_t = Temporal(A_0, ..., A_{t-1}).
    """

    def __init__(self, cfg: dict = TEMPORAL_CONFIG, vocab_size: int = 2048):
        super().__init__()
        self.cfg = cfg
        self.dim = cfg["latent_dim"]
        # Токенные эмбеддинги: отдельная таблица на каждый "вид" токена
        # (target-audio codebook q, source-audio codebook q, text token).
        # Здесь — одна общая таблица для простоты; в проде — per-codebook таблицы.
        self.token_embed = nn.Embedding(vocab_size, self.dim)
        # Абсолютные синусоидальные позиционные эмбеддинги (как в Helium/wav2vec-S).
        # Синусоиды поддерживают произвольную длину (в отличие от learned таблицы),
        # что важно для streaming и длинных разговоров.
        self.max_len = 4096
        self.register_buffer("pos_table", _sinusoidal_pos_table(self.max_len, self.dim))
        self.blocks = nn.ModuleList([TemporalBlock(cfg) for _ in range(cfg["num_layers"])])
        self.norm_f = nn.LayerNorm(self.dim)

    def forward(self, token_ids: torch.Tensor, caches: list | None = None):
        """
        token_ids: (B, T) — последовательность ID токенов (всех потоков, flatten).
        caches:    список KV-cache на каждый блок (для streaming) или None.

        Возвращает:
            z: (B, T, D) — контекстные представления.
            new_caches: обновлённые кэши по блокам.
        """
        B, T = token_ids.shape
        x = self.token_embed(token_ids)  # (B, T, D)
        # позиционные эмбеддинги (первые T позиций)
        assert T <= self.max_len, f"seq_len {T} > max_len {self.max_len}; увеличьте max_len"
        x = x + self.pos_table[:T][None]

        new_caches = []
        for i, block in enumerate(self.blocks):
            c = caches[i] if caches is not None else None
            x, nc = block(x, c)
            new_caches.append(nc)
        z = self.norm_f(x)
        return z, new_caches

    @torch.no_grad()
    def step(self, token_id: torch.Tensor, caches: list):
        """
        Streaming-шаг: обработка одного токена с переиспользованием KV-cache.
        token_id: (B, 1)
        caches:   KV-cache по блокам.
        Возвращает z (B, 1, D) и обновлённые caches.
        """
        return self.forward(token_id, caches)


# =============================================================================
# 1B.6. Загрузка/маппинг весов из Helium-1
# =============================================================================
# Moshi: «Temporal Transformer initialized from Helium».
# Helium-1 — 2B текстовый LLM (Kyutai). Его веса маппятся в Temporal Transformer
# (преобразование размерности входных эмбеддингов под multistream/audio-токены).
def init_from_helium(model: TemporalTransformer, helium_state_dict: dict):
    """
    Инициализирует Temporal Transformer из весов Helium-1.

    [warn] В проде: точный маппинг ключей зависит от формата Helium.
    Обычно: attn.qkv <- helium.attn.{q,k,v}_proj; ffn <- helium.mlp;
    token_embed остаётся случайным (разный вокабуляр) или инициализируется
    из text-эмбеддингов Helium для text-токенов.
    """
    missing, unexpected = model.load_state_dict(helium_state_dict, strict=False)
    print(f"[init] Helium -> Temporal: missing={len(missing)}, unexpected={len(unexpected)}")
    return model


# =============================================================================
# 1B.7. Sanity-check
# =============================================================================
def _sanity_check():
    cfg = {**TEMPORAL_CONFIG, "num_layers": 2, "latent_dim": 64,
           "silu_gating_dim": 128, "num_heads": 4, "attention_window": 8}
    vocab = 2048
    model = TemporalTransformer(cfg, vocab_size=vocab)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"[temporal] params (toy config): {n_params:,}")

    # Forward
    x = torch.randint(0, vocab, (2, 10))
    z, caches = model(x)
    assert z.shape == (2, 10, cfg["latent_dim"]), f"z shape: {z.shape}"
    print(f"[ok] forward z={z.shape}, caches={len(caches)} blocks")

    # Streaming step
    z2, caches2 = model.step(torch.randint(0, vocab, (2, 1)), caches)
    assert z2.shape == (2, 1, cfg["latent_dim"])
    print("[ok] streaming step")


if __name__ == "__main__":
    _sanity_check()
    print("Этап 1B: Temporal Transformer готов.")
