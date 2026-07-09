"""
Этап 1 (часть C): Depth Transformer — малый авторегрессионный трансформер по codebook-оси.

Цель: внутри одного time-step t авторегрессионно предсказывать токены по codebook-оси
(q = 1..Q), используя контекст Z_t от Temporal Transformer и уже предсказанные
токены A_{t,0..q-1}.

Параметры (из arXiv:2410.00037, Moshi; arXiv:2602.11072, Hibiki-Zero):
  - latent_dim = 1024
  - gating_dim = 4096
  - layers per codebook = 6
  - heads = 16
  - параметры ≈ 0.5-1B
  - инициализация случайная (НЕ из Helium)

Функция:
    l_{t,q} = Depth(Z_t, A_{t,0}, ..., A_{t,q-1}) ∈ R^{N_a}
    P(A_{t,q} | history) = softmax(l_{t,q})

Ключевая идея RQ-трансформера: вместо того чтобы моделировать всю последовательность
длины K*Q одним авторегрессионным трансформером (O((K*Q)^2)), задача разбивается:
  - Temporal Transformer (O(K * window)) моделирует временные зависимости;
  - Depth Transformer (O(Q^2), Q маленькое) моделирует зависимости по codebook-оси
    внутри одного time-step.

Acoustic delay (см. 01a_mimi_codec.py): акустические токены (q>=2) подаются на Depth
со сдвигом 2 фрейма — это даёт Depth Transformer lookahead по семантике.

Источник: arXiv:2410.00037 (Moshi), arXiv:2602.11072 (Hibiki-Zero).
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# =============================================================================
# 1C.1. Конфигурация Depth Transformer
# =============================================================================
DEPTH_CONFIG = {
    "latent_dim": 1024,
    "gating_dim": 4096,
    "num_layers": 6,            # слоёв на codebook
    "num_heads": 16,
    "dropout": 0.0,
    # Q (число codebooks) и codebook_size задаются извне (из Mimi-конфига)
    "num_codebooks": 8,
    "codebook_size": 2048,
}


# =============================================================================
# 1C.2. Causal self-attention по codebook-оси
# =============================================================================
# В отличие от Temporal (causal по time), здесь attention causal по codebook-оси q:
# токен codebook q может видеть токены codebook 0..q, но не q+1..Q.
# Так как Q=8 маленькое, это полная (не local) causal attention.
class CausalAttentionQ(nn.Module):
    """Causal self-attention вдоль codebook-оси (Q позиций)."""

    def __init__(self, dim: int, num_heads: int, dropout: float = 0.0):
        super().__init__()
        assert dim % num_heads == 0
        self.num_heads = num_heads
        self.head_dim = dim // num_heads
        self.qkv = nn.Linear(dim, 3 * dim, bias=False)
        self.proj = nn.Linear(dim, dim, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor):
        """
        x: (B, Q, D) — эмбеддинги по codebook-оси.
        Возвращает: (B, Q, D).
        """
        B, Q, D = x.shape
        qkv = self.qkv(x).reshape(B, Q, 3, self.num_heads, self.head_dim)
        q, k, v = qkv.unbind(dim=2)  # (B, Q, H, hd)
        q, k, v = [t.transpose(1, 2) for t in (q, k, v)]  # (B, H, Q, hd)

        scores = torch.matmul(q, k.transpose(-2, -1)) / math.sqrt(self.head_dim)
        # causal mask по Q: позиция q видит 0..q
        mask = torch.triu(torch.ones(Q, Q, device=x.device, dtype=torch.bool), diagonal=1)
        scores = scores.masked_fill(mask[None, None], float("-inf"))
        attn = F.softmax(scores, dim=-1)
        attn = self.dropout(attn)
        out = torch.matmul(attn, v).transpose(1, 2).reshape(B, Q, D)
        return self.proj(out)


# =============================================================================
# 1C.3. Feed-forward с SiLU-gating (меньший, чем у Temporal)
# =============================================================================
class SiLUGatedFFN(nn.Module):
    def __init__(self, dim: int, gating_dim: int, dropout: float = 0.0):
        super().__init__()
        self.linear_gate = nn.Linear(dim, gating_dim, bias=False)
        self.linear_up = nn.Linear(dim, gating_dim, bias=False)
        self.linear_out = nn.Linear(gating_dim, dim, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        gate = F.silu(self.linear_gate(x))
        up = self.linear_up(x)
        return self.dropout(self.linear_out(gate * up))


# =============================================================================
# 1C.4. Блок Depth Transformer
# =============================================================================
class DepthBlock(nn.Module):
    """Один блок поверх codebook-оси: LN -> Attn -> residual; LN -> FFN -> residual."""

    def __init__(self, cfg: dict = DEPTH_CONFIG):
        super().__init__()
        self.norm1 = nn.LayerNorm(cfg["latent_dim"])
        self.attn = CausalAttentionQ(cfg["latent_dim"], cfg["num_heads"], cfg["dropout"])
        self.norm2 = nn.LayerNorm(cfg["latent_dim"])
        self.ffn = SiLUGatedFFN(cfg["latent_dim"], cfg["gating_dim"], cfg["dropout"])

    def forward(self, x: torch.Tensor):
        h = self.norm1(x)
        x = x + self.attn(h)
        h = self.norm2(x)
        x = x + self.ffn(h)
        return x


# =============================================================================
# 1C.5. Полный Depth Transformer
# =============================================================================
class DepthTransformer(nn.Module):
    """
    Малый Depth Transformer: предсказывает токены по codebook-оси внутри time-step.

    Input:
        z_t:    (B, D_temporal) — контекст от Temporal Transformer (проекция в D_depth)
        prev_tokens: (B, Q, D_depth) — эмбеддинги уже предсказанных токенов A_{t,0..Q-1}
                  (на обучении — ground truth, со сдвигом; на инференсе — предсказанные).
    Output:
        logits: (B, Q, N_a) — распределение по codebook-записям для каждого q.

    В режиме teacher-forcing (обучение) все Q позиций обрабатываются за один forward
    благодаря causal mask по q. На инференсе — пошагово (см. step()).
    """

    def __init__(self, cfg: dict = DEPTH_CONFIG, temporal_dim: int = 2048):
        super().__init__()
        self.cfg = cfg
        self.dim = cfg["latent_dim"]
        self.num_codebooks = cfg["num_codebooks"]
        self.codebook_size = cfg["codebook_size"]

        # Проекция Z_t из размерности Temporal в размерность Depth
        self.z_proj = nn.Linear(temporal_dim, self.dim, bias=False)
        # Эмбеддинги токенов: отдельная таблица на каждый codebook (как в Moshi)
        self.token_embeds = nn.ModuleList(
            [nn.Embedding(self.codebook_size, self.dim) for _ in range(self.num_codebooks)]
        )
        self.blocks = nn.ModuleList([DepthBlock(cfg) for _ in range(cfg["num_layers"])])
        self.norm_f = nn.LayerNorm(self.dim)
        # Выходная голова: logits по codebook-записям, per-codebook
        self.heads = nn.ModuleList(
            [nn.Linear(self.dim, self.codebook_size, bias=False) for _ in range(self.num_codebooks)]
        )

    def forward(self, z_t: torch.Tensor, prev_token_ids: torch.Tensor):
        """
        Обучающий forward (teacher forcing).

        Аргументы:
            z_t: (B, D_temporal) — контекст Temporal на time-step t.
            prev_token_ids: (B, Q) — ground-truth токены A_{t,0..Q-1} (со сдвигом
                            для causal: позиция q предсказывается по 0..q-1).

        Возвращает:
            logits: (B, Q, N_a) — logits для каждого codebook q.
        """
        B, Q = prev_token_ids.shape
        # Эмбеддинги токенов: shift вправо (позиция q предсказывается по токенам 0..q-1)
        # Вставляем проекцию z_t как "нулевой" вход, затем токены 0..Q-2
        z = self.z_proj(z_t)  # (B, D_depth)
        # Формируем последовательность по codebook-оси длиной Q:
        #   позиция 0: z (контекст), предсказывает codebook 0
        #   позиция q>=1: embed(token_{q-1}), предсказывает codebook q
        embeds = [z]
        for q in range(Q - 1):
            emb = self.token_embeds[q](prev_token_ids[:, q])  # (B, D_depth)
            embeds.append(emb)
        x = torch.stack(embeds, dim=1)  # (B, Q, D_depth)

        for block in self.blocks:
            x = block(x)
        x = self.norm_f(x)
        # logits для каждого q через свою голову
        logits = torch.stack([self.heads[q](x[:, q]) for q in range(Q)], dim=1)  # (B, Q, N_a)
        return logits

    @torch.no_grad()
    def step(self, z_t: torch.Tensor, prev_token_ids: torch.Tensor):
        """
        Инференс-шаг: предсказание одного полного time-step (все Q codebooks).
        Реализует авторегрессию по q: предсказывает q=0, затем q=1 по предсказанному q=0, и т.д.

        Аргументы:
            z_t: (B, D_temporal)
            prev_token_ids: (B, 0) — пустой (или содержащий ранее предсказанные).
        Возвращает:
            tokens: (B, Q) — предсказанные токены для time-step t.
        """
        B = z_t.shape[0]
        Q = self.num_codebooks
        device = z_t.device
        z = self.z_proj(z_t)  # (B, D_depth)

        tokens = []
        embeds = [z]
        for q in range(Q):
            # Собираем последовательность из текущих embeds и пропускаем через блоки
            x = torch.stack(embeds, dim=1)  # (B, q+1, D_depth)
            for block in self.blocks:
                x = block(x)
            x = self.norm_f(x)
            logits_q = self.heads[q](x[:, q])  # (B, N_a)
            tok_q = logits_q.argmax(dim=-1)     # (B,)
            tokens.append(tok_q)
            # Эмбеддинг для следующего шага
            if q < Q - 1:
                embeds.append(self.token_embeds[q](tok_q))
        return torch.stack(tokens, dim=1)  # (B, Q)


# =============================================================================
# 1C.6. Sanity-check
# =============================================================================
def _sanity_check():
    cfg = {**DEPTH_CONFIG, "latent_dim": 64, "gating_dim": 128, "num_heads": 4,
           "num_layers": 2, "num_codebooks": 8, "codebook_size": 2048}
    temporal_dim = 128
    model = DepthTransformer(cfg, temporal_dim=temporal_dim)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"[depth] params (toy config): {n_params:,}")

    B = 2
    z_t = torch.randn(B, temporal_dim)
    prev = torch.randint(0, cfg["codebook_size"], (B, cfg["num_codebooks"]))
    logits = model(z_t, prev)
    assert logits.shape == (B, cfg["num_codebooks"], cfg["codebook_size"]), f"logits: {logits.shape}"
    print(f"[ok] training forward logits={logits.shape}")

    # Inference step (авторегрессия по q)
    tokens = model.step(z_t, torch.empty(B, 0, dtype=torch.long))
    assert tokens.shape == (B, cfg["num_codebooks"]), f"step tokens: {tokens.shape}"
    print(f"[ok] inference step tokens={tokens.shape}")


if __name__ == "__main__":
    _sanity_check()
    print("Этап 1C: Depth Transformer готов.")
