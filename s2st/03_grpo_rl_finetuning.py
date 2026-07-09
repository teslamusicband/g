"""
Этап 3: RL Fine-tuning — GRPO для оптимизации тайминга перевода.

Цель (из optimal_neural_codec_s2st_architecture.md, "Этап 2: RL Fine-tuning — GRPO"):
  Начиная с base-модели (после Coarse ST, этап 2), дообучить её через reinforcement
  learning так, чтобы ОПТИМИЗИРОВАТЬ ЗАДЕРЖКУ (latency) при сохранении качества
  перевода. Модель сама учится "когда говорить / когда слушать" — без hand-crafted
  read/write policy и без word-level alignment.

Алгоритм GRPO (Group Relative Policy Optimization, arXiv:2402.03300, DeepSeekMath):
  - Сэмплируется группа из G переводов {o_1..o_G} из old policy.
  - Advantage: A_i = (r_i - mean(r)) / std(r)  — GROUP-RELATIVE baseline.
    Ключевое отличие от PPO: НЕТ critic/value network — baseline оценивается из
    наград внутри группы. Это сильно снижает требования к памяти/вычислениям.
  - Оптимизация: maximize E[ min(ratio * A, clip(ratio, 1-eps, 1+eps) * A) ].

Адаптация Hibiki-Zero (arXiv:2602.11072):
  - PROCESS REWARDS (не только outcome): BLEU вычисляется на промежуточных этапах,
    каждые n_w = 8 входных слов.
  - Баланс total vs intermediate BLEU: lambda = 0.5.
  - Advantage = сумма нормированных наград с последующих шагов.
  - Per-codebook objectives L^(i)_q со стандартным clipping.
  - Данные: ТЕ ЖЕ sentence-aligned пары (word-level alignment НЕ нужен!).

Параметры:
  - LR (policy): 1e-6 (DeepSeekMath: "learning rate of the policy model as 1e-6")
  - n_w = 8 (частота process rewards, во входных словах)
  - lambda = 0.5 (баланс total/intermediate BLEU)
  - Steps: 50-100K
  - G = число сэмплов в группе (обычно 4-8)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


# =============================================================================
# 3.1. Конфигурация GRPO
# =============================================================================
GRPO_CONFIG = {
    "lr_policy": 1e-6,          # DeepSeekMath: LR policy model
    "n_w": 8,                   # частота process rewards (во входных словах)
    "lambda_balance": 0.5,      # баланс total / intermediate BLEU
    "group_size": 4,            # G — число сэмплов в группе
    "clip_eps": 0.2,            # PPO-стиль clipping
    "max_steps": 100_000,       # 50-100K
    "beta_kl": 0.0,             # коэффициент KL-штрафа к reference (0 = без KL)
    "temperature": 1.0,         # температура сэмплинга переводов
}


# =============================================================================
# 3.2. Process rewards: BLEU на промежуточных этапах
# =============================================================================
# Reward вычисляется каждые n_w=8 входных слов: BLEU между текстовым выводом модели
# ДО данного фрейма t и ground-truth переводом соответствующих входных предложений.
# Это даёт "process" сигнал — модель получает награду не только в конце, но и на
# промежуточных этапах, что важно для обучения тайминга.
#
# Полный reward на шаге t:
#   R_t = lambda * BLEU_intermediate(y_pred[:t], y_gt) + (1 - lambda) * BLEU_total(y_pred, y_gt)
# где lambda = 0.5.
def compute_process_reward(
    predicted_text: list[str],
    reference_text: list[str],
    n_w: int = GRPO_CONFIG["n_w"],
    lam: float = GRPO_CONFIG["lambda_balance"],
) -> list[float]:
    """
    Вычисляет process rewards на промежуточных шагах.

    Аргументы:
        predicted_text: список предсказанных текстовых фрагментов (по шагам).
        reference_text: список ground-truth текстовых фрагментов.
        n_w:            частота reward (во входных словах).
        lam:            баланс total/intermediate BLEU.

    Возвращает:
        rewards: список наград (по шагам).
    """
    from sacrebleu import corpus_bleu  # [в проде] pip install sacrebleu

    rewards = []
    cum_pred = []
    cum_ref = []
    for i, (pred, ref) in enumerate(zip(predicted_text, reference_text)):
        cum_pred.append(pred)
        cum_ref.append(ref)
        # Каждые n_w слов (или на каждом шаге — упрощённо) считаем BLEU
        if (i + 1) % n_w == 0 or i == len(predicted_text) - 1:
            bleu_inter = corpus_bleu(cum_pred, [cum_ref]).score
            bleu_total = corpus_bleu(predicted_text, [reference_text]).score
            r_t = lam * bleu_inter + (1 - lam) * bleu_total
            rewards.append(r_t)
    return rewards


# =============================================================================
# 3.3. Group-relative advantage (без critic)
# =============================================================================
# A_i = (r_i - mean(r)) / std(r)   — для каждого перевода i в группе из G.
# Это ключевое отличие GRPO от PPO: baseline = средняя награда по группе,
# а не обучаемая value-сеть. Экономит память (нет value network).
def compute_group_advantages(rewards: list[float]) -> list[float]:
    """
    Вычисляет group-relative advantages.

    Аргументы:
        rewards: список наград для G переводов группы.

    Возвращает:
        advantages: нормированные advantages (A_i = (r_i - mean) / std).
    """
    r = torch.tensor(rewards, dtype=torch.float32)
    mean = r.mean()
    std = r.std() + 1e-8  # защита от деления на 0
    advantages = ((r - mean) / std).tolist()
    return advantages


# =============================================================================
# 3.4. GRPO loss
# =============================================================================
# Для каждого перевода i и шага t:
#   ratio_t = exp(log_pi_theta(a_{i,t}) - log_pi_old(a_{i,t}))
#   L = -E[ min(ratio_t * A_{i,t}, clip(ratio_t, 1-eps, 1+eps) * A_{i,t}) ]
# Advantage A_{i,t} = сумма нормированных rewards с шага t onwards (cumulative).
def grpo_loss(
    log_probs_new: torch.Tensor,   # (G, T) — log prob новых действий
    log_probs_old: torch.Tensor,   # (G, T) — log prob старых действий (old policy)
    advantages: torch.Tensor,      # (G, T) — advantage на каждый шаг
    clip_eps: float = GRPO_CONFIG["clip_eps"],
) -> torch.Tensor:
    """
    Вычисляет GRPO loss (для максимизации -> берём с минусом для gradient descent).

    Аргументы:
        log_probs_new: (G, T) — log pi_theta(a_{i,t} | s_{i,t})
        log_probs_old: (G, T) — log pi_old(a_{i,t} | s_{i,t})
        advantages:    (G, T) — advantage (group-relative, cumulative)
        clip_eps:      clipping параметр.

    Возвращает:
        loss: скаляр (для минимизации).
    """
    ratio = torch.exp(log_probs_new - log_probs_old)  # (G, T)
    surr1 = ratio * advantages
    surr2 = torch.clamp(ratio, 1.0 - clip_eps, 1.0 + clip_eps) * advantages
    loss = -torch.min(surr1, surr2).mean()
    return loss


# =============================================================================
# 3.5. Цикл GRPO-обучения
# =============================================================================
def train_grpo(
    model: nn.Module,
    ref_model: nn.Module,           # frozen copy для log_probs_old (и опц. KL)
    dataloader,
    cfg: dict = GRPO_CONFIG,
    device: str = "cuda",
):
    """
    RL fine-tuning цикл GRPO.

    Аргументы:
        model:     текущая policy (обучается) — base-модель после Coarse ST.
        ref_model: frozen копия для вычисления log_probs_old.
        dataloader: sentence-aligned пары (source_tokens, target_tokens, text_tokens).
        cfg:       конфигурация GRPO.
        device:    'cuda'.

    Шаги:
      1. Для каждого входа сэмплируем G переводов из policy (с температурой).
      2. Вычисляем process rewards (BLEU каждые n_w слов).
      3. Group-relative advantages (без critic).
      4. GRPO loss с clipping.
      5. backward + step (LR=1e-6).
    """
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg["lr_policy"])
    ref_model.eval()
    for p in ref_model.parameters():
        p.requires_grad_(False)

    model.train()
    step = 0
    for batch in dataloader:
        if step >= cfg["max_steps"]:
            break
        source_tokens, target_tokens, reference_text = batch
        source_tokens = source_tokens.to(device)
        target_tokens = target_tokens.to(device)

        G = cfg["group_size"]
        all_log_probs_new = []
        all_log_probs_old = []
        all_rewards = []

        # 1. Сэмплируем G переводов из policy
        for g in range(G):
            with torch.no_grad():
                # [warn] sampling с температурой; collect log_probs_old из ref_model
                sampled = model.translate_streaming(source_tokens[0], max_steps=target_tokens.shape[2])
            # Вычисляем log_probs под new policy и old policy
            log_probs_new = _compute_sequence_logprobs(model, source_tokens, sampled, device)
            with torch.no_grad():
                log_probs_old = _compute_sequence_logprobs(ref_model, source_tokens, sampled, device)
            all_log_probs_new.append(log_probs_new)
            all_log_probs_old.append(log_probs_old)

            # 2. Process rewards (нужен текстовый вывод; здесь — заглушка)
            predicted_text = _tokens_to_text(sampled)  # [в проде] decode через tokenizer
            rewards = compute_process_reward(predicted_text, reference_text, cfg["n_w"], cfg["lambda_balance"])
            all_rewards.append(rewards)

        # 3. Group-relative advantages
        # Усредняем advantages по группе (как в Hibiki-Zero: "advantages averaged over multiple translations")
        # и делаем cumulative (advantage_t = сумма нормированных rewards с t onwards)
        advantages_per_group = []
        for g in range(G):
            adv = compute_group_advantages(all_rewards[g])
            # cumulative: A_{i,t} = sum_{k>=t} normalized_reward_k
            cum_adv = []
            running = 0.0
            for r in reversed(adv):
                running += r
                cum_adv.append(running)
            cum_adv.reverse()
            advantages_per_group.append(cum_adv)

        # 4. GRPO loss
        log_probs_new = torch.stack(all_log_probs_new)   # (G, T)
        log_probs_old = torch.stack(all_log_probs_old)   # (G, T)
        advantages = torch.tensor(advantages_per_group, device=device)  # (G, T)

        loss = grpo_loss(log_probs_new, log_probs_old, advantages, cfg["clip_eps"])

        # 5. Backward + step
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        if step % 100 == 0:
            print(f"[GRPO step {step}] loss={loss.item():.4f}, "
                  f"mean_reward={torch.tensor(all_rewards).mean().item():.2f}")
        step += 1

    torch.save(model.state_dict(), "/data/checkpoints/grpo_final.pt")
    print("[done] GRPO fine-tuning завершён.")


# =============================================================================
# 3.6. Вспомогательные функции
# =============================================================================
def _compute_sequence_logprobs(model, source_tokens, target_tokens, device) -> torch.Tensor:
    """
    Вычисляет log-prob последовательности target-токенов под моделью.
    Возвращает: (T,) — log probs по time-шагам.

    [warn] В проде: использует forward модели с teacher forcing и собирает
    log_softmax логитов для ground-truth токенов.
    """
    # Заглушка: реальные log_probs вычисляются из логитов модели
    T = target_tokens.shape[1]
    return torch.randn(T, device=device) * 0.1  # [в проде] заменить


def _tokens_to_text(tokens: torch.Tensor) -> list[str]:
    """Декодирует токены в текст (для BLEU). [в проде] использовать tokenizer."""
    return ["placeholder"] * 4  # [в проде] заменить


# =============================================================================
# 3.7. Запуск
# =============================================================================
if __name__ == "__main__":
    print("Этап 3: RL Fine-tuning — GRPO")
    print(f"  LR={GRPO_CONFIG['lr_policy']}, n_w={GRPO_CONFIG['n_w']}, "
          f"lambda={GRPO_CONFIG['lambda_balance']}, G={GRPO_CONFIG['group_size']}")
    print("  [warn] Подключите base-модель (после этапа 2) и sentence-aligned данные.")
