# Реализация архитектуры Neural-Codec Streaming S2ST

Скрипты для пошаговой реализации архитектуры из `optimal_neural_codec_s2st_architecture.md`.
Каждый файл — отдельный этап; содержимое переносится в ячейки Jupyter notebook вручную.

## Структура файлов

| Файл | Этап | Описание |
|------|------|----------|
| `00_data_preparation.py` | Этап 0 | Подготовка данных: загрузка Mimi/Helium, токенизация аудио, Whisper-транскрипция, sentence-level alignment, alignment-aware TTS |
| `01a_mimi_codec.py` | Этап 1A | Mimi Neural Audio Codec: контракт кодека, acoustic delay, multistream concat, streaming-энкодер |
| `01b_temporal_transformer.py` | Этап 1B | Temporal Transformer: causal local attention, SiLU-gating FFN, KV-cache, init из Helium-1 |
| `01c_depth_transformer.py` | Этап 1C | Depth Transformer: авторегрессия по codebook-оси, causal attention по q, per-codebook головы |
| `01d_multistream_inner_monologue.py` | Этап 1D | Multistream modeling + Inner Monologue: объединение source/target, per-kind эмбеддинги |
| `01e_full_model.py` | Этап 1E | Полная модель NeuralCodecS2ST: сборка всех компонентов, обучающий forward, streaming-инференс |
| `02_coarse_st_training.py` | Этап 2 | Coarse ST Training: multitask loss, FSDP, разные LR (3e-6/5e-5), 400K steps |
| `03_grpo_rl_finetuning.py` | Этап 3 | GRPO RL fine-tuning: process rewards (BLEU каждые 8 слов), group-relative advantage, LR 1e-6 |
| `04_russian_voice_adaptation.py` | Этап 4 | Адаптация к русскому: light fine-tuning (2K-20K ч), speaker conditioning (10 сек), Align2Speak |
| `05_streaming_inference.py` | Этап 5 | Streaming-инференс: чанк-за-чанком, KV-cache, целевая latency 160-200 мс |
| `06_evaluation.py` | Этап 6 | Оценка: ASR-BLEU, COMET, LAAL, TTFB, speaker similarity |

## Соответствие архитектуре

```
00 → подготовка данных и pretrained компонентов
       │
01A (Mimi codec) ──► 01B (Temporal) ──► 01C (Depth) ──► 01D (Multistream+IM) ──► 01E (полная модель)
       │                                                                                    │
       └──────────────────────────────────────────────────────────────► 02 (Coarse ST training)
                                                                                              │
                                                                                     03 (GRPO RL)
                                                                                              │
                                                                                     04 (RU adaptation)
                                                                                              │
                                                                          05 (streaming inference) → 06 (evaluation)
```

## Ключевые параметры (из анализа статей)

| Компонент | Параметр | Значение | Источник |
|-----------|----------|----------|----------|
| Mimi | codebooks × size | 8 × 2048 | arXiv:2410.00037 |
| Mimi | frame rate | 12.5 Hz (80 мс) | arXiv:2410.00037 |
| Mimi | acoustic delay | 2 фрейма | arXiv:2602.11072 |
| Temporal | dim / gating | 2048 / 8192 | arXiv:2602.11072 |
| Temporal | layers / heads | 28 / 16 | arXiv:2602.11072 |
| Temporal | attention window | 3000 токенов | arXiv:2602.11072 |
| Depth | dim / gating | 1024 / 4096 | arXiv:2410.00037, 2602.11072 |
| Depth | layers/codebook | 6 | arXiv:2410.00037 |
| Coarse ST | LR temporal / depth | 3e-6 / 5e-5 | arXiv:2410.00037 |
| Coarse ST | steps | 400K | arXiv:2602.11072 |
| GRPO | LR policy | 1e-6 | arXiv:2402.03300 |
| GRPO | n_w (reward freq) | 8 слов | arXiv:2602.11072 |
| GRPO | λ (BLEU balance) | 0.5 | arXiv:2602.11072 |
| Adaptation | speaker conditioning | 10 сек | arXiv:2602.11072 |
| Inference | latency | 160 мс (теор.) / 200 мс (практ.) | arXiv:2410.00037 |

## Использование

1. Заполнить места, помеченные `[в проде]` / `[warn]`, реальными весами и данными.
2. Перенести содержимое каждого файла в соответствующие ячейки Jupyter notebook.
3. Запускать этапы последовательно (00 → 01A..01E → 02 → 03 → 04 → 05 → 06).

Для распределённого обучения (этап 2): `torchrun --nproc_per_node=8 02_coarse_st_training.py`
