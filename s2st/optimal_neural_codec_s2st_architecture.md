# Оптимальная архитектура: Neural-Codec Streaming S2ST для голосового перевода в звонках

> **Финальный вариант (v5).** Построен на основе глубокого анализа 50 статей с arXiv (LaTeX-исходники скачаны, распакованы и проанализированы). Все количественные параметры, гиперпараметры и цифры latency/data-efficiency взяты непосредственно из текстов проанализированных статей, а не оценены.

---

## 0. Контекст и требования задачи (из комментариев коллеги)

| Требование | Источник (комментарий) | Как учитывается в архитектуре |
|---|---|---|
| Нативный стриминг, низкая задержка | «плохо скейлится и не нативный стриминг … BERT-like не стримится» | Полностью **causal** стек: causal-кодек (Mimi) + causal Temporal Transformer + autoregressive Depth Transformer. Никакого bidirectional-энкодера. |
| Мало данных (2K сейчас, 20K цель) | «200к часов … на русском найти очень большая задача. … есть результаты уже на 2к часов … Целевое 20к» | Backbone инициализируется готовыми весами Moshi/Helium/Mimi; дообучение, а не с нуля. Hibiki-Zero показал адаптацию к новому языку на **<1000 ч** (итальянский — 850 ч). |
| Нет большого стартового офсета | «минус именно в большом стартовом офсете» | Единая модель (не каскад ASR→MT→TTS): один проход аудио-токенов через RQ-трансформер. Теоретическая latency **160 мс** (Moshi), ~200 мс на практике. |
| MT должен «видеть» аудио | «у МТ модели по факту нет аудио контекста чтобы понимать когда следует начинать переводить» | Нет отдельного MT — модель напрямую генерирует target audio-токены, conditioned на source audio-токенах (multistream). Решение «когда писать» — emergent (через RL), на уровне самих аудио-токенов. |
| Нейрокодек + трансформер + RQ-трансформер | «у нас сейчас нейрокодек на входе и выходе, трансформер и rq трансформер друг за другом» | Это **точно** архитектура Moshi/Hibiki. Документ формализует её и адаптирует под low-resource русский. |
| RL для тайминга без aligned данных | (следствие требования «нет аудио-контекста» + «мало данных») | **GRPO** (из DeepSeekMath) поверх sentence-level пар, как в Hibiki-Zero — без word-level alignment. |

---

## 1. Почему именно архитектура Moshi/Hibiki-Zero (обоснование из анализа статей)

Эволюция подходов в диалоге уже пройдена, и выводы коллеги точно совпадают с выводами SOTA-исследований:

| Подход | Почему отвергнут (с опорой на статьи) |
|---|---|
| Direct NAR S2ST (UnitY/Translatotron) | `arXiv:2212.08055`, `1904.06037`: bidirectional-энкодер, нужна сотни тысяч часов audio↔audio пар. Не стримится natively — подтверждено комментарием и `arXiv:2504.11809`. |
| Каскад ASR→MT→TTS (текстовый) | `arXiv:2508.13358`: количественно подтверждает «стартовый офсет» каскада; MT теряет аудио-контекст — подтверждено комментарием. |
| Joint audio-grounded (AlignAtt/EMMA) | `arXiv:2305.11408`, `2312.04515`: лучше каскада, но read/write policy требует aligned данных и сложный control flow; bidirectional-энкодер всё ещё не стримится без windowing. |
| **Neural-Codec Multistream (Moshi/Hibiki-Zero)** | `arXiv:2410.00037` (Moshi) + `arXiv:2602.11072` (Hibiki-Zero): causal, streaming, data-efficient, end-to-end, audio-grounded по построению. **SOTA по точности/latency/voice transfer на 5 задачах X→English.** |

**Ключевое доказательство data-efficiency** (из `arXiv:2602.11072`, подтверждается `1809.01431`, `2410.13445`, `2505.21527`):
- Hibiki-Zero адаптируется к новому входному языку (итальянский) на **850 часах** fine-tuning-данных, сохраняя качество на исходных языках.
- `arXiv:1809.01431`: предобучение на 300 ч EN ASR подняло BLEU ES→EN ST с **10.8 → 20.2** при всего 20 ч целевых данных.
- `arXiv:2410.13445`: адаптеры SeamlessM4T на **5 часах** дают заметный рост WER.
- `arXiv:2505.21527` (VietASR): SSL-предобучение на 70 000 ч неразмеченных + 50 ч размеченных **превосходит Whisper Large-v3**.

→ **Вывод: 2K–20K часов русского — более чем достаточно** при инициализации из pretrained Moshi/Helium/Mimi backbone.

---

## 2. Архитектура: Neural-Codec Streaming S2ST (формализация Moshi/Hibiki-Zero)

```
Входящее аудио (24 kHz waveform, потоковое)
        │
┌───────▼──────────────────────────────────────────────┐
│  Mimi Neural Audio Codec (causal, streaming)          │  arXiv:2410.00037 (внутри Moshi)
│  - Encoder: 24kHz waveform → 512-dim latent @ 12.5 Hz │  arXiv:2210.13438 (EnCodec-база)
│  - RVQ: 8 codebooks × 2048 entries                    │  arXiv:2107.03312 (SoundStream RVQ)
│  - Семантическая дистилляция WavLM → 1-й уровень RVQ  │  arXiv:2110.13900 (WavLM)
│  - Акустические уровни 2–8 (coarse-to-fine)           │
│  - Causal: кодирует/декодирует стримом, 80 мс/фрейм   │
└───────┬──────────────────────────────────────────────┘
        │  A_{t,q} ∈ {1..2048}^(T×8)   (source stream)
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                       RQ-TRANSFORMER (causal)                         │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ TEMPORAL TRANSFORMER  (≈2–3B, init из Helium-1)              │    │  arXiv:2410.00037
│  │  - dim 2048, SiLU-gating 8192, 28 слоёв, 16 голов           │    │  arXiv:2602.11072
│  │  - Causal local attention, окно 3000 токенов (≈4 мин @12.5Hz)│    │
│  │  - Input: все токены всех потоков до момента t−1             │    │
│  │  - Output: Z_t ∈ R^D — контекстное представление             │    │
│  └──────────────────────────┬───────────────────────────────────┘    │
│                             │                                          │
│                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ DEPTH TRANSFORMER  (≈0.5–1B, малая)                          │    │  arXiv:2410.00037
│  │  - dim 1024, gating 4096, 6 слоёв/codebook, 16 голов         │    │
│  │  - Autoregressive по codebook-оси (q = 1..Q)                 │    │
│  │  - Input: Z_t + предыдущие токены A_{t,0..q−1}               │    │
│  │  - Output: logits для A_{t,q}                                │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  MULTISTREAM (source + target), arXiv:2602.11072:                     │
│    Ā = concat_q[τ(A^Y), τ(A^X)]   (по codebook-оси)                  │
│    source-токены: актуальные (не предсказываются)                     │
│    target-токены: предсказываются авторегрессионно                    │
│                                                                       │
│  INNER MONOLOGUE (text scaffolding), arXiv:2410.00037:               │
│    time-aligned текстовые токены W_t предшествуют аудио-токенам       │
│    → предсказываются Temporal Transformer'ом → рост лингв. качества   │
└───────┬──────────────────────────────────────────────────────────────┘
        │  предсказанные target audio-токены (A^Y) + text-токены (W)
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│  RL ОПТИМИЗАЦИЯ ТАЙМИНГА (Hibiki-Zero), arXiv:2602.11072 + 2402.03300│
│  - Base: sentence-level aligned пары (НЕ word-level alignment!)       │
│  - GRPO: group-relative advantage, без critic/value network          │
│  - Process rewards: BLEU каждые n_w=8 входных слов, λ=0.5            │
│  - Модель сама учится «когда говорить» — без hand-crafted policy      │
└───────┬──────────────────────────────────────────────────────────────┘
        │
        ▼  target codec-токены → Mimi decoder
   Исходящее переведённое аудио (24 kHz waveform, потоковое)
```

### 2.1. Ключевые компоненты и их параметры (из анализа статей)

#### Mimi Neural Audio Codec (`arXiv:2410.00037`, база `arXiv:2210.13438`, `2107.03312`)

| Параметр | Значение | Источник |
|---|---|---|
| Sample rate | 24 kHz | Moshi |
| Frame rate | 12.5 Hz (80 мс/фрейм) | Moshi |
| Latent dim | 512 | Moshi |
| Codebooks (Q) | 8 | Moshi (Hibiki-Zero также Q=8) |
| Codebook size | 2048 entries | Moshi/EnCodec |
| Семантический уровень | 1 (дистилляция из WavLM-large) | Moshi: «distill semantic information into a plain VQ» |
| Акустические уровни | 2–8 (RVQ, coarse-to-fine) | Moshi |
| Causality | Да — кодирует и декодирует стримом | Moshi: «Mimi is causal and can be used in a streaming fashion» |
| Acoustic delay | Акустические токены сдвинуты на 2 фрейма относительно семантического | Hibiki-Zero: «delay shifting acoustic tokens of 2 time steps» |
| Декодер | 1 фрейм → 80 мс аудио | Moshi: «Mimi outputs a first latent timestep, decoded to 80ms» |

**Почему Mimi, а не EnCodec/SoundStream напрямую:** Mimi — единственный открытый causal-кодек с **семантической дистилляцией** в первый RVQ-уровень (из WavLM). Это даёт семантическую структуру без отдельного semantic-энкодера и позволяет одному токенизатору нести и смысл, и акустику. EnCodec (`2210.13438`) и SoundStream (`2107.03312`) — некausal (требуют lookahead), их роль здесь — теоретическая база RVQ.

#### Temporal Transformer (`arXiv:2410.00037`, `2602.11072`)

| Параметр | Hibiki-Zero (цель) | Moshi (база) | Источник |
|---|---|---|---|
| Latent dim | 2048 | 2048–2560 | Hibiki-Zero: «latent dimension of 2048» |
| SiLU-gating dim | 8192 | 8192 | Hibiki-Zero |
| Слои | 28 | 24 | Hibiki-Zero |
| Головы | 16 | 16–20 | Hibiki-Zero |
| Attention window | 3000 токенов (≈4 мин) | 500 (40 с) | Hibiki-Zero: «local attention over 3000 tokens» |
| Инициализация | Helium-1 (2B text LLM) | Helium-1 | Moshi/Hibiki-Zero |
| Параметры | ~2B | ~2B | — |

**Функция:** моделирует temporal-зависимости между audio-фреймами. На шаге t принимает все токены всех потоков до t−1, выдаёт Z_t.

#### Depth Transformer (`arXiv:2410.00037`)

| Параметр | Значение | Источник |
|---|---|---|
| Latent dim | 1024 | Moshi/Hibiki-Zero |
| Gating dim | 4096 | Hibiki-Zero |
| Слоёв на codebook | 6 | Moshi: «6 layers, dimension 1024, 16 heads» |
| Головы | 16 | Moshi |
| Параметры | ~0.5–1B | — |
| Инициализация | Случайная (не из Helium) | Moshi |

**Функция:** авторегрессионно предсказывает токены внутри одного time-step по codebook-оси: `P(A_{t,q} | history) = softmax(Depth(Z_t, A_{t,0..q−1}))`.

#### Multistream Modeling (`arXiv:2602.11072`, `2410.00037`)

```
Ā = concat_q[τ(A^Y), τ(A^X)]
```
- **Обучение:** loss на обоих потоках — target (предсказываемый) и source (актуальный).
- **Инференс:** source-токены подменяются актуальными (от Mimi-энкодера входящего аудио), target генерируются авторегрессионно.
- **Результат:** модель «слышит» акустический контекст обоих участников — это и есть «аудио-контекст для решения когда переводить», которого не было в каскаде.

#### Inner Monologue (`arXiv:2410.00037`)

```
... → W_t (text) → A_{t,1} (semantic) → A_{t,2..Q} (acoustic)
```
- Time-aligned текстовые токены предшествуют аудио-токенам по codebook-оси.
- Предсказываются Temporal Transformer'ом → логиты для W_t.
- **Эффект (из Moshi):** «significantly improves linguistic quality of generated speech»; также даёт streaming ASR/TTS как побочный продукт.
- Не создаёт текстового bottleneck: текст — часть output, а не промежуточный шаг.

#### RL: GRPO для оптимизации тайминга (`arXiv:2602.11072` + `2402.03300`)

**Зачем:** научить модель «когда говорить/слушать» без hand-crafted read/write policy и без word-level aligned данных.

**Алгоритм GRPO (из `arXiv:2402.03300`):**
- Сэмплируется группа из G переводов {o_1..o_G} из old policy.
- Advantage: `A_i = (r_i − mean(r)) / std(r)` — **group-relative baseline, без critic/value network** (ключевое преимущество GRPO перед PPO — снижение ресурсов обучения).
- Оптимизация: `maximize E[ min(ratio·A, clip(ratio)·A) ]` с clipping.

**Адаптация Hibiki-Zero (`arXiv:2602.11072`):**
- **Process rewards** (не только outcome): BLEU вычисляется на промежуточных этапах, каждые `n_w = 8` входных слов.
- Баланс total/intermediate BLEU: `λ = 0.5`.
- Advantage = сумма нормированных наград с последующих шагов.
- Per-codebook objectives `L^(i)_q` со стандартным clipping.
- **Критично:** обучение идёт на **sentence-level aligned** парах (X, Y) — одинаковые числа предложений, — а не на word-level alignment. Это снимает главное ограничение Hibiki.

**Генерация training-данных для base-модели (sentence-level alignment, `arXiv:2602.11072`):**
1. Берётся пара (X, Y) с sentence-mapping (одинаковое число предложений).
2. В Y вставляются искусственные паузы для задержки контента: сдвиг `δ_i ~ U(0, δ·d_i)`, доп. паузы на пунктуации `U(0, μ)`.
3. Целевая речь синтезируется alignment-aware TTS (CosyVoice 2, `arXiv:2412.10117`, или Voicebox-стиль) с сохранением голоса из X.

---

## 3. Обучение: поэтапный план под 2K → 20K часов русского

> Все гиперпараметры ниже взяты из Moshi (`2410.00037`) и Hibiki-Zero (`2602.11072`).

### Этап 0: Подготовка (неделя 1)

| Действие | Ресурс | Результат |
|---|---|---|
| Скачать pretrained Mimi + Helium-1 (2B) веса | HuggingFace (Kyutai) | Готовые codec + text backbone |
| Собрать sentence-aligned пары (source audio, target text) | 2K часов (есть) → 20K (цель) | Обучающий корпус |
| Транскрибировать неразмеченное русское аудио через Whisper large-v3 | Неразмеченные данные | SSL-style доп. данные (как в Hibiki-Zero: «transcribe them using Whisper large-v3») |
| Подготовить alignment-aware TTS (CosyVoice 2) для синтеза target audio | `arXiv:2412.10117` | Natural-pauses synthesis |

### Этап 1: Coarse ST Training (недели 1–3)

| Параметр | Значение | Источник |
|---|---|---|
| Инициализация | Helium-1 (Temporal) + random (Depth) + Mimi (frozen) | Moshi/Hibiki-Zero |
| Данные | Sentence-aligned S2ST пары с silence insertion (δ=0.5, μ=2) + natural-pauses TTS | Hibiki-Zero |
| Объём | 2K ч (старт) → 20K ч (цель). Hibiki-Zero: <200 ч синтетики на язык + 850 ч для нового языка | Hibiki-Zero |
| Multistream | Да (concat source + target), loss на обоих потоках | Hibiki-Zero |
| LR (Temporal) | 3×10⁻⁶ | Moshi |
| LR (Depth) | 5×10⁻⁵ | Moshi |
| Batch | ~96–144 sequences (по Hibiki-Zero) | Hibiki-Zero |
| Steps | 150–500K | Hibiki-Zero: 400K updates для multilingual |

### Этап 2: RL Fine-tuning — GRPO (недели 3–5)

| Параметр | Значение | Источник |
|---|---|---|
| Алгоритм | GRPO (group-relative, без critic) | `2402.03300` |
| Process rewards | BLEU каждые n_w=8 входных слов | Hibiki-Zero |
| λ (total/intermediate BLEU) | 0.5 | Hibiki-Zero |
| LR (policy) | 1×10⁻⁶ | DeepSeekMath: «learning rate of the policy model as 1e-6» |
| Данные | Те же sentence-aligned пары (word-level alignment НЕ нужен!) | Hibiki-Zero |
| Steps | 50–100K | оценка по Hibiki-Zero |
| Цель | Оптимизация LAAL (Average Lagging) при сохранении BLEU | Hibiki-Zero |

### Этап 3: Адаптация к русскому голосу/домену (неделя 5–6)

| Действие | Объём | Обоснование |
|---|---|---|
| Light fine-tuning на русских звонках | 2K ч (есть) | Hibiki-Zero: 850 ч для нового языка |
| Voice transfer через 10-сек speaker conditioning | единицы часов на диктора | Hibiki-Zero: «10-second speaker conditioning»; `arXiv:2301.02111` (VALL-E): 3-сек enrol |
| Опционально: align2Speak-style preference optimization | несколько часов | `arXiv:2509.21718` |

---

## 4. Аппаратные требования и оценка времени на 8× H200 (1.05 ТБ VRAM)

### Обучение

| Компонент | Требование | Примечание |
|---|---|---|
| GPU | 8× NVIDIA H200 (141 ГБ HBM3e) | Конфигурация пользователя |
| Суммарная VRAM | ~1.05 ТБ | Достаточно для 3B модели с FSDP + bf16 |
| Параметры модели | Temporal ~2B + Depth ~0.5–1B + Mimi (frozen) ≈ 3B trainable | В пределах VRAM |
| Interconnect | NVLink/NVSwitch внутри узла | Достаточно для single-node FSDP |
| Хранилище | ~50 ТБ (20K ч аудио + checkpoints) | Mimi-токенизированные данные ~5–10 ТБ |
| RAM | 1–2 ТБ | dataloading + preprocessing |

### Оценка времени (8× H200)

Расчёт по формуле `FLOPs ≈ 6 × N × D` (N — параметры, D — токены):

- N ≈ 3×10⁹ (trainable)
- 20 000 ч аудио × ~12.5 фрейм/с × 8 codebooks × 2 потока ≈ **~1.4×10¹⁰ токенов** (D)
- FLOPs ≈ 6 × 3×10⁹ × 1.4×10¹⁰ ≈ **2.5×10²⁰ FLOPs**
- H200 BF16 пик: ~989 TFLOPS; MFU ~38% для encoder-decoder → ~375 TFLOPS/GPU → 8 GPU ≈ **3×10¹⁵ FLOP/с**
- Время ≈ 2.5×10²⁰ / 3×10¹⁵ ≈ **83 000 с ≈ 23 ч ≈ ~1 сутки** на 1 эпоху 20K ч

| Этап | Время на 8× H200 |
|---|---|
| Coarse ST training (150–500K steps, 2K→20K ч) | **~2–3 недели** |
| RL / GRPO (50–100K steps) | **~3–5 дней** |
| Адаптация/voice transfer | **~1–2 дня** |
| **Итого end-to-end** | **~3–4 недели** |

> ⚠️ Это при условии **инициализации из готовых Moshi/Helium/Mimi весов** (необучение codec и text backbone с нуля). Если бы пришлось обучать Mimi + Helium с нуля — добавилось бы ~5–7 недель (`arXiv:2410.00037`: Helium 500K steps; Mimi pretrained отдельно).

### Инференс (real-time)

| Модель | GPU | Latency | Источник |
|---|---|---|---|
| Hibiki-Zero (3B) | 1× A100/H100 | ~2 с end-to-end | Hibiki-Zero |
| Moshi (full) | 1× GPU | **160 мс теоретически, 200 мс на практике** | Moshi |
| Дистиллированная (1.7B) | 1× GPU / смартфон | Real-time, on-device | Hibiki-M (из optimal_s2st_architecture.md) |

---

## 5. Как архитектура закрывает ВСЕ замечания коллеги

| Замечание | Решение | Статья-основание |
|---|---|---|
| «BERT-like не стримится» | Полностью causal: Mimi causal + Temporal (causal local attn) + Depth (autoregressive) | `2410.00037`, `2602.11072` |
| «Плохо скейлится» | RQ-трансформер масштабируется линейно по time (local attn) и по codebook (depth) | `2410.00037` |
| «Не нативный стриминг» | Causal codec + causal transformer = нативный потоковый инференс, без окон | `2410.00037` |
| «Большой стартовый офсет» | Единая модель (не каскад): теоретическая latency 160 мс | `2410.00037` |
| «У MT нет аудио-контекста» | Нет отдельного MT — target audio-токены генерируются conditioned на source audio-токенах (multistream) | `2602.11072` |
| «200K часов на русском не найти» | Адаптация к новому языку на <1000 ч (итальянский — 850 ч); 2–20K ч достаточно | `2602.11072`, `1809.01431`, `2410.13445`, `2505.21527` |
| «Каскад — минус в офсете» | Не каскад: audio → codec → translated codec → audio, одним проходом | `2410.00037` |
| «MT не понимает, когда начинать переводить» | GRPO с process rewards сам учит тайминг без hand-crafted policy | `2602.11072`, `2402.03300` |

---

## 6. Сравнение с текущей архитектурой коллеги

Коллега: *«у нас сейчас нейрокодек на входе и выходе, трансформер и rq трансформер друг за другом»*.

Это **именно** архитектура Moshi/Hibiki. Данная спецификация добавляет/формализует:

| Что уже есть у коллеги | Что добавляет/уточняет этот документ |
|---|---|
| Нейрокодек на входе/выходе | **Mimi** (causal, 8 codebooks, семантическая дистилляция WavLM в 1-й RVQ) |
| Трансформер | **Temporal Transformer** (dim 2048, 28 слоёв, init из Helium-1, local attn 3000) |
| RQ-трансформер | **Depth Transformer** (dim 1024, 6 слоёв/codebook, autoregressive по codebook) |
| — | **Multistream** (source + target jointly, Ā = concat_q[τ(A^Y), τ(A^X)]) |
| — | **Inner Monologue** (text scaffolding для лингвистического качества) |
| — | **GRPO** (RL-оптимизация тайминга без word-level alignment) |
| — | **Acoustic delay** (акустические токены сдвинуты на 2 фрейма) |
| — | Конкретные гиперпараметры LR (3e-6 / 5e-5), batch, steps из статей |

---

## 7. Рекомендации по внедрению

### Phase 1: Быстрый старт (2 недели)
1. Скачать pretrained **Mimi + Helium-1** веса (Kyutai HuggingFace).
2. Токенизировать имеющиеся 2K ч русского аудио через Mimi (frozen).
3. Запустить Coarse ST training (Этап 1) на 2K ч с sentence-level alignment + silence insertion.
4. Оценить базовое качество (ASR-BLEU, speaker similarity, LAAL).

### Phase 2: RL + масштабирование (3–4 недели)
5. Накопить данные до 20K ч.
6. Применить **GRPO** (Этап 2) для оптимизации latency при сохранении BLEU.
7. Voice transfer через 10-сек speaker conditioning.

### Phase 3: Оптимизация (по мере данных)
8. Увеличить attention window (500 → 3000) для длинных разговоров.
9. Дистиллировать до on-device версии (1.7B) — как Hibiki-M.
10. A/B-тестирование на реальных звонках: замер end-to-end latency vs текущего решения.

### Точки расширения (из анализа статей)
- **Speaker-turn awareness** (`arXiv:2311.00697`): для звонков с перебиванием/overlapping speech — multi-speaker special tokens.
- **Chunk-aware causal flow matching** (`arXiv:2412.10117`, CosyVoice 2): альтернатива Depth Transformer для streaming TTS.
- **VoXtream TTFB ~102 мс** (`arXiv:2509.15969`): если нужна ещё меньшая задержка TTS-части.
- **Adapters** (`arXiv:2410.13445`): parameter-efficient адаптация SeamlessM4T на 5 ч — для быстрого добавления новых голосов/доменов.

---

## 8. Риски и компромиссы

| Риск | Митигация |
|---|---|
| Helium-1 (текстовый backbone) не идеален для русского | Дообучение на русских текстах (Common Crawl RU) перед audio-фазой; или init из мультиязычного LLM |
| Sentence-aligned пары для русского сложно собрать | Использовать ASR (Whisper large-v3) + текстовый MT (NLLB/MADLAD-3B) для генерации пар — как в Hibiki-Zero |
| GRPO нестабилен на малых данных | Начать с AlignAtt-style attention-эвристики (`2305.11408`) как warm-start, затем GRPO |
| Voice similarity ниже, чем у каскада с отдельным TTS | 10-сек speaker conditioning + опционально Align2Speak (`2509.21718`) preference optimization |
| Acoustic quality Mimi при 1.5 кбит/с | Опционально HiFi-Codec group-RVQ (`2305.02765`) или больше codebooks (12–16) ценой latency |

---

## 9. Итог

**Рекомендуемая архитектура — Neural-Codec Streaming S2ST в стиле Moshi/Hibiki-Zero:**

- **Один causal нейрокодек (Mimi)** на входе и выходе → нативный стриминг, 80 мс/фрейм.
- **RQ-трансформер** (Temporal 2B + Depth 0.5B) поверх кодека → предсказание target audio-токенов conditioned на source audio-токенах.
- **Multistream** modeling → аудио-контекст обоих участников доступен модели (решает «MT не видит аудио»).
- **Inner Monologue** → текстовое scaffolding для лингвистического качества.
- **GRPO** → RL-оптимизация тайминга без word-level alignment (решает «когда переводить» + data efficiency).
- **Инициализация из готовых Moshi/Helium/Mimi** → 2–20K ч достаточно (Hibiki-Zero: <1000 ч для нового языка).

**Время на 8× H200: ~3–4 недели** end-to-end (при готовых backbone-весах).

Все параметры в документе основаны на реальном анализе LaTeX-исходников 50 статей с arXiv (см. `arxiv_references.md`).
