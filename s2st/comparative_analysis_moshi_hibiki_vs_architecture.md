# Сравнительный анализ: связка статей Moshi / Hibiki / Hibiki-Zero vs `optimal_neural_codec_s2st_architecture.md`

> Анализ выполнен на основе **LaTeX-исходников** трёх статей с arXiv (скачаны, распакованы, прочитаны):
> - **Moshi** — `arXiv:2410.00037` (Défossez et al., Kyutai, 2024)
> - **Hibiki** — `arXiv:2502.03382` (Labiausse, Mazaré, Grave, Pérez, Défossez, Zeghidour, Kyutai, 2025)
> - **Hibiki-Zero** — `arXiv:2602.11072` (Labiausse, Fabre, Estève, Défossez, Zeghidour, Kyutai, 2026)
>
> vs архитектурный документ **`optimal_neural_codec_s2st_architecture.md`** (далее «Документ»).

---

## 1. Что представляет собой каждая из трёх статей

| | Moshi (2410.00037) | Hibiki (2502.03382) | Hibiki-Zero (2602.11072) |
|---|---|---|---|
| **Задача** | Full-duplex голосовой диалог (не перевод) | Симультанный S2ST-перевод (FR→EN) | Симультанный S2ST-перевод (мультиязычный, X→EN) |
| **Архитектура** | Mimi codec + RQ-Transformer (Temporal+Depth) + multistream + Inner Monologue | Mimi codec + RQ-Transformer + multistream (наследует Moshi) | Mimi codec + RQ-Transformer + multistream (наследует Hibiki) |
| **Метод тайминга** | Неявный (full-duplex, всегда говорит/слушает) | **Weakly-supervised**: perplexity MADLAD-3B → word-level alignment → silence insertion | **GRPO (RL)**: sentence-level пары, process rewards, без word-level alignment |
| **Данные** | 7B Helium на 2.1T текстовых токенов; Fisher для duplex | 40K часов на язык (FR/EN); CVSS-T 900ч; ~900ч interpretation pauses | <200ч синтетики multilingual; 850ч для Italian (новый язык) |
| **Размер** | Temporal ~7B (Helium); Depth малый | Temporal 2.7B (dim 2560, 24 layers, 20 heads, window 500); distilled -M 1.7B | Temporal 3B (dim 2048, 28 layers, 16 heads, window 3000) |
| **Результаты** | 160ms теоретическая latency; full-duplex диалог | SOTA FR→EN: ASR-BLEU 47; превосходит Seamless/StreamSpeech по качеству/голосу/естественности | Превосходит Hibiki на +3pts ASR-BLEU; +30pts speaker sim vs Seamless; адаптация <1000ч |
| **Инференс** | Real-time, streaming | Vanilla temperature sampling, **batched**, on-device (-M на смартфоне) | Streaming; RL-оптимизированный тайминг |

**Эволюция:** Moshi (базовая audio-LM архитектура) → Hibiki (адаптация под перевод через weakly-supervised alignment) → Hibiki-Zero (замена alignment на RL/GRPO + мультиязычность + data efficiency).

---

## 2. Сводная таблица: что Документ берёт из каждой статьи

| Компонент / параметр | Moshi (2410.00037) | Hibiki (2502.03382) | Hibiki-Zero (2602.11072) | Документ | Совпадение? |
|---|:---:|:---:|:---:|---|:---:|
| **Mimi codec** (causal, RVQ) | ✅ источник | использует | использует | использует | ✅ точное |
| Sample rate / frame rate | 24kHz / 12.5Hz | то же | то же | 24kHz / 12.5Hz | ✅ |
| Codebooks × size | 8 × 2048 | 8 × 2048 (16 в -full) | 8 × 2048 | 8 × 2048 | ✅ |
| Latent dim codec | 512 | 512 | 512 | 512 | ✅ |
| Semantic distillation (WavLM→RVQ1) | ✅ оригинал | — | — | ✅ | ✅ |
| Acoustic delay = 2 фрейма | ✅ | ✅ | ✅ | 2 | ✅ |
| **Temporal Transformer** | dim 2048–2560 | dim 2560, 24L, 20H, win 500 | dim 2048, 28L, 16H, win 3000 | dim 2048, 28L, 16H, win 3000 | ✅ (взят Hibiki-Zero) |
| SiLU-gating | 8192 | 7040 | 8192 | 8192 | ✅ (Hibiki-Zero) |
| Init из Helium | ✅ Helium 7B | ✅ Helium (pretrain 600K steps) | ✅ Helium-1 2B | Helium-1 | ✅ |
| **Depth Transformer** | dim 1024, 6L/codebook | dim 1024, 6L, gating 2816 | dim 1024, 6L, gating 4096 | dim 1024, 6L, gating 4096 | ✅ (Hibiki-Zero) |
| Depth init | random | random | random | random | ✅ |
| **Multistream** (source+target) | ✅ (user+model) | ✅ (source+target) | ✅ (source+target) | ✅ | ✅ |
| **Inner Monologue** (text prefix) | ✅ оригинал | использует | использует | ✅ | ✅ |
| **Метод тайминга** | неявный (duplex) | weakly-supervised (perplexity) | **GRPO (RL)** | **GRPO (RL)** | ✅ (взят Hibiki-Zero) |
| GRPO: n_w=8, λ=0.5 | — | — | ✅ | ✅ | ✅ |
| GRPO: LR 1e-6 | — | — | ✅ | ✅ | ✅ |
| Sentence-level alignment (без word-level) | — | ❌ (нужен word-level) | ✅ | ✅ | ✅ (Hibiki-Zero) |
| Silence insertion (δ, μ) | — | ✅ (через perplexity) | ✅ (δ=0.5, μ=2) | δ=0.5, μ=2 | ✅ |
| **Coarse ST LR** | 3e-6 / 5e-5 | 3e-6 / 5e-5 (cosine, 2K warmup) | наследует | 3e-6 / 5e-5 | ✅ |
| Coarse ST steps | — | 40K часов данных | 400K updates (multilingual) | 150–500K | ✅ |
| **Адаптация к новому языку** | — | — | ✅ <1000ч (Italian 850ч) | 2K–20K ч (русский) | ✅ (обосновано) |
| Speaker conditioning | 10 сек (WavLM) | ✅ | 10 сек | 10 сек | ✅ |
| Distillation to -M (1.7B) | — | ✅ (4L/codebook, weight sharing) | — | упоминается | ✅ |
| **Latency** | 160ms теор. / 200ms практ. | batched, on-device | RL-оптимизированный | 160–200ms | ✅ |
| Batched inference | — | ✅ (преимущество над Seamless) | — | — | ⚠️ не акцентировано |
| Full-duplex (overlapping/перебивания) | ✅ оригинал | — | — | — | ❌ не используется |

---

## 3. Ключевые расхождения и нюансы

### 3.1. Метод тайминга: weakly-supervised (Hibiki) vs GRPO (Hibiki-Zero) — Документ выбрал верно

| | Hibiki (2502.03382) | Hibiki-Zero (2602.11072) | Документ |
|---|---|---|---|
| Метод | Perplexity MADLAD-3B → word-level alignment → silence insertion | GRPO (RL) на sentence-level парах | GRPO (RL) на sentence-level парах |
| Нужен word-level alignment? | **Да** (через perplexity off-the-shelf MT) | **Нет** | Нет |
| Language-specific heuristics? | Да (perplexity-выравнивание зависит от языка) | Нет (language-agnostic) | Нет |
| Стабильность | Выше (supervised, проверено на FR→EN) | Ниже (RL, требует настройки n_w/λ/clip) | Риск: RL менее стабилен |
| Data efficiency | 40K часов/язык | <200ч синтетики + 850ч для нового языка | 2K–20K ч (русский) |

**Вывод:** Документ правильно выбрал Hibiki-Zero (GRPO) — это единственный вариант, совместимый с low-resource русским (2K–20K часов). Hibiki требует 40K часов/язык и word-level alignment через perplexity, что для русского труднодостижимо. **Но** нужно учитывать риск нестабильности RL — Hibiki-Zero отмечает, что BLEU на RL-данных «much noisier» и LAAL в начале RL «~6 секунд, что far worse than reference».

### 3.2. Параметры Temporal Transformer: Документ берёт Hibiki-Zero, не Hibiki

| Параметр | Hibiki (2.7B) | Hibiki-Zero (3B) | Документ | Комментарий |
|---|---|---|---|---|
| Latent dim | 2560 | 2048 | 2048 | Документ → Hibiki-Zero ✅ |
| Gating | 7040 | 8192 | 8192 | ✅ |
| Layers | 24 | 28 | 28 | ✅ |
| Heads | 20 | 16 | 16 | ✅ |
| Window | 500 (40с) | 3000 (4мин) | 3000 | ✅ — важно для длинных разговоров |

Документ корректно указывает «Hibiki-Zero (цель)» в таблице параметров. Окно 3000 (vs 500 в Hibiki) — обоснованный выбор для звонков с длинными репликами.

### 3.3. Что Документ НЕ перенял из статей

| Функция | Источник | Почему не использовано в Документе | Оценка |
|---|---|---|---|
| **Full-duplex** (overlapping speech, перебивания, interjections) | Moshi | Документ фокусируется на переводе, а не на диалоге; turn-taking в звонке проще | ⚠️ упущение: для звонков с перебиванием full-duplex полезен |
| **Batched inference** (преимущество над Seamless/StreamSpeech) | Hibiki | Документ не акцентирует batched-преимущество | ⚠️ стоит добавить: упрощает деплой |
| **Distillation -M** (детали: 4L/codebook, weight sharing codebooks 9-16, low-rank 128) | Hibiki | Документ упоминает дистилляцию до 1.7B, но без деталей | ⚠️ стоит добавить детали |
| **Weakly-supervised perplexity alignment** | Hibiki | Заменён на GRPO (Hibiki-Zero) | ✅ осознанный выбор |
| **Text pretraining 600K steps** (Helium с нуля) | Hibiki/Moshi | Документ предлагает брать готовый Helium-1 | ✅ правильно (экономия ~2 недель) |

### 3.4. Что Документ добавляет сверх статей (адаптация под русского)

| Добавление | Обоснование | В статьях? |
|---|---|---|
| Целевой язык — русский (2K–20K ч) | Задача коллеги | Hibiki-Zero: только FR/IT; русский не тестировался |
| Whisper large-v3 для транскрипции неразмеченного аудио | Data augmentation | Hibiki-Zero: использует Whisper для ASR-BLEU оценки, не для данных |
| CosyVoice 2 как alignment-aware TTS | Синтез target-аудио | Hibiki/Zero: используют собственный TTS (Voicebox-стиль), не CosyVoice |
| Align2Speak (опц. preference optimization) | Качество голоса | Не в Hibiki/Zero; из arXiv:2509.21718 |
| Этап 6 (метрики: LAAL, TTFB, speaker sim) | Оценка прототипа | Hibiki-Zero использует те же метрики, но Документ формализует пайплайн |

---

## 4. Сводная таблица: сравнение по критериям задачи

| Критерий (из комментариев коллеги) | Moshi | Hibiki | Hibiki-Zero | Документ | Лучший |
|---|:---:|:---:|:---:|:---:|:---:|
| **Нативный стриминг (causal)** | ✅ | ✅ | ✅ | ✅ | все равны |
| **Низкая задержка** | ✅ 160ms | ✅ batched | ✅ RL-оптим. | ✅ 160–200ms | все равны |
| **Data efficiency (<20K ч)** | ❌ (нужен 2.1T токенов Helium) | ❌ (40K ч/язык) | ✅ (<1000ч) | ✅ (2–20K ч) | **Документ = Hibiki-Zero** |
| **Без word-level alignment** | — | ❌ (нужен perplexity-alignment) | ✅ (GRPO) | ✅ (GRPO) | **Документ = Hibiki-Zero** |
| **Аудио-контекст для тайминга** | ✅ (multistream) | ✅ | ✅ | ✅ | все равны |
| **Не каскад (единая модель)** | ✅ | ✅ | ✅ | ✅ | все равны |
| **Адаптация к русскому** | ❌ | ❌ (только FR) | ⚠️ (IT 850ч, RU не тестировался) | ✅ (явная цель) | **Документ** |
| **Проверено экспериментально** | ✅ (диалог) | ✅ (FR→EN SOTA) | ✅ (5 задач X→EN) | ❌ (спецификация) | **Hibiki-Zero** |
| **Стабильность метода** | ✅ | ✅ (supervised) | ⚠️ (RL нестабилен) | ⚠️ (наследует) | **Hibiki** |
| **Batched / on-device** | — | ✅ (-M на смартфоне) | — | ⚠️ (не акцент.) | **Hibiki** |
| **Full-duplex (перебивания)** | ✅ | ❌ | ❌ | ❌ | **Moshi** |
| **Готовые веса + код** | ✅ | ✅ | ✅ | ❌ (свои веса нужны) | **статьи** |

---

## 5. Что в итоге лучше?

### Ответ: для задачи коллеги (русский, 2–20K часов, звонки) — **Документ лучше как спецификация, но Hibiki-Zero — как проверенная база**.

**Почему Документ лучше как спецификация целевой системы:**
1. **Единственный, адаптированный под русский low-resource.** Ни Moshi (диалог, не перевод), ни Hibiki (только FR→EN, 40K ч/язык), ни Hibiki-Zero (FR/IT, русский не тестировался) не решают задачу коллеги напрямую. Документ — единственный, где русский + 2–20K часов — явная цель.
2. **Синтезирует сильные стороны всех трёх:** Mimi+Inner Monologue (Moshi) + multistream (Hibiki) + GRPO без alignment (Hibiki-Zero). Ни одна статья отдельно не содержит всю эту комбинацию.
3. **Учитывает ВСЕ комментарии коллеги:** causal (Moshi/Hibiki), не каскад, аудио-контекст (multistream), RL-тайминг без alignment (Hibiki-Zero), data efficiency (<1000ч обоснование).
4. **Добавляет практические элементы:** CosyVoice 2 для TTS, Whisper для данных, Align2Speak для голоса, этап оценки с метриками.

**Почему Hibiki-Zero лучше как проверенная отправная точка:**
1. **Экспериментально верифицирована:** SOTA на 5 задачах X→EN, +3pts ASR-BLEU над Hibiki, +30pts speaker sim над Seamless. Документ — спецификация без экспериментов.
2. **Готовые веса и код** (HuggingFace + GitHub). Документ требует обучения с нуля поверх чужих backbone.
3. **RL-метод (GRPO) отлажен** на реальных данных: n_w=8, λ=0.5, clip — конкретные работающие значения. Документ переносит их, но не проверял на русском.

### Рекомендация

**Оптимальная стратегия — гибрид:**
1. Взять **Hibiki-Zero как базу** (готовые веса, код, проверенный GRPO) — это снижает риск и даёт проверенную отправную точку.
2. Применить **план адаптации из Документа** (этапы 0–4: Mimi-токенизация русского, Whisper-транскрипция, CosyVoice 2 TTS, light fine-tuning на 2K–20K ч, GRPO на русских данных).
3. Использовать **параметры из Документа** (window 3000, 28 layers) — они из Hibiki-Zero и подходят для длинных разговоров.
4. Дополнить элементами, которых нет в статьях: **Align2Speak** (качество голоса), **этап 6 метрик** (LAAL/TTFB/speaker sim для прототипа).

**Итоговая оценка:**

| | Документ | Hibiki-Zero |
|---|---|---|
| Адаптация под задачу | ✅ лучшая | ⚠️ нужна доработка |
| Проверенность | ❌ спецификация | ✅ SOTA |
| Риск | выше (неверифицирован) | ниже (готовые веса) |
| Готовность к применению | нужна реализация | почти готов (fine-tune на RU) |

**Вывод:** Документ — лучшее **описание целевой архитектуры** для задачи коллеги (адаптировано под русский, low-resource, учитывает все комментарии). Hibiki-Zero — лучшая **проверенная реализация** для старта (готовые веса, отлаженный GRPO). **Правильный путь — начать с Hibiki-Zero как базы и следовать плану адаптации из Документа.**

---

## 6. Риски и ограничения Документа (выявленные из анализа статей)

| Риск | Основание (из статей) | Митигация |
|---|---|---|
| **RL (GRPO) нестабилен на русском** | Hibiki-Zero: BLEU на RL «much noisier», LAAL в начале ~6 сек | Начать с AlignAtt (attention-эвристика) как warm-start, затем GRPO; или fallback на Hibiki-style perplexity-alignment если RL не сойдётся |
| **Helium-1 не идеален для русского** | Helium обучен на английских текстах (2.1T токенов, англо-доминантных) | Дообучение Helium на русских текстах перед audio-фазой; или init из мультиязычного LLM |
| **Mimi codec не тестировался на русском** | Moshi/Mimi: оценка на английском; русский в статьях не упоминается | Проверить качество Mimi-реконструкции на русском аудио перед обучением |
| **Sentence-aligned пары для русского** | Hibiki-Zero: использует Europarl-ST/CVSS; для русского таких готовых нет | Генерация пар через ASR (Whisper) + текстовый MT (NLLB/MADLAD-3B), как описано в Документе |
| **Full-duplex не реализован** | Moshi: full-duplex (перебивания, overlapping) — ключевая фича для звонков | Добавить speaker-turn awareness (arXiv:2311.00697) или full-duplex из Moshi в будущей итерации |
| **Документ не проверен экспериментально** | Все три статьи имеют экспериментальные результаты; Документ — нет | Прогнать pipeline на toy-данных (как в s2st_implementation/) перед масштабированием |

---

## 7. Итог

Документ `optimal_neural_codec_s2st_architecture.md` — это **корректный синтез** Moshi + Hibiki + Hibiki-Zero, адаптированный под задачу коллеги (русский, 2–20K часов, звонки). Параметры в нём точно соответствуют источникам (особенно Hibiki-Zero для Temporal/Depth/GRPO). Он лучше любой отдельной статьи **как спецификация целевой системы**, но уступает Hibiki-Zero **в проверенности** (нет экспериментов, нет готовых весов).

**Финальный ответ на «что лучше»:**
- Для **понимания, что строить** → Документ (адаптация под русского + все комментарии учтены).
- Для **быстрого старта реализации** → Hibiki-Zero (готовые веса, проверенный GRPO, SOTA).
- **Оптимально: Hibiki-Zero как база + план адаптации из Документа.**
