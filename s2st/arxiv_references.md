# Релевантные исследования с arXiv для задачи streaming real-time S2ST в звонках

## Постановка конечной задачи (по комментариям коллеги)

Требуется система голосового перевода **в режиме живого телефонного звонка** со следующими жёсткими ограничениями:

- **Нативный стриминг / низкая задержка.** Аудио приходит потоком; модель должна выдавать перевод по мере поступления речи, а не обрабатывать целый фрагмент. Целевая end-to-end задержка — порядка сотен миллисекунд.
- **Data efficiency.** Сейчас есть ~2 000 часов качественных параллельных данных на русском, цель прототипа — ~20 000 часов. Десятки/сотни тысяч часов audio↔audio пар недоступны.
- **Аудио-контекст для решения «когда переводить».** Модель, принимающая решения о тайминге перевода, должна опираться на акустические признаки (просодия, паузы, интонация), а не на «остывший» текст ASR.
- **Единая, а не строго последовательная схема.** Жёсткий текстовый каскад ASR→MT→TTS даёт слишком большой «стартовый офсет» и теряет аудио-контекст.
- **Архитектура на нейрокодеке + RQ-трансформере** (Temporal + Depth), как описано в финальной итерации (`optimal_s2st_architecture.md`, v4), с RL-оптимизацией тайминга.

Все приведённые ниже arXiv-ID **проверены через официальный arXiv API** (статус OK, реальное название/дата). В таблице указано, какой аспект задачи закрывает каждая работа.

---

## Категория 1. Ядро целевой архитектуры (нейрокодек + RQ-трансформер + full-duplex)

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 1 | Moshi: a speech-text foundation model for real-time dialogue | [2410.00037](https://arxiv.org/abs/2410.00037) | Базовая архитектура целевого решения: full-duplex spoken dialogue через моделирование речи как токенов RVQ-кодека в параллельных потоках (свой + собеседник). Здесь же описаны **нейрокодек Mimi** (causal, streaming, семантическая дистилляция в первый уровень RVQ) и **Inner Monologue** (time-aligned текстовые токены как префикс к аудио-токенам для роста лингвистического качества). Теоретическая задержка 160 мс, ~200 мс на практике. |
| 2 | Simultaneous Speech-to-Speech Translation Without Aligned Data (Hibiki-Zero) | [2602.11072](https://arxiv.org/abs/2602.11072) | Прямой предшественник задачи: использует backbone Moshi/Mimi для симультанного S2ST. Ключевое — **отказ от word-level aligned данных**: обучение на sentence-level парах → затем **GRPO** для оптимизации задержки при сохранении качества. Показана адаптация к новому входному языку на **<1000 ч** данных. SOTA по точности/задержке/voice transfer на 5 задачах X→English. Релиз весов и кода. |
| 3 | High Fidelity Neural Audio Compression (EnCodec) | [2210.13438](https://arxiv.org/abs/2210.13438) | Streaming encoder-decoder + RVQ; adversarial+reconstruction loss; loss-balancer. Референс дизайна RVQ-кодека, поверх которого построены Mimi/SoundStream. Код и веса открыты. |
| 4 | SoundStream: An End-to-End Neural Audio Codec | [2107.03312](https://arxiv.org/abs/2107.03312) | Полностью свёрточный энкодер-декодер + RVQ, обучаемый end-to-end; поддержка streamable inference в real time; structured dropout по уровням квантования → переменный bitrate одной моделью. Основа для causality/streaming-дизайна кодека. |
| 5 | DeepSeekMath: Pushing the Limits of Mathematical Reasoning in Open Language Models | [2402.03300](https://arxiv.org/abs/2402.03300) | Источник алгоритма **GRPO (Group Relative Policy Optimization)** — варианта PPO с group-relative бейзлайном, снижающего нагрузку на память. Именно этот RL-метод Hibiki-Zero использует для оптимизации задержки перевода без aligned данных. |

## Категория 2. Streaming / simultaneous перевод и политика read-write

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 6 | Seamless: Multilingual Expressive and Streaming Speech Translation (SeamlessStreaming) | [2312.05187](https://arxiv.org/abs/2312.05187) | Референс «один speech-энкодер + multitask ASR/S2TT/S2ST головы без промежуточной сериализации в текст»; реализация EMMA-политики для streaming. |
| 7 | Efficient Monotonic Multihead Attention (EMMA) | [2312.04515](https://arxiv.org/abs/2312.04515) | Обучаемая монотонная attention-политика read/write поверх аудио-энкодера без фиксированного wait-k — низкая задержка без ожидания полного аудио. |
| 8 | AlignAtt: Using Attention-based Audio-Translation Alignments as a Guide for Simultaneous ST | [2305.11408](https://arxiv.org/abs/2305.11408) | Read/write-политика прямо из cross-attention между аудио-энкодером и декодером перевода — решение проблемы «нет аудио-контекста». |
| 9 | SimulSeamless: FBK at IWSLT 2024 Simultaneous Speech Translation | [2406.14177](https://arxiv.org/abs/2406.14177) | AlignAtt можно «навесить» на готовую offline-модель без переобучения под стриминг — снижает требования к данным. |
| 10 | StreamSpeech: Simultaneous Speech-to-Speech Translation with Multi-task Learning | [2406.03049](https://arxiv.org/abs/2406.03049) | Общий каузальный энкодер с несколькими головами (ASR CTC + перевод), обучаемыми совместно; политика на выравниваниях, а не на фиксированном wait-k. |
| 11 | Direct Simultaneous Translation Activation for Large Audio-Language Models (SimulSA) | [2509.15692](https://arxiv.org/abs/2509.15692) | Активация симультанного режима на ~1% от offline SFT-данных через self-augmentation (случайная обрезка аудио) — обоснование data-efficiency для audio-grounded политики. |
| 12 | StreamUni: Achieving Streaming Speech Translation with a Unified Large Speech-Language Model | [2507.07803](https://arxiv.org/abs/2507.07803) | Streaming ST через единый Large Speech-Language Model + speech Chain-of-Thought: сегментация, решение о политике и генерация перевода в одном проходе без policy-specific обучения. |
| 13 | Hierarchical Policy Optimization for Simultaneous Translation of Unbounded Speech (InfiniSST) | [2604.21045](https://arxiv.org/abs/2604.21045) | LLM-декодер перевода с переиспользованием KV-cache по чанкам аудио; победитель low-latency трека IWSLT 2025. |
| 14 | Efficient and Adaptive Simultaneous Speech Translation with Fully Unidirectional Architecture (wav2vec-S) | [2504.11809](https://arxiv.org/abs/2504.11809) | Замена bidirectional self-attention на block-wise (causal) + абсолютные позиционные эмбеддинги → энкодер стримится natively с KV-cache между чанками. |
| 15 | SASST: Leveraging Syntax-Aware Chunking and LLMs for Simultaneous Speech Translation | [2508.07781](https://arxiv.org/abs/2508.07781) | Синтаксически осознанное разбиение речи на чанки для reordering без ожидания полного предложения. |
| 16 | End-to-End Single-Channel Speaker-Turn Aware Conversational Speech Translation | [2311.00697](https://arxiv.org/abs/2311.00697) | Multi-speaker conversational ST через multi-task (ASR+ST+speaker-turn) с special tokens — релевантно для телефонных звонков с turn-taking/перебиванием. |

## Категория 3. Задержка, оценка и выравнивание

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 17 | Overcoming Latency Bottlenecks in On-Device Speech Translation: A Cascaded Approach with Alignment-Based Streaming MT | [2508.13358](https://arxiv.org/abs/2508.13358) | Количественно показывает «стартовый офсет» текстового каскада ASR→MT — обоснование отказа от строгого текстового каскада. |
| 18 | DTW-Align: Bridging the Modality Gap in End-to-End Speech Translation with Dynamic Time Warping Alignment | [2509.18987](https://arxiv.org/abs/2509.18987) | Монотонное выравнивание речь↔текст во время обучения без внешнего forced-alignment — упрощает alignment для низкоресурсных языков. |
| 19 | NaturalFlow: Reducing Disruptive Pauses for Natural Speech Flow in Simultaneous Speech-to-Speech Translation | [2606.13121](https://arxiv.org/abs/2606.13121) | Жёсткие chunkwise read/write политики создают неестественные паузы; обосновывает адаптивную политику записи и сглаживание акустического потока. |
| 20 | End-to-End Evaluation for Low-Latency Simultaneous Speech Translation | [2308.03415](https://arxiv.org/abs/2308.03415) | Методология оценки задержки/качества simultaneous ST — для метрик прототипа. |
| 21 | Incremental Blockwise Beam Search for Simultaneous Speech Translation with Controllable Quality | [2309.11379](https://arxiv.org/abs/2309.11379) | Управление качеством/задержкой через blockwise beam search при streaming. |

## Категория 4. Нейрокодеки, discrete units и direct S2ST

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 22 | Direct speech-to-speech translation with discrete units (S2UT) | [2107.05604](https://arxiv.org/abs/2107.05604) | Ключевая идея — перевод в дискретные HuBERT-юниты вместо спектрограмм; кросс-энтропия вместо MSE, короче целевые последовательности. |
| 23 | UnitY: Two-pass Direct Speech-to-speech Translation with Discrete Units | [2212.08055](https://arxiv.org/abs/2212.08055) | Двухпроходная схема (текстовый декодер → T2U) — исторический предшественник hierarchical semantic→acoustic генерации Moshi. |
| 24 | SeamlessM4T: Massively Multilingual & Multimodal Machine Translation | [2308.11596](https://arxiv.org/abs/2308.11596) | Единая модель (Conformer-энкодер + Unity-декодер) на ~100 языков; источник конфигурации модулей и токенизации юнитов. |
| 25 | SpeechMatrix: A Large-Scale Mined Corpus of Multilingual Speech-to-Speech Translations | [2211.04508](https://arxiv.org/abs/2211.04508) | Методология майнинга параллельных речевых пар — референс построения обучающего датасета. |
| 26 | DiffS2UT: A Semantic Preserving Diffusion Model for Textless Direct S2ST | [2310.17570](https://arxiv.org/abs/2310.17570) | Диффузионная генерация дискретных юнитов — альтернатива авторегрессионному depth-декодеру. |
| 27 | AV-TranSpeech: Audio-Visual Robust Speech-to-Speech Translation | [2305.15403](https://arxiv.org/abs/2305.15403) | Обзор эволюции direct S2ST (Translatotron→Translatotron 2→UWSpeech→S2UT); точка расширения на аудио-визуальную устойчивость. |
| 28 | Dub-S2ST: Textless Speech-to-Speech Translation for Seamless Dubbing | [2505.20899](https://arxiv.org/abs/2505.20899) | Non-autoregressive дискретно-диффузионный декодер юнитов + speed-адаптация длительности — основа duration predictor. |
| 29 | Direct Speech to Speech Translation: A Review | [2503.04799](https://arxiv.org/abs/2503.04799) | Сравнение каскадных и прямых архитектур: прямые лучше сохраняют голос/просодию и снижают задержку ценой чувствительности к нехватке данных. |
| 30 | SLM-S2ST: A multimodal language model for direct speech-to-speech translation | [2506.04392](https://arxiv.org/abs/2506.04392) | Speech-aware LLM поверх мультимодальной модели (Phi4-MM); data/size scaling достигает SOTA direct S2ST. |
| 31 | SimulTron: On-Device Simultaneous Speech to Speech Translation | [2406.02133](https://arxiv.org/abs/2406.02133) | Идеи снижения задержки для потокового on-device S2ST. |
| 32 | Phonology-Guided Speech-to-Speech Translation for African Languages | [2410.23323](https://arxiv.org/abs/2410.23323) | Свод трендов (NAR/диффузия, pretraining, augmentation, multitask) — методология мультизадачного обучения. |
| 33 | Direct speech-to-speech translation with a sequence-to-sequence model (Translatotron) | [1904.06037](https://arxiv.org/abs/1904.06037) | Первая прямая (без текста на инференсе) S2ST-модель — базовая идея end-to-end перевода речь→речь. |
| 34 | HiFi-Codec: Group-residual Vector quantization for High Fidelity Audio Codec | [2305.02765](https://arxiv.org/abs/2305.02765) | Group-RVQ для высокого качества при меньшем числе кодбуков — альтернатива/улучшение RVQ. |
| 35 | Language-Codec: Bridging Discrete Codec Representations and Speech Language Models | [2402.12208](https://arxiv.org/abs/2402.12208) | Мост между codec-токенами и speech LLM — релевантно для обучения RQ-трансформера поверх кодека. |

## Категория 5. SSL-бэкбоны (для semantic дистилляции / инициализации)

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 36 | WavLM: Large-Scale Self-Supervised Pre-Training for Full Stack Speech Processing | [2110.13900](https://arxiv.org/abs/2110.13900) | SSL-представления, в которые Mimi дистиллирует первый (семантический) уровень RVQ — источник semantic структуры кодека. |
| 37 | HuBERT: Self-Supervised Speech Representation Learning by Masked Prediction of Hidden Units | [2106.07447](https://arxiv.org/abs/2106.07447) | Источник дискретных речевых юнитов (k-means поверх HuBERT) и SSL-инициализации. |
| 38 | wav2vec 2.0: A Framework for Self-Supervised Learning of Speech Representations | [2006.11477](https://arxiv.org/abs/2006.11477) | Базовый SSL-фреймворк для speech-энкодеров; основа wav2vec-S (causal). |

## Категория 6. Streaming TTS (генерация выходной речи с малой задержкой)

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 39 | VoXtream: Full-Stream Text-to-Speech with Extremely Low Latency | [2509.15969](https://arxiv.org/abs/2509.15969) | Полностью потоковый TTS: phoneme→temporal→depth-transformer; TTFB ~102 мс — альтернативный depth-декодер кодека. |
| 40 | Streaming T5-based Text-to-Speech Synthesis with Limited Lookahead (S5-TTS) | [2606.21882](https://arxiv.org/abs/2606.21882) | Word-by-word синтез с монотонным alignment learning — начинает синтез после первых слов. |
| 41 | From Start to Finish: Latency Reduction Strategies for Incremental Speech Synthesis in Simultaneous S2ST | [2110.08214](https://arxiv.org/abs/2110.08214) | TTS использует прямой доступ к входной речи для pseudo-lookahead — сокращает собственный стартовый лаг TTS. |
| 42 | Align2Speak: Improving TTS for Low Resource Languages via ASR-Guided Online Preference Optimization | [2509.21718](https://arxiv.org/abs/2509.21718) | Дообучение мультиязычного TTS под целевой голос/язык на нескольких часах поверх языко-агностичного фундамента. |
| 43 | CosyVoice: A Scalable Multilingual Zero-shot Text-to-speech Synthesizer based on Supervised Semantic Acoustic Tokens | [2407.05407](https://arxiv.org/abs/2407.05407) | Progressive semantic decoding (LM + Flow Matching) для in-context voice cloning — кандидат на синтез target-аудио при подготовке данных. |
| 44 | CosyVoice 2: Scalable Streaming Speech Synthesis with Large Language Models | [2412.10117](https://arxiv.org/abs/2412.10117) | Streaming-версия: finite-scalar quantization, chunk-aware causal flow matching, прямое использование pretrained LLM как backbone — референс streaming TTS поверх кодека. |
| 45 | Neural Codec Language Models are Zero-Shot Text to Speech Synthesizers (VALL-E) | [2301.02111](https://arxiv.org/abs/2301.02111) | TTS как нейрокодек-LM: zero-shot voice cloning из 3-секундного энролла — подход для сохранения голоса говорящего. |

## Категория 7. Data efficiency / low-resource перенос

| № | Название статьи | arXiv ID | Краткий комментарий |
|---|-----------------|----------|---------------------|
| 46 | Pre-training on high-resource speech recognition improves low-resource speech-to-text translation | [1809.01431](https://arxiv.org/abs/1809.01431) | Прямое доказательство: предобучение на 300 ч EN ASR подняло BLEU ES→EN ST с 10.8 до 20.2 при 20 ч целевых данных. Обоснование, что 2–20K ч достаточно при pretrained backbone. |
| 47 | Analyzing ASR pretraining for low-resource speech-to-text translation | [1910.10762](https://arxiv.org/abs/1910.10762) | Систематический анализ влияния ASR-pretraining на low-resource ST; когда и почему перенос помогает. |
| 48 | Strategies for improving low resource speech to text translation relying on pre-trained ASR models | [2306.00208](https://arxiv.org/abs/2306.00208) | Инициализация ST из pretrained мультиязычного ASR + совместное обучение с CTC превосходит SOTA даже при 300 ч. |
| 49 | Parameter-efficient Adaptation of Multilingual Multimodal Models for Low-resource ASR | [2410.13445](https://arxiv.org/abs/2410.13445) | Адаптеры SeamlessM4T на 5 ч размеченной речи дают заметный рост WER — дообучение готового backbone требует на порядки меньше данных. |
| 50 | VietASR: Achieving Industry-level Vietnamese ASR with 50-hour labeled data and Large-Scale Unsupervised Pre-training | [2505.21527](https://arxiv.org/abs/2505.21527) | Предобучение на 70 000 ч неразмеченных + дообучение на 50 ч превосходит Whisper Large-v3 — доказательство, что SSL+малое дообучение масштабируется лучше end-to-end на размеченных парах. |

---

**Итого: 50 верифицированных статей.** Категории 1–2 (нейрокодек/RQ-трансформер + streaming-политика) образуют ядро целевой архитектуры; категории 3–7 дают обоснования по задержке, кодекам, SSL-бэкбонам, streaming-TTS и data-efficiency.
