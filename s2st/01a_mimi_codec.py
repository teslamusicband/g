"""
Этап 1 (часть A): Mimi Neural Audio Codec — модель и работа с токенами.

Цель: определить структуру Mimi-кодека (causal, streaming) и операции над
дискретными токенами RVQ, которые понадобятся на всех последующих этапах.

Mimi — это causal нейрокодек с RVQ (Residual Vector Quantization):
  - Encoder: 24kHz waveform -> 512-dim латент @ 12.5 Hz (80 мс/фрейм)
  - RVQ: 8 codebooks x 2048 entries. Уровень 1 — семантический (дистилляция WavLM-large),
         уровни 2-8 — акустические (coarse-to-fine).
  - Decoder: латент -> 24kHz waveform. Один фрейм -> 80 мс аудио.
  - Causality: кодирует и декодирует стримом, без lookahead.

Ключевое свойство для стриминга: acoustic delay — акустические токены (q>=2)
сдвинуты на 2 фрейма относительно семантического (q=1):
    tau(A)_{t,1} = A_{t,1}                        (semantic — без задержки)
    tau(A)_{t,q} = A_{t-2,q}  для q>=2, t>=3      (acoustic — задержка 2 фрейма)

Источники: arXiv:2410.00037 (Moshi/Mimi), arXiv:2210.13438 (EnCodec),
           arXiv:2107.03312 (SoundStream), arXiv:2602.11072 (Hibiki-Zero, acoustic delay).

Примечание: в проде веса Mimi берутся готовые (Kyutai HF) — кодек НЕ обучается с нуля.
Ниже — контракт интерфейса и утилиты для работы с токенами (acoustic delay, multistream concat).
"""

import torch
import torch.nn as nn


# =============================================================================
# 1.1. Конфигурация Mimi кодека
# =============================================================================
MIMI_CONFIG = {
    "sample_rate": 24000,
    "frame_rate": 12.5,          # 12.5 фреймов/сек
    "frame_stride": int(24000 / 12.5),  # = 1920 сэмплов на фрейм
    "latent_dim": 512,
    "num_codebooks": 8,          # Q
    "codebook_size": 2048,       # N_a
    "acoustic_delay": 2,         # задержка акустических токенов (в фреймах)
    "semantic_level": 1,         # 1-й уровень RVQ — семантический
}


# =============================================================================
# 1.2. Контракт Mimi кодека (интерфейс)
# =============================================================================
class MimiCodec(nn.Module):
    """
    Causal streaming нейрокодек Mimi.

    В проде: наследуется/оборачивает реальные веса kyutai/mimi.
    Здесь зафиксирован интерфейс, от которого зависят остальные этапы.

    Методы:
        encode(waveform) -> tokens   (B, Q, T)  LongTensor
        decode(tokens)   -> waveform (B, 1, T*frame_stride) FloatTensor
        quantize(latent) -> tokens   (B, Q, T)
        dequantize(tokens) -> latent (B, latent_dim, T)
    """

    def __init__(self, cfg: dict = MIMI_CONFIG):
        super().__init__()
        self.cfg = cfg
        self.num_codebooks = cfg["num_codebooks"]
        self.codebook_size = cfg["codebook_size"]
        self.acoustic_delay = cfg["acoustic_delay"]
        # [в проде] Загрузить encoder/decoder/RVQ из kyutai/mimi:
        #   self.encoder = ...   # causal conv encoder
        #   self.decoder = ...   # causal conv decoder
        #   self.quantizer = ResidualVectorQuantizer(dim=cfg["latent_dim"],
        #                  codebook_size=cfg["codebook_size"], num_quantizers=cfg["num_codebooks"])
        raise NotImplementedError("[в проде] Загрузите реальные веса Mimi (kyutai/mimi).")

    def encode(self, waveform: torch.Tensor) -> torch.Tensor:
        """waveform (B,1,S) -> tokens (B,Q,T). Causal."""
        raise NotImplementedError

    def decode(self, tokens: torch.Tensor) -> torch.Tensor:
        """tokens (B,Q,T) -> waveform (B,1,S). Causal."""
        raise NotImplementedError


# =============================================================================
# 1.3. Acoustic delay: применение и снятие сдвига
# =============================================================================
# tau(A)_{t,1} = A_{t,1}            (semantic — без задержки)
# tau(A)_{t,q} = A_{t-2,q}  для q>=2 (acoustic — задержка 2 фрейма)
#
# На обучении: применяем tau к target-токенам, чтобы модель училась предсказывать
#   "задержанную" акустику (это даёт Depth Transformer lookahead по семантике).
# На инференсе: обратное преобразование tau^{-1} восстанавливает исходный порядок.
def apply_acoustic_delay(tokens: torch.Tensor, delay: int = MIMI_CONFIG["acoustic_delay"]) -> torch.Tensor:
    """
    Применяет acoustic delay к токенам RVQ.

    Аргументы:
        tokens: (B, Q, T) — исходные RVQ-токены.
        delay: величина сдвига акустических уровней (по умолчанию 2).

    Возвращает:
        (B, Q, T) — токены с применённым acoustic delay.
            semantic (q=0) не меняется;
            acoustic (q>=1) сдвигается на `delay` фреймов вперёд.
    """
    B, Q, T = tokens.shape
    out = tokens.clone()
    # acoustic levels: индексы 1..Q-1 (0-й — semantic)
    for q in range(1, Q):
        # tau(A)_{t,q} = A_{t-delay, q}: сдвигаем содержимое вправо на delay,
        # первые delay позиций заполняем padding (0).
        out[:, q, delay:] = tokens[:, q, :T - delay]
        out[:, q, :delay] = 0  # padding
    return out


def remove_acoustic_delay(tokens: torch.Tensor, delay: int = MIMI_CONFIG["acoustic_delay"]) -> torch.Tensor:
    """
    Обратное преобразование к apply_acoustic_delay (для инференса/декодирования).

    Аргументы:
        tokens: (B, Q, T) — токены с applied acoustic delay.
        delay: величина сдвига.

    Возвращает:
        (B, Q, T) — исходные токены (без delay).
    """
    B, Q, T = tokens.shape
    out = tokens.clone()
    for q in range(1, Q):
        # A_{t,q} = tau(A)_{t+delay, q}: сдвигаем влево
        out[:, q, :T - delay] = tokens[:, q, delay:]
        out[:, q, T - delay:] = 0
    return out


# =============================================================================
# 1.4. Multistream concat: объединение source и target по codebook-оси
# =============================================================================
# Ā = concat_q[tau(A^Y), tau(A^X)]
#   - source (X) токены: актуальные (считываются Mimi-энкодером входящего аудио)
#   - target (Y) токены: предсказываются моделью авторегрессионно
# На обучении loss считается на обоих потоках; на инференсе source подменяется
# актуальными токенами, target генерируется.
# Источник: arXiv:2602.11072 (Hibiki-Zero), arXiv:2410.00037 (Moshi).
def multistream_concat(source_tokens: torch.Tensor, target_tokens: torch.Tensor) -> torch.Tensor:
    """
    Объединяет source и target RVQ-токены по codebook-оси.

    Аргументы:
        source_tokens: (B, Q, T_x) — токены входящего аудио (актуальные).
        target_tokens: (B, Q, T_y) — токены исходящего аудио (предсказываемые).

    Возвращает:
        (B, 2*Q, T) — конкатенированные токены, где T = max(T_x, T_y),
        короткий поток дополняется padding (0) до общей длины.
        Порядок по codebook-оси: [target_q0, target_q1, ..., target_q{Q-1},
                                  source_q0, source_q1, ..., source_q{Q-1}].
    """
    B, Q, T_x = source_tokens.shape
    _, _, T_y = target_tokens.shape
    T = max(T_x, T_y)
    # pad до общей длины
    if T_x < T:
        pad = torch.zeros(B, Q, T - T_x, dtype=source_tokens.dtype, device=source_tokens.device)
        source_tokens = torch.cat([source_tokens, pad], dim=2)
    if T_y < T:
        pad = torch.zeros(B, Q, T - T_y, dtype=target_tokens.dtype, device=target_tokens.device)
        target_tokens = torch.cat([target_tokens, pad], dim=2)
    # concat по codebook-оси: target сначала, затем source
    return torch.cat([target_tokens, source_tokens], dim=1)  # (B, 2Q, T)


# =============================================================================
# 1.5. Streaming-интерфейс: инкрементальное кодирование по чанкам
# =============================================================================
# Causality Mimi позволяет кодировать аудио потоком по чанкам без пересчёта.
# На инференсе: входящее аудио накапливается в буфере, при достижении frame_stride
# сэмплов (1920 при 24kHz) выдаётся один фрейм токенов (Q токенов).
class StreamingMimiEncoder:
    """
    Потоковая обёртка над Mimi-энкодером: принимает сэмплы инкрементально,
    выдаёт фреймы токенов по мере готовности.

    [warn] В проде: использовать нативный causal streaming-режим Mimi.
    Здесь — контракт для интеграции в streaming-пайплайн (этап 6).
    """

    def __init__(self, codec: MimiCodec, cfg: dict = MIMI_CONFIG):
        self.codec = codec
        self.frame_stride = cfg["frame_stride"]  # 1920 сэмплов = 80 мс
        self.buffer = torch.zeros(1, 1, 0)
        self.num_codebooks = cfg["num_codebooks"]

    def push_samples(self, samples: torch.Tensor):
        """
        Добавляет сэмплы во внутренний буфер.

        Аргументы:
            samples: (1, 1, S) — новые сэмплы аудио (24kHz).
        """
        self.buffer = torch.cat([self.buffer, samples], dim=2)

    def pop_ready_frames(self) -> torch.Tensor | None:
        """
        Возвращает готовые фреймы токенов (Q, num_new_frames) или None,
        если в буфере недостаточно сэмплов для нового фрейма.
        """
        num_frames = self.buffer.shape[2] // self.frame_stride
        if num_frames == 0:
            return None
        ready = self.buffer[:, :, :num_frames * self.frame_stride]
        self.buffer = self.buffer[:, :, num_frames * self.frame_stride:]
        tokens = self.codec.encode(ready)  # (1, Q, num_frames)
        return tokens[0]  # (Q, num_frames)


# =============================================================================
# 1.6. Sanity-check операций над токенами
# =============================================================================
def _sanity_check():
    Q, T = MIMI_CONFIG["num_codebooks"], 20
    tokens = torch.randint(0, MIMI_CONFIG["codebook_size"], (2, Q, T))
    delayed = apply_acoustic_delay(tokens)
    restored = remove_acoustic_delay(delayed)
    # semantic level (q=0) не должен измениться
    assert torch.equal(delayed[:, 0], tokens[:, 0]), "semantic level не должен меняться"
    # обратное преобразование восстанавливает (с потерей последних delay позиций)
    assert torch.equal(restored[:, 1:, :T - MIMI_CONFIG["acoustic_delay"]],
                       tokens[:, 1:, :T - MIMI_CONFIG["acoustic_delay"]]), \
        "remove_acoustic_delay некорректен"
    # multistream concat
    src = torch.randint(0, 2048, (2, Q, 10))
    tgt = torch.randint(0, 2048, (2, Q, 15))
    merged = multistream_concat(src, tgt)
    assert merged.shape == (2, 2 * Q, 15), f"multistream concat shape: {merged.shape}"
    print("[ok] Mimi token operations sanity-check passed")


if __name__ == "__main__":
    _sanity_check()
    print("Этап 1A: Mimi codec — контракт и операции над токенами готовы.")
