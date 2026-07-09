"""
Этап 5: Streaming-инференс — голосовой перевод в реальном времени.

Цель: реализовать потоковый инференс модели в режиме живого телефонного звонка.
Аудио приходит потоком (чанками), перевод выдаётся инкрементально с минимальной задержкой.

Архитектура streaming-инференса:
  1. Входящее аудио (24kHz) накапливается в буфере StreamingMimiEncoder.
  2. При готовности нового фрейма (каждые 80 мс = 1920 сэмплов) source-токены
     добавляются в контекст.
  3. Temporal Transformer обрабатывает новый time-step с переиспользованием KV-cache
     (не пересчитывает всю историю).
  4. Depth Transformer генерирует target-токены для нового time-step.
  5. Target-токены декодируются Mimi-декодером в аудио (80 мс на фрейм).
  6. Исходящее аудио отправляется в поток.

Latency: теоретически 160 мс (Moshi), ~200 мс на практике (Hibiki-Zero).
- 1 фрейм входного аудио (80 мс) -> source-токены
- Temporal + Depth на 1 шаг (KV-cache) -> ~десятки мс
- Mimi decode 1 фрейм -> 80 мс аудио

Источники: arXiv:2410.00037 (Moshi, 160ms theoretical), arXiv:2602.11072 (Hibiki-Zero).
"""

import time
import torch
import torch.nn as nn


# =============================================================================
# 5.1. Конфигурация streaming-инференса
# =============================================================================
INFERENCE_CONFIG = {
    "sample_rate": 24000,
    "frame_stride": 1920,          # 80 мс при 24 kHz
    "frame_rate": 12.5,
    "max_latency_ms": 500,         # целевая end-to-end latency
    "kv_cache_enabled": True,
    "num_codebooks": 8,
    "acoustic_delay": 2,
}


# =============================================================================
# 5.2. Streaming-оркестратор
# =============================================================================
class StreamingS2STInference:
    """
    Потоковый инференс S2ST: входящее аудио -> переведённое аудио в реальном времени.

    Компоненты:
      - codec: Mimi (frozen) — streaming encode/decode.
      - model: NeuralCodecS2ST (Temporal + Depth + multistream).
      - KV-cache: переиспользование между time-step'ами (causal).

    Жизненный цикл на каждый входной фрейм:
      1. Mimi encode -> source_tokens (Q токенов).
      2. Добавить source-токены в multistream-последовательность.
      3. Temporal.step() с KV-cache -> Z_t.
      4. Depth.step(Z_t) -> target_tokens (Q токенов).
      5. Mimi decode(target_tokens) -> 80 мс аудио.
    """

    def __init__(self, model: nn.Module, codec: nn.Module, cfg: dict = INFERENCE_CONFIG):
        self.model = model
        self.codec = codec
        self.cfg = cfg
        self.Q = cfg["num_codebooks"]

        # Состояние streaming
        self.audio_buffer = torch.zeros(1, 1, 0)  # буфер входящих сэмплов
        self.temporal_caches = None               # KV-cache Temporal по блокам
        self.generated_target = []                # накопленные target-токены
        self.source_history = []                  # накопленные source-токены

    def reset(self):
        """Сброс состояния (новый звонок)."""
        self.audio_buffer = torch.zeros(1, 1, 0)
        self.temporal_caches = None
        self.generated_target = []
        self.source_history = []

    @torch.no_grad()
    def push_audio_chunk(self, chunk: torch.Tensor) -> torch.Tensor | None:
        """
        Принимает чанк входящего аудио, возвращает переведённое аудио (или None,
        если в буфере ещё недостаточно сэмплов для нового фрейма).

        Аргументы:
            chunk: (S,) — новые сэмплы входящего аудио (24kHz).

        Возвращает:
            output_audio: (S_out,) — переведённое аудио (80 мс на фрейм), или None.
        """
        device = next(self.model.parameters()).device
        # 1. Добавляем чанк в буфер
        chunk = chunk.to(device).reshape(1, 1, -1)
        self.audio_buffer = torch.cat([self.audio_buffer.to(device), chunk], dim=2)

        outputs = []
        # Обрабатываем все готовые фреймы
        while self.audio_buffer.shape[2] >= self.cfg["frame_stride"]:
            # Берём один фрейм
            frame_audio = self.audio_buffer[:, :, :self.cfg["frame_stride"]]
            self.audio_buffer = self.audio_buffer[:, :, self.cfg["frame_stride"]:]

            # 2. Mimi encode -> source_tokens (Q токенов)
            source_tokens = self.codec.encode(frame_audio)  # (1, Q, 1)
            source_tokens = source_tokens.squeeze(2)        # (1, Q)
            self.source_history.append(source_tokens)

            # 3-4. Генерируем target-токены через модель
            target_tokens = self._generate_one_step(source_tokens)
            self.generated_target.append(target_tokens)

            # 5. Mimi decode -> аудио
            target_tokens_full = target_tokens.unsqueeze(2)  # (1, Q, 1)
            out_audio = self.codec.decode(target_tokens_full)  # (1, 1, frame_stride)
            outputs.append(out_audio.squeeze(0).squeeze(0))

        if outputs:
            return torch.cat(outputs)
        return None

    def _generate_one_step(self, source_tokens: torch.Tensor) -> torch.Tensor:
        """
        Генерирует target-токены для одного time-step, используя KV-cache.

        Аргументы:
            source_tokens: (1, Q) — source RVQ-токены нового фрейма.
        Возвращает:
            target_tokens: (1, Q) — предсказанные target RVQ-токены.
        """
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from importlib import import_module
        mimi_mod = import_module("01a_mimi_codec")

        # Применяем acoustic delay к source
        src_delayed = mimi_mod.apply_acoustic_delay(
            source_tokens.unsqueeze(2), self.cfg["acoustic_delay"]
        ).squeeze(2)  # (1, Q)

        # Строим входную последовательность для этого шага
        # [warn] В реальной реализации: формируем multistream-последовательность
        # для нового time-step и вызываем temporal.step() с KV-cache.
        # Здесь — упрощённый вызов через translate_streaming (без полноценного cache).

        # Накопленная target-история
        if self.generated_target:
            cur_target = torch.stack(self.generated_target, dim=2)  # (1, Q, T)
        else:
            cur_target = torch.zeros(1, self.Q, 0, dtype=torch.long, device=source_tokens.device)

        # Накопленная source-история
        cur_source = torch.stack(self.source_history, dim=2)  # (1, Q, T)

        # Temporal + Depth на последний time-step
        # [warn] В проде: использовать KV-cache вместо полного forward.
        # Здесь — вызов через модель с полной историей (менее эффективно, но корректно).
        target_tokens = self.model.translate_streaming(
            cur_source[0], max_steps=1
        )  # (Q, 1)
        return target_tokens[:, -1:].T  # (1, Q)


# =============================================================================
# 5.3. Демонстрация streaming-инференса с замером latency
# =============================================================================
def demo_streaming_inference(model, codec, cfg: dict = INFERENCE_CONFIG):
    """
    Демонстрирует streaming-инференс на синтетическом аудио и замеряет latency.

    [warn] В проде: подавать реальное аудио из микрофона/потока.
    """
    device = next(model.parameters()).device
    inference = StreamingS2STInference(model, codec, cfg)

    # Симулируем входящий аудиопоток чанками по 200 мс
    chunk_ms = 200
    chunk_samples = int(cfg["sample_rate"] * chunk_ms / 1000)
    total_ms = 2000  # 2 секунды симуляции
    num_chunks = total_ms // chunk_ms

    print(f"[demo] Streaming inference: {total_ms}ms input in {chunk_ms}ms chunks")
    latencies = []
    total_output_samples = 0

    for i in range(num_chunks):
        # Симулируем чанк аудио (шум)
        chunk = torch.randn(chunk_samples) * 0.1

        t0 = time.perf_counter()
        output = inference.push_audio_chunk(chunk)
        t1 = time.perf_counter()

        latency_ms = (t1 - t0) * 1000
        out_ms = (output.shape[0] / cfg["sample_rate"] * 1000) if output is not None else 0
        latencies.append(latency_ms)
        if output is not None:
            total_output_samples += output.shape[0]
        print(f"  chunk {i}: proc={latency_ms:.1f}ms, output={out_ms:.0f}ms")

    avg_lat = sum(latencies) / len(latencies)
    rtf = sum(latencies) / (num_chunks * chunk_ms)
    print(f"\n[demo] Avg processing latency: {avg_lat:.1f}ms")
    print(f"[demo] RTF (real-time factor): {rtf:.3f} ({'OK' if rtf < 1 else 'TOO SLOW'})")
    print(f"[demo] Total output: {total_output_samples/cfg['sample_rate']:.2f}s")


# =============================================================================
# 5.4. Запуск
# =============================================================================
if __name__ == "__main__":
    print("Этап 5: Streaming-инференс")
    print(f"  Frame: {INFERENCE_CONFIG['frame_stride']} samples = 80ms @ 24kHz")
    print(f"  Target latency: {INFERENCE_CONFIG['max_latency_ms']}ms")
    print("  [warn] Подключите обученную модель и Mimi codec для demo.")
    # demo_streaming_inference(model, codec)  # раскомментировать в проде
