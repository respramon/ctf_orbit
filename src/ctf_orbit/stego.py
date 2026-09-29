"""Image metadata, pixel bit planes, and PCM WAV sample LSB."""

from __future__ import annotations

import io
import warnings
import wave

from .common import OrbitError, bounded, find_flags, preview, write_new

MAX_PIXELS = 8_000_000


def load_image(data: bytes):
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:
        raise OrbitError('Pasang modul image: python -m pip install ".[image]"') from exc
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(data))
            if image.width * image.height > MAX_PIXELS:
                image.close()
                raise OrbitError(f"Batas gambar {MAX_PIXELS} piksel")
            image.load()
            return image
    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        SyntaxError,
    ) as exc:
        raise OrbitError(f"Gambar tidak dapat dibaca: {exc}") from exc


def image_info(data: bytes) -> dict:
    with load_image(data) as image:
        metadata = {
            str(k): str(v)[:4096] for k, v in image.info.items() if not isinstance(v, bytes)
        }
        exif = {str(k): str(v)[:1024] for k, v in image.getexif().items()}
        return {
            "format": image.format,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "frames": getattr(image, "n_frames", 1),
            "metadata": metadata,
            "exif_tag_ids": exif,
            "flags": find_flags(str(metadata) + str(exif)),
            "note": "LSB piksel cocok untuk PNG/BMP lossless; JPEG memerlukan teknik domain frekuensi",
        }


def _bits_to_bytes(bits, limit: int, skip: int = 0, bit_order: str = "msb") -> bytes:
    result, accumulator, count = bytearray(), 0, 0
    for index, bit in enumerate(bits):
        if index < skip:
            continue
        if bit_order == "msb":
            accumulator = (accumulator << 1) | bit
        else:
            accumulator |= bit << count
        count += 1
        if count == 8:
            result.append(accumulator)
            accumulator, count = 0, 0
            if len(result) >= limit:
                break
    return bytes(result)


def image_lsb(
    data: bytes,
    channels: str = "rgb",
    plane: int = 0,
    bit_order: str = "msb",
    skip_bits: int = 0,
    limit: int = 131072,
) -> bytes:
    bounded(plane, 0, 7, "Bit plane")
    bounded(limit, 1, 1048576, "Limit bytes")
    bounded(skip_bits, 0, MAX_PIXELS * 4, "Skip bits")
    if (
        not channels
        or any(c not in "rgba" for c in channels)
        or len(set(channels)) != len(channels)
    ):
        raise OrbitError("Channels berupa urutan unik r/g/b/a, contoh rgb atau bgr")
    with load_image(data) as image:
        if "a" in channels and "A" not in image.getbands() and "transparency" not in image.info:
            raise OrbitError("Gambar tidak mempunyai kanal alpha")
        with image.convert("RGBA") as normalized:
            indices = ["rgba".index(c) for c in channels]
            raw_pixels = normalized.tobytes()
            bits = (
                (raw_pixels[pos + index] >> plane) & 1
                for pos in range(0, len(raw_pixels), 4)
                for index in indices
            )
            return _bits_to_bytes(bits, limit, skip_bits, bit_order)


def bit_planes(data: bytes, directory: str, channel: str = "r") -> dict:
    from pathlib import Path

    if channel not in "rgba" or len(channel) != 1:
        raise OrbitError("Channel plane harus r/g/b/a")
    paths = [Path(directory) / f"{channel}-bit-{bit}.png" for bit in range(8)]
    if any(p.exists() or p.is_symlink() for p in paths):
        raise OrbitError("File bit plane sudah ada; gunakan direktori baru")
    saved = []
    with load_image(data) as image:
        if channel == "a" and "A" not in image.getbands() and "transparency" not in image.info:
            raise OrbitError("Gambar tidak mempunyai kanal alpha")
        with image.convert("RGBA") as normalized, normalized.getchannel(channel.upper()) as gray:
            for bit, path in enumerate(paths):
                with gray.point(lambda value, bit=bit: 255 if value & (1 << bit) else 0) as plane:
                    stream = io.BytesIO()
                    plane.save(stream, format="PNG")
                    saved.append(write_new(path, stream.getvalue()))
    return {"saved": saved, "channel": channel, "note": "8 visualisasi bit plane grayscale"}


def wav_info(data: bytes) -> dict:
    try:
        with wave.open(io.BytesIO(data), "rb") as sound:
            params = {
                "channels": sound.getnchannels(),
                "sample_width": sound.getsampwidth(),
                "sample_rate": sound.getframerate(),
                "frames": sound.getnframes(),
                "compression": sound.getcomptype(),
            }
    except (wave.Error, EOFError) as exc:
        raise OrbitError(f"WAV tidak didukung: {exc}") from exc
    params["duration_seconds"] = round(params["frames"] / params["sample_rate"], 4)
    return params


def wav_lsb(
    data: bytes,
    channel: int | None = None,
    plane: int = 0,
    bit_order: str = "msb",
    limit: int = 131072,
) -> bytes:
    bounded(plane, 0, 7, "Bit plane")
    bounded(limit, 1, 1048576, "Limit bytes")
    try:
        with wave.open(io.BytesIO(data), "rb") as sound:
            width, channels = sound.getsampwidth(), sound.getnchannels()
            if sound.getcomptype() != "NONE" or width not in (1, 2, 3, 4):
                raise OrbitError("Hanya WAV PCM integer 8/16/24/32-bit")
            if channel is not None and not 0 <= channel < channels:
                raise OrbitError("Channel WAV di luar rentang (indeks mulai 0)")
            selected = range(channels) if channel is None else [channel]
            frame_count = min(sound.getnframes(), limit * 8)
            raw = sound.readframes(frame_count)
            bits = (
                (raw[pos + c * width] >> plane) & 1
                for pos in range(0, len(raw) - channels * width + 1, channels * width)
                for c in selected
            )
            return _bits_to_bytes(bits, limit, bit_order=bit_order)
    except (wave.Error, EOFError) as exc:
        raise OrbitError(f"WAV tidak dapat dibaca: {exc}") from exc


def extraction_result(raw: bytes, save: str | None = None) -> dict:
    result = {"flags": find_flags(raw), **preview(raw)}
    if save:
        result["saved"] = write_new(save, raw)
    return result
