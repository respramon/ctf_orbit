"""Bounded APK, Android binary-XML string pool and DEX string analysis."""

from __future__ import annotations

import re
import struct

from .artifacts import open_zip, safe_zip_sample
from .common import OrbitError, find_flags


def _length8(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise OrbitError("String pool UTF-8 terpotong")
    value = data[pos]
    if value & 0x80:
        if pos + 1 >= len(data):
            raise OrbitError("String pool length terpotong")
        return ((value & 0x7F) << 8) | data[pos + 1], pos + 2
    return value, pos + 1


def axml_strings(data: bytes) -> list[str]:
    if data.lstrip().startswith(b"<"):
        return [data[:262144].decode("utf-8", "replace")]
    if len(data) < 8:
        raise OrbitError("Manifest terlalu pendek")
    kind, header_size, total = struct.unpack_from("<HHI", data)
    if kind != 3 or header_size < 8 or not header_size <= total <= len(data):
        raise OrbitError("Header Android binary XML tidak valid")
    pos, result = header_size, []
    for _ in range(5000):
        if pos + 8 > total:
            break
        kind, header, size = struct.unpack_from("<HHI", data, pos)
        if header < 8 or size < header or pos + size > total:
            raise OrbitError("Chunk Android XML tidak valid")
        if kind == 1:
            if header < 28:
                raise OrbitError("String pool header tidak valid")
            chunk = data[pos : pos + size]
            count, _, flags, start, _ = struct.unpack_from("<5I", chunk, 8)
            if count > 10000 or not header + count * 4 <= start <= len(chunk):
                raise OrbitError("String pool count/offset tidak valid")
            for index in range(min(count, 5000)):
                off = struct.unpack_from("<I", chunk, header + index * 4)[0] + start
                if off >= len(chunk):
                    raise OrbitError("String pool entry keluar dari chunk")
                if flags & 0x100:
                    _, off = _length8(chunk, off)
                    length, off = _length8(chunk, off)
                    if off + length >= len(chunk) or chunk[off + length] != 0:
                        raise OrbitError("String pool UTF-8 tidak valid")
                    result.append(chunk[off : off + min(length, 4096)].decode("utf-8", "replace"))
                else:
                    if off + 2 > len(chunk):
                        raise OrbitError("String pool UTF-16 length terpotong")
                    length = struct.unpack_from("<H", chunk, off)[0]
                    off += 2
                    if length & 0x8000:
                        if off + 2 > len(chunk):
                            raise OrbitError("String pool UTF-16 length terpotong")
                        length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", chunk, off)[0]
                        off += 2
                    if off + length * 2 + 2 > len(chunk):
                        raise OrbitError("String pool UTF-16 entry terpotong")
                    result.append(
                        chunk[off : off + min(length * 2, 8192)].decode("utf-16-le", "replace")
                    )
        pos += size
    return result


def dex_strings(data: bytes, maximum: int = 5000) -> list[str]:
    if len(data) < 112 or not data.startswith(b"dex\n") or data[7] != 0:
        raise OrbitError("Header DEX tidak valid (compact DEX belum didukung)")
    if data[4:7] not in (b"035", b"037", b"038", b"039", b"040"):
        raise OrbitError(
            "DEX hanya mendukung versi 035/037/038/039/040; container 041 belum didukung"
        )
    endian_tag = data[40:44]
    if endian_tag == b"\x78\x56\x34\x12":
        endian = "<"
    elif endian_tag == b"\x12\x34\x56\x78":
        endian = ">"
    else:
        raise OrbitError("Endian tag DEX tidak valid")
    file_size, header = struct.unpack_from(endian + "II", data, 32)
    count, table = struct.unpack_from(endian + "II", data, 56)
    if file_size > len(data) or header < 112 or file_size < header or table + count * 4 > file_size:
        raise OrbitError("DEX size/string table tidak valid")
    if count and table < header:
        raise OrbitError("DEX string IDs overlap dengan header")
    result = []
    for index in range(min(count, maximum)):
        off = struct.unpack_from(endian + "I", data, table + index * 4)[0]
        if off < header:
            raise OrbitError("DEX string data overlap dengan header")
        for _ in range(5):
            if off >= file_size:
                raise OrbitError("DEX string ULEB128 terpotong")
            value, off = data[off], off + 1
            if not value & 0x80:
                break
        else:
            raise OrbitError("DEX ULEB128 terlalu panjang")
        end = data.find(b"\x00", off, min(file_size, off + 8192))
        if end < 0:
            continue
        # MUTF-8 NUL normalization; surrogate pairs remain replacement characters.
        result.append(data[off:end].replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace"))
    return result


def inspect(data: bytes) -> dict:
    strings_found, errors, dex_files, entries = [], [], [], []
    with open_zip(data) as archive:
        for info in archive.infolist():
            entries.append(info.filename)
            if info.filename == "AndroidManifest.xml" or re.fullmatch(
                r"classes\d*\.dex", info.filename
            ):
                if len(dex_files) >= 10 and info.filename.endswith(".dex"):
                    errors.append("Batas analisis 10 file DEX tercapai")
                    continue
                try:
                    raw = safe_zip_sample(archive, info, 8 * 1024 * 1024)
                    if info.filename.endswith(".dex"):
                        values = dex_strings(raw)
                        dex_files.append({"name": info.filename, "strings_sampled": len(values)})
                    else:
                        values = axml_strings(raw)
                    strings_found.extend(values)
                except OrbitError as exc:
                    errors.append(f"{info.filename}: {exc}")
    joined = "\n".join(strings_found)
    return {
        "entries": entries,
        "dex_files": dex_files,
        "native_libraries": [n for n in entries if n.startswith("lib/") and n.endswith(".so")],
        "certificate_files": [
            n
            for n in entries
            if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
        ],
        "permissions": sorted(set(re.findall(r"android\.permission\.[A-Z_]+", joined))),
        "urls": sorted(set(re.findall(r"https?://[^\s<>\"']{1,2048}", joined)))[:500],
        "interesting_strings": [
            s[:2048]
            for s in strings_found
            if re.search(r"(?i)flag|secret|token|api[_-]?key|https?://|debuggable|exported", s)
        ][:500],
        "flags": find_flags(joined),
        "errors": errors,
        "note": "Analisis statis; string pool bukan rekonstruksi manifest lengkap, sertifikat belum diverifikasi, APK tidak diinstal",
    }
