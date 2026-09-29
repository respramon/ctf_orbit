"""File signatures, archive inventory, strings and precise-offset carving."""

from __future__ import annotations

import io
import math
import re
import struct
import zipfile
import zlib
from pathlib import PurePosixPath

from .common import DEFAULT_PREFIXES, OrbitError, entropy, find_flags, hashes, strings, write_new

SIGNATURES = {
    "elf": b"\x7fELF",
    "pe": b"MZ",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "zip": b"PK\x03\x04",
    "pdf": b"%PDF-",
    "gzip": b"\x1f\x8b\x08",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
    "sqlite": b"SQLite format 3\x00",
    "riff": b"RIFF",
    "squashfs-le": b"hsqs",
    "squashfs-be": b"sqsh",
    "ubi": b"UBI#",
    "jffs2-le": b"\x85\x19",
    "pcap-le": b"\xd4\xc3\xb2\xa1",
    "pcap-be": b"\xa1\xb2\xc3\xd4",
    "pcap-nano-le": b"\x4d\x3c\xb2\xa1",
    "pcap-nano-be": b"\xa1\xb2\x3c\x4d",
    "pcapng": b"\x0a\x0d\x0d\x0a",
    "dex": b"dex\n",
}


def detect_type(data: bytes) -> str:
    for name, signature in SIGNATURES.items():
        if data.startswith(signature):
            if name == "riff" and data[8:12] == b"WAVE":
                return "wav"
            return name
    if data.startswith(b"PK\x05\x06"):
        return "zip"
    if (
        data
        and sum(c in (9, 10, 13) or 32 <= c < 127 for c in data[:8192]) / len(data[:8192]) > 0.95
    ):
        return "text"
    return "unknown"


def signature_scan(data: bytes, maximum: int = 128) -> list[dict]:
    found = []
    for name, signature in SIGNATURES.items():
        start = 0
        for _ in range(16):
            offset = data.find(signature, start)
            if offset < 0:
                break
            found.append(
                {
                    "type": name,
                    "offset": offset,
                    "note": "magic-byte candidate; belum memvalidasi seluruh format",
                }
            )
            start = offset + 1
    return sorted(found, key=lambda item: item["offset"])[:maximum]


def open_zip(data: bytes) -> zipfile.ZipFile:
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise OrbitError("ZIP tidak memiliki EOCD yang valid")
    disk, cd_disk, disk_entries, entries, size = struct.unpack_from("<4HI", data, end + 4)
    if disk or cd_disk or disk_entries != entries:
        raise OrbitError("ZIP multi-volume tidak didukung")
    if entries > 5000 or size > 8 * 1024 * 1024:
        raise OrbitError(
            "ZIP terlalu banyak entri/besar; batas 5000 entri dan central directory 8 MiB"
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        if len(archive.infolist()) > 5000:
            archive.close()
            raise OrbitError("ZIP melebihi 5000 entri")
        return archive
    except zipfile.BadZipFile as exc:
        raise OrbitError(f"ZIP tidak valid: {exc}") from exc


def safe_zip_sample(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.flag_bits & 1:
        raise OrbitError("Entri ZIP terenkripsi")
    if info.file_size > 8 * 1024 * 1024 or info.file_size / max(1, info.compress_size) > 200:
        raise OrbitError("Entri ZIP melewati batas ukuran atau rasio kompresi")
    try:
        with archive.open(info) as stream:
            return stream.read(limit)
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error) as exc:
        raise OrbitError(f"Entri ZIP tidak dapat dibaca: {exc}") from exc


def archive_inventory(data: bytes, prefixes=DEFAULT_PREFIXES) -> dict:
    items, flags, budget = [], set(), 2 * 1024 * 1024
    with open_zip(data) as archive:
        for index, info in enumerate(archive.infolist()):
            normalized = info.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            item = {
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "encrypted": bool(info.flag_bits & 1),
                "unsafe_path": path.is_absolute()
                or ".." in path.parts
                or bool(re.match("^[A-Za-z]:", normalized)),
                "flags": find_flags(info.filename, prefixes),
            }
            flags.update(item["flags"])
            if not info.is_dir() and index < 50 and budget > 0:
                try:
                    sample = safe_zip_sample(archive, info, min(256 * 1024, budget))
                    budget -= len(sample)
                    item["sample_bytes"] = len(sample)
                    item["sample_truncated"] = len(sample) < info.file_size
                    item["flags"] = sorted(set(item["flags"] + find_flags(sample, prefixes)))
                    flags.update(item["flags"])
                except OrbitError as exc:
                    item["sample_skipped"] = str(exc)
            items.append(item)
        comment = archive.comment.decode("utf-8", "replace")
        flags.update(find_flags(comment, prefixes))
    return {
        "entries": items,
        "comment": comment,
        "flags": sorted(flags),
        "note": "Inventaris tanpa ekstraksi; sampel maksimal 50 entri dan total 2 MiB",
    }


def inspect(data: bytes, path: str = "", prefixes=DEFAULT_PREFIXES) -> dict:
    extracted = strings(data)
    flags = set(find_flags(data, prefixes))
    for item in extracted:
        flags.update(find_flags(item["text"], prefixes))
    block_size = max(4096, math.ceil(len(data) / 64))
    result = {
        "path": path,
        "size": len(data),
        "type": detect_type(data),
        "hashes": hashes(data),
        "entropy": entropy(data),
        "strings": extracted,
        "signatures": signature_scan(data),
        "entropy_blocks": [
            {
                "offset": pos,
                "size": len(data[pos : pos + block_size]),
                "entropy": entropy(data[pos : pos + block_size]),
            }
            for pos in range(0, len(data), block_size)
        ],
    }
    if result["type"] == "zip":
        try:
            result["archive"] = archive_inventory(data, prefixes)
            flags.update(result["archive"]["flags"])
        except OrbitError as exc:
            result["archive_error"] = str(exc)
    elif result["type"] == "gzip":
        try:
            decoder = zlib.decompressobj(31)
            sample = decoder.decompress(data, 2 * 1024 * 1024)
            result["gzip_sample"] = {
                "bytes": len(sample),
                "complete": decoder.eof,
                "strings": strings(sample, maximum=100),
                "flags": find_flags(sample, prefixes),
            }
            flags.update(result["gzip_sample"]["flags"])
        except zlib.error as exc:
            result["gzip_error"] = str(exc)
    result["flags"] = sorted(flags)
    return result


def carve(
    data: bytes, offset: int, save: str, length: int | None = None, signature: str | None = None
) -> dict:
    if not 0 <= offset < len(data):
        raise OrbitError("Offset carving berada di luar file")
    if length is not None:
        if length < 1 or offset + length > len(data):
            raise OrbitError("Length carving berada di luar file")
        end, method = offset + length, "explicit-length"
    elif signature == "png":
        if data[offset : offset + 8] != SIGNATURES["png"]:
            raise OrbitError("Tidak ada signature PNG pada offset")
        pos, end = offset + 8, None
        while pos + 12 <= len(data):
            size = int.from_bytes(data[pos : pos + 4], "big")
            next_pos = pos + 12 + size
            if next_pos > len(data):
                break
            if data[pos + 4 : pos + 8] == b"IEND" and size == 0:
                end = next_pos
                break
            pos = next_pos
        if end is None:
            raise OrbitError("PNG terpotong atau tidak mempunyai IEND")
        method = "png-chunks-through-IEND; CRC tidak diperiksa"
    elif signature == "jpeg":
        if not data[offset:].startswith(SIGNATURES["jpeg"]):
            raise OrbitError("Tidak ada signature JPEG pada offset")
        marker = data.find(b"\xff\xd9", offset + 3)
        if marker < 0:
            raise OrbitError("JPEG tidak memiliki kandidat EOI")
        end, method = marker + 2, "heuristic-first-JPEG-EOI"
    else:
        end, method = len(data), "offset-to-EOF; panjang format belum ditentukan"
    raw = data[offset:end]
    return {
        "saved": write_new(save, raw),
        "offset": offset,
        "length": len(raw),
        "method": method,
        "hashes": hashes(raw),
        "flags": find_flags(raw),
    }
