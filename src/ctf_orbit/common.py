"""Bounded I/O, flag detection, scoring, and portable reports."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PREFIXES = ("flag", "ctf", "picoCTF", "HTB", "THM", "ORBIT")
MAX_FILE_BYTES = 32 * 1024 * 1024


class OrbitError(ValueError):
    """Expected user-input or challenge-format error."""


def read_file(path: str | Path, limit: int = MAX_FILE_BYTES) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise OrbitError(f"Bukan file biasa: {p}")
    if p.stat().st_size > limit:
        raise OrbitError(f"File melebihi batas {limit} byte: {p}")
    with p.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise OrbitError("File berubah atau melebihi batas ketika dibaca")
    return data


def write_new(path: str | Path, data: bytes) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also rejects existing symlinks.
    with p.open("xb") as stream:
        stream.write(data)
    return str(p.resolve())


def bounded(value: int, low: int, high: int, label: str) -> int:
    if not low <= value <= high:
        raise OrbitError(f"{label} harus antara {low} dan {high}")
    return value


def parse_int(value: str) -> int:
    try:
        text = value.strip()
        return int(text, 16 if text.lower().lstrip("-").startswith("0x") else 10)
    except ValueError as exc:
        raise OrbitError(f"Integer tidak valid: {value}") from exc


def hex_bytes(value: str) -> bytes:
    text = value.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise OrbitError("Hex harus berisi pasangan digit, misalnya 414243 atau 0x414243") from exc


def find_flags(data: bytes | bytearray | str, prefixes=DEFAULT_PREFIXES) -> list[str]:
    text = data.decode("latin-1") if isinstance(data, (bytes, bytearray)) else data
    prefix_list = tuple(prefixes)
    if not prefix_list:
        return []
    for prefix in prefix_list:
        if not re.fullmatch(r"[A-Za-z0-9_]{1,40}", prefix):
            raise OrbitError("Prefix flag hanya boleh berupa huruf, angka, underscore (1–40)")
    pattern = r"(?i)(?<![A-Za-z0-9_])(?:" + "|".join(map(re.escape, prefix_list))
    pattern += r")\{[\x20-\x7e]{1,200}?\}"
    return sorted(set(re.findall(pattern, text)))[:200]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    return round(-sum((n / size) * math.log2(n / size) for n in Counter(data).values()), 5)


def hashes(data: bytes) -> dict[str, str]:
    return {
        name: hashlib.new(name, data, usedforsecurity=False).hexdigest()
        for name in ("md5", "sha1", "sha256")
    }


def text_score(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:8192]
    printable = sum(32 <= c <= 126 or c in (9, 10, 13) for c in sample) / len(sample)
    common = sum(c in b" etaoinshrdluETAOINSHRDLU{}_" for c in sample) / len(sample)
    letters = sum(65 <= c <= 90 or 97 <= c <= 122 for c in sample) / len(sample)
    return round(printable * 4 + common * 2 + letters + 20 * bool(find_flags(sample)), 4)


def preview(data: bytes, limit: int = 1024) -> dict:
    return {
        "length": len(data),
        "text": data[:limit].decode("utf-8", "replace"),
        "hex": data[: min(limit, 256)].hex(),
        "preview_truncated": len(data) > limit,
    }


def strings(data: bytes, minimum: int = 4, maximum: int = 500) -> list[dict]:
    bounded(minimum, 2, 128, "Minimum panjang string")
    bounded(maximum, 1, 10000, "Jumlah string")
    found = []
    for encoding, pattern in (
        ("ascii", rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}"),
        ("utf-16-le", rb"(?:[\x20-\x7e]\x00){" + str(minimum).encode() + rb",}"),
        ("utf-16-be", rb"(?:\x00[\x20-\x7e]){" + str(minimum).encode() + rb",}"),
    ):
        for match in re.finditer(pattern, data):
            if len(found) >= maximum:
                return sorted(found, key=lambda item: item["offset"])
            raw = match.group()[: 1024 if encoding == "ascii" else 2048]
            found.append(
                {
                    "offset": match.start(),
                    "encoding": encoding,
                    "text": raw.decode(encoding),
                    "truncated": len(raw) < len(match.group()),
                }
            )
    return sorted(found, key=lambda item: item["offset"])


def report_markdown(report: dict) -> str:
    title = report.get("command", "CTF Orbit")
    chunks = [f"# Laporan {title}", "", f"Dibuat: {report.get('generated_at', '')}", ""]
    flag_list = report.get("flags", [])
    if flag_list:
        chunks += ["## Kandidat flag", ""]
        chunks += [f"- `{flag.replace('`', '')}`" for flag in flag_list]
        chunks += [""]

    def walk(value, depth=2):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("command", "generated_at"):
                    continue
                safe_key = str(key).replace("\n", "\\n").replace("\r", "\\r")[:240]
                key_fence = "`" * max(
                    1, max((len(m.group()) + 1 for m in re.finditer(r"`+", safe_key)), default=1)
                )
                chunks.extend([f"{'#' * min(depth, 6)} {key_fence} {safe_key} {key_fence}", ""])
                walk(item, depth + 1)
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            for index, item in enumerate(value, 1):
                chunks.extend([f"{'#' * min(depth, 6)} Item {index}", ""])
                walk(item, depth + 1)
        else:
            rendered = json.dumps(value, ensure_ascii=False, indent=2)
            # JSON-quoted strings may still contain Markdown fence characters.
            fence = "`" * max(
                3, max((len(m.group()) + 1 for m in re.finditer(r"`+", rendered)), default=3)
            )
            chunks.extend([f"{fence}json", rendered, fence, ""])

    walk({k: v for k, v in report.items() if k != "flags"})
    return "\n".join(chunks)


def emit(result: dict, command: str, output: str | None = None) -> dict:
    report = {
        "schema_version": 1,
        "tool_version": "1.0.0",
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    encoded = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode()
    if output:
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        if any(
            (directory / name).exists() or (directory / name).is_symlink()
            for name in ("report.json", "report.md")
        ):
            raise OrbitError("Laporan sudah ada; gunakan direktori --out yang baru")
        write_new(directory / "report.json", encoded)
        write_new(directory / "report.md", report_markdown(report).encode("utf-8"))
    return report
