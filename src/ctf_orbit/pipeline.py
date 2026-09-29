"""Category routing and local directory automation."""

from __future__ import annotations

import os
from pathlib import Path

from . import artifacts, binary, blockchain, codecs, crypto, hardware, mobile, network, osint, stego
from .common import DEFAULT_PREFIXES, OrbitError, bounded, find_flags, read_file
from .web import html_info

CATEGORIES = (
    "web",
    "crypto",
    "forensics",
    "stego",
    "reverse",
    "pwn",
    "network",
    "osint",
    "mobile",
    "blockchain",
    "hardware",
    "misc",
)
IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    "reports",
    "build",
    "dist",
}


def route(data: bytes, path: str) -> list[str]:
    kind, suffix = artifacts.detect_type(data), Path(path).suffix.lower()
    selected = ["forensics", "misc"]
    if kind in ("elf", "pe"):
        selected += ["reverse", "pwn"]
    if kind in ("png", "jpeg", "wav") or suffix in (".bmp", ".gif", ".tiff", ".webp"):
        selected += ["stego"]
    if kind.startswith("pcap") or suffix in (".pcap", ".pcapng"):
        selected += ["network"]
    if suffix == ".apk":
        selected += ["mobile"]
    if kind == "dex" or suffix in (".dex", ".axml"):
        selected += ["mobile"]
    if suffix == ".sol":
        selected += ["blockchain"]
    if kind in ("squashfs-le", "squashfs-be", "ubi", "jffs2-le") or suffix in (
        ".bin",
        ".hex",
        ".ihex",
        ".fw",
    ):
        selected += ["hardware"]
    if kind == "text":
        selected += ["crypto", "osint"]
        if suffix in (".html", ".htm", ".js"):
            selected += ["web"]
    elif kind == "unknown" and data and len(data) <= 65536:
        selected += ["crypto"]
    return selected


def _collect_flags(value, prefixes) -> set[str]:
    if isinstance(value, str):
        return set(find_flags(value, prefixes))
    if isinstance(value, dict):
        return (
            set().union(*(_collect_flags(v, prefixes) for v in value.values())) if value else set()
        )
    if isinstance(value, list):
        return set().union(*(_collect_flags(v, prefixes) for v in value)) if value else set()
    return set()


def _misc(data: bytes, prefixes) -> dict:
    candidates = [data.strip()] if len(data.strip()) <= 8192 else []
    for item in artifacts.strings(data, minimum=12, maximum=40):
        raw = item["text"].encode()
        if raw not in candidates:
            candidates.append(raw)
        if len(candidates) >= 16:
            break
    results, flags = [], set()
    for candidate in candidates[:16]:
        result = codecs.decode_layers(candidate, depth=4, max_nodes=48, prefixes=prefixes)
        flags.update(result["flags"])
        interesting = [
            c
            for c in result["candidates"]
            if c["flags"] or (c["chain"] != ["input"] and c["score"] >= 4.8)
        ]
        results.extend(interesting[:5])
    return {
        "flags": sorted(flags),
        "inputs_sampled": len(candidates[:16]),
        "decoded_candidates": results[:40],
        "note": "Decoding bounded; tidak menjalankan kode challenge",
    }


def analyze_bytes(
    data: bytes, path: str, category: str = "auto", prefixes=DEFAULT_PREFIXES
) -> dict:
    selected = (
        route(data, path)
        if category == "auto"
        else list(CATEGORIES)
        if category == "all"
        else [category]
    )
    results, flags, errors = {}, set(find_flags(data, prefixes)), []
    suffix = Path(path).suffix.lower()
    kind = artifacts.detect_type(data)
    cached_binary = None
    for name in selected:
        try:
            if name == "forensics":
                result = artifacts.inspect(data, path, prefixes)
            elif name == "misc":
                result = _misc(data, prefixes)
            elif name in ("reverse", "pwn"):
                if cached_binary is None:
                    cached_binary = binary.inspect(data)
                result = cached_binary
            elif name == "crypto":
                result = (
                    crypto.caesar(data[:8192].decode("utf-8", "replace"))
                    if kind == "text"
                    else crypto.xor(data[:2048], top=3)
                    if data
                    else {"flags": []}
                )
            elif name == "web":
                result = html_info(data[:1048576].decode("utf-8", "replace"))
            elif name == "osint":
                result = osint.inspect(data[:1048576])
            elif name == "network":
                result = network.inspect(data)
            elif name == "mobile":
                if kind == "dex" or suffix == ".dex":
                    values = mobile.dex_strings(data)
                    result = {"strings": values, "flags": find_flags("\n".join(values), prefixes)}
                elif suffix == ".axml":
                    values = mobile.axml_strings(data)
                    result = {"strings": values, "flags": find_flags("\n".join(values), prefixes)}
                else:
                    result = mobile.inspect(data)
            elif name == "blockchain":
                result = blockchain.inspect(data[:1048576])
            elif name == "hardware":
                result = (
                    hardware.intel_hex(data.decode("ascii"))
                    if suffix in (".hex", ".ihex")
                    else hardware.inspect(data, path)
                )
            elif name == "stego":
                if kind == "wav":
                    result = {"wav": stego.wav_info(data)}
                    raw = stego.wav_lsb(data)
                else:
                    result = stego.image_info(data)
                    raw = stego.image_lsb(data)
                result["lsb_sample"] = stego.extraction_result(raw)
                result["lsb_sample"]["flags"] = find_flags(raw, prefixes)
                result["flags"] = sorted(
                    set(result.get("flags", []) + result["lsb_sample"]["flags"])
                )
            else:
                raise OrbitError(f"Kategori tidak dikenal: {name}")
            flags.update(result.get("flags", []))
            flags.update(_collect_flags(result, prefixes))
            results[name] = {"status": "ok", "result": result}
        except (OrbitError, UnicodeError, OSError, ValueError) as exc:
            results[name] = {"status": "skipped", "reason": str(exc)}
            errors.append({"category": name, "message": str(exc)})
    return {
        "path": path,
        "detected_type": kind,
        "categories": selected,
        "modules": results,
        "flags": sorted(flags),
        "module_errors": errors,
    }


def _files(path: Path, recursive: bool, maximum: int):
    pending, scanned = [path], 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                scanned += 1
                if scanned > 10000:
                    raise OrbitError(
                        "Lebih dari 10000 entri direktori; pilih direktori challenge yang lebih spesifik"
                    )
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
                    maximum -= 1
                    if maximum <= 0:
                        return
                elif (
                    recursive
                    and entry.is_dir(follow_symlinks=False)
                    and entry.name not in IGNORED_DIRECTORIES
                    and not entry.name.startswith(".")
                ):
                    pending.append(Path(entry.path))


def analyze(
    path: str,
    category: str = "auto",
    recursive: bool = False,
    max_files: int = 50,
    max_size_mib: int = 32,
    prefixes=DEFAULT_PREFIXES,
) -> dict:
    bounded(max_files, 1, 500, "Max files")
    bounded(max_size_mib, 1, 128, "Max size MiB")
    if category not in ("auto", "all", *CATEGORIES):
        raise OrbitError("Kategori tidak dikenal")
    find_flags(b"", prefixes)  # Validate custom prefixes before work.
    target = Path(path)
    if not target.exists():
        raise OrbitError(f"Path tidak ditemukan: {path}")
    if target.is_file():
        selected = [target]
    elif target.is_dir():
        selected = list(_files(target, recursive, max_files + 1))
    else:
        raise OrbitError("Path harus berupa file atau direktori")
    results, errors, flags = [], [], set()
    for file in selected[:max_files]:
        try:
            data = read_file(file, max_size_mib * 1024 * 1024)
            result = analyze_bytes(data, str(file), category, prefixes)
            results.append(result)
            flags.update(result["flags"])
        except (OSError, OrbitError) as exc:
            errors.append({"path": str(file), "message": str(exc)})
    return {
        "target": str(target),
        "category": category,
        "files_analyzed": len(results),
        "file_limit_reached": len(selected) > max_files,
        "flags": sorted(flags),
        "files": results,
        "errors": errors,
        "note": "Analisis lokal tanpa eksekusi binary, ekstraksi arsip, atau akses jaringan",
    }
