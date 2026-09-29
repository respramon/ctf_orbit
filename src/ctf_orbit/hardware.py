"""Firmware clues and Intel HEX conversion with checksums and address limits."""

from __future__ import annotations

import re

from .artifacts import inspect as file_inspect
from .common import OrbitError, find_flags, hashes, write_new


def inspect(data: bytes, path: str = "") -> dict:
    result = file_inspect(data, path)
    result["firmware_clues"] = [
        s
        for s in result["strings"]
        if re.search(
            r"(?i)u-boot|busybox|linux version|squashfs|uart|jffs2|ubifs|bootargs", s["text"]
        )
    ][:100]
    result["note"] = (
        "Magic/entropy/string adalah petunjuk; belum mengekstrak filesystem atau membaca perangkat"
    )
    return result


def intel_hex(text: str, save: str | None = None) -> dict:
    segments, base, eof, total, start_address = [], 0, False, 0, None
    for number, line in enumerate(text.splitlines(), 1):
        record = line.strip()
        if not record:
            continue
        if eof:
            raise OrbitError("Ada record setelah EOF Intel HEX")
        if not record.startswith(":") or len(record) > 521:
            raise OrbitError(f"Record Intel HEX tidak valid pada baris {number}")
        try:
            raw = bytes.fromhex(record[1:])
        except ValueError as exc:
            raise OrbitError(f"Hex tidak valid pada baris {number}") from exc
        if len(raw) < 5 or len(raw) != raw[0] + 5 or sum(raw) % 256:
            raise OrbitError(f"Length/checksum Intel HEX salah pada baris {number}")
        size, address, kind = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        payload = raw[4:-1]
        if kind == 0:
            if address + size > 65536 or base + address + size > 2**32:
                raise OrbitError("Intel HEX data melintasi batas address")
            if payload:
                segments.append((base + address, payload))
                total += size
                if total > 4 * 1024 * 1024:
                    raise OrbitError("Data Intel HEX melewati 4 MiB")
        elif kind == 1 and size == 0 and address == 0:
            eof = True
        elif kind in (2, 4) and size == 2 and address == 0:
            base = int.from_bytes(payload, "big") << (4 if kind == 2 else 16)
        elif kind in (3, 5) and size == 4 and address == 0:
            start_address = (
                ((int.from_bytes(payload[:2], "big") << 4) + int.from_bytes(payload[2:], "big"))
                if kind == 3
                else int.from_bytes(payload, "big")
            )
        else:
            raise OrbitError(f"Intel HEX record type/length tidak didukung pada baris {number}")
    if not eof or not segments:
        raise OrbitError("Intel HEX membutuhkan EOF dan record data")
    lowest = min(address for address, _ in segments)
    highest = max(address + len(payload) for address, payload in segments)
    if highest - lowest > 4 * 1024 * 1024:
        raise OrbitError("Span alamat Intel HEX melewati 4 MiB")
    output, assigned = bytearray(b"\xff" * (highest - lowest)), bytearray(highest - lowest)
    for address, payload in segments:
        offset = address - lowest
        for index, value in enumerate(payload, offset):
            if assigned[index] and output[index] != value:
                raise OrbitError("Intel HEX mempunyai overlap dengan byte berbeda")
            output[index], assigned[index] = value, 1
    result = {
        "base_address": hex(lowest),
        "end_address_exclusive": hex(highest),
        "start_address": hex(start_address) if start_address is not None else None,
        "bytes": len(output),
        "filled_gap_bytes": assigned.count(0),
        "hashes": hashes(output),
        "flags": find_flags(output),
    }
    if save:
        result["saved"] = write_new(save, bytes(output))
    return result
