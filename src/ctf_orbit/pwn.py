"""Portable cyclic offsets and integer packing; no binary execution."""

from __future__ import annotations

from itertools import islice

from .common import OrbitError, bounded, hex_bytes, parse_int, preview


def _alphabet(alphabet: str, n: int):
    bounded(n, 2, 8, "n")
    if not 2 <= len(alphabet) <= 64 or len(set(alphabet)) != len(alphabet):
        raise OrbitError("Alphabet membutuhkan 2–64 karakter unik")
    if any(not 33 <= ord(c) <= 126 for c in alphabet):
        raise OrbitError("Alphabet hanya menerima ASCII printable tanpa spasi")
    return alphabet.encode("ascii")


def _debruijn(alphabet: bytes, n: int):
    k = len(alphabet)
    values = [0] * (k * n)

    def visit(t: int, p: int):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[values[j]]
        else:
            values[t] = values[t - p]
            yield from visit(t + 1, p)
            for j in range(values[t - p] + 1, k):
                values[t] = j
                yield from visit(t + 1, t)

    yield from visit(1, 1)


def cyclic(length: int = 200, alphabet: str = "abcdefghijklmnopqrstuvwxyz", n: int = 4) -> bytes:
    chars = _alphabet(alphabet, n)
    bounded(length, 1, min(1048576, len(chars) ** n), "Panjang pattern")
    return bytes(islice(_debruijn(chars, n), length))


def offset(
    value: str,
    encoding: str = "text",
    endian: str = "little",
    n: int = 4,
    alphabet: str = "abcdefghijklmnopqrstuvwxyz",
    max_length: int = 1000000,
) -> dict:
    chars = _alphabet(alphabet, n)
    bounded(max_length, n, 1048576, "Max length")
    if encoding == "hex":
        needle = hex_bytes(value)
    elif encoding == "int":
        integer = parse_int(value)
        if not 0 <= integer < 256**n:
            raise OrbitError("Nilai tidak muat dalam n byte")
        needle = integer.to_bytes(n, endian)
    else:
        try:
            needle = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise OrbitError("Pattern text harus berupa ASCII") from exc
    if len(needle) != n:
        raise OrbitError(
            "Panjang nilai harus sama dengan n; gunakan n yang sama saat membuat pattern"
        )
    pattern = cyclic(min(max_length, len(chars) ** n), alphabet, n)
    index = pattern.find(needle)
    return {
        "offset": index if index >= 0 else None,
        "needle_hex": needle.hex(),
        "n": n,
        "endian": endian,
        "bytes_searched": len(pattern),
        "note": "Jika tidak ditemukan, periksa n/endian/alphabet dan batas pencarian",
    }


def pack(value: int, bits: int = 64, endian: str = "little") -> dict:
    if not 0 <= value < 2**bits:
        raise OrbitError("Nilai pack tidak muat dalam ukuran unsigned yang dipilih")
    raw = value.to_bytes(bits // 8, endian)
    return {
        "value": str(value),
        "bits": bits,
        "endian": endian,
        "python_bytes": "".join(f"\\x{b:02x}" for b in raw),
        **preview(raw),
    }


def unpack(data: bytes, endian: str = "little") -> dict:
    if len(data) not in (1, 2, 4, 8):
        raise OrbitError("Unpack menerima 1, 2, 4, atau 8 byte")
    value = int.from_bytes(data, endian)
    return {"value": str(value), "value_hex": hex(value), "bits": len(data) * 8, "endian": endian}
