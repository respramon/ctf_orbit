"""Classical crypto and explicitly bounded textbook RSA helpers."""

from __future__ import annotations

import math
import re

from .common import OrbitError, bounded, find_flags, preview, text_score


def caesar(text: str, shift: int | None = None) -> dict:
    shifts = range(26) if shift is None else [shift % 26]
    candidates = []
    for n in shifts:
        plain = "".join(
            chr((ord(c) - base - n) % 26 + base)
            if (base := (65 if "A" <= c <= "Z" else 97 if "a" <= c <= "z" else 0))
            else c
            for c in text
        )
        candidates.append(
            {
                "shift": n,
                "text": plain,
                "score": text_score(plain.encode()),
                "flags": find_flags(plain),
            }
        )
    candidates.sort(key=lambda item: item["score"], reverse=True)
    return {"flags": sorted({f for c in candidates for f in c["flags"]}), "candidates": candidates}


def vigenere(text: str, key: str, encrypt: bool = False) -> dict:
    if not re.fullmatch("[A-Za-z]+", key):
        raise OrbitError("Key Vigenere harus berupa huruf ASCII")
    shifts, output, pos = [ord(c) - 97 for c in key.lower()], [], 0
    for c in text:
        if "A" <= c <= "Z" or "a" <= c <= "z":
            base = 65 if c.isupper() else 97
            step = shifts[pos % len(shifts)] * (1 if encrypt else -1)
            output.append(chr((ord(c) - base + step) % 26 + base))
            pos += 1
        else:
            output.append(c)
    result = "".join(output)
    return {
        "mode": "encrypt" if encrypt else "decrypt",
        "text": result,
        "flags": find_flags(result),
    }


def xor(data: bytes, key: bytes | None = None, top: int = 10) -> dict:
    bounded(top, 1, 256, "Top")
    if len(data) > 65536:
        raise OrbitError("Input XOR maksimal 64 KiB")
    if not data:
        raise OrbitError("Input XOR kosong")
    if key == b"":
        raise OrbitError("Key XOR kosong")
    candidates = []
    for item in [key] if key is not None else [bytes([i]) for i in range(256)]:
        raw = bytes(value ^ item[index % len(item)] for index, value in enumerate(data))
        candidates.append(
            {
                "key_hex": item.hex(),
                "score": text_score(raw),
                "flags": find_flags(raw),
                **preview(raw),
            }
        )
    candidates.sort(key=lambda entry: entry["score"], reverse=True)
    return {
        "mode": "known-key" if key is not None else "single-byte-search",
        "flags": sorted({f for c in candidates for f in c["flags"]}),
        "candidates": candidates[:top],
    }


def integer_root(value: int, power: int) -> int:
    if value < 0 or power < 1:
        raise OrbitError("Root membutuhkan nilai nonnegatif dan pangkat positif")
    if value <= 1:
        return value
    low, high = 0, 1 << ((value.bit_length() + power - 1) // power)
    while low + 1 < high:
        mid = (low + high) // 2
        if mid**power <= value:
            low = mid
        else:
            high = mid
    return high if high**power <= value else low


def probable_prime(value: int) -> bool:
    if value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if value % p == 0:
            return value == p
    d, s = value - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic for <2**64; a probable-prime check for larger factors.
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True


def rsa(
    n: int,
    e: int,
    c: int,
    p: int | None = None,
    q: int | None = None,
    trial_limit: int = 100000,
    fermat_steps: int = 0,
) -> dict:
    if n <= 1 or e <= 1 or not 0 <= c < n:
        raise OrbitError("RSA membutuhkan n>1, e>1, dan 0<=c<n")
    if max(n.bit_length(), e.bit_length(), c.bit_length()) > 8192:
        raise OrbitError("Integer RSA maksimal 8192 bit")
    bounded(trial_limit, 0, 1000000, "Trial limit")
    bounded(fermat_steps, 0, 1000000, "Fermat steps")
    method = "provided-factors"
    if p is None and q is not None:
        if q <= 1 or n % q:
            raise OrbitError("q bukan faktor n")
        p = n // q
    if p is not None and q is None:
        if p <= 1 or n % p:
            raise OrbitError("p bukan faktor n")
        q = n // p
    if p is None:
        if e <= 64:
            root = integer_root(c, e)
            if root**e == c:
                raw = root.to_bytes(max(1, (root.bit_length() + 7) // 8), "big")
                return {
                    "method": "exact-small-exponent-root",
                    "m": str(root),
                    "flags": find_flags(raw),
                    **preview(raw),
                }
        if n % 2 == 0 and trial_limit >= 2:
            p, q, method = 2, n // 2, "trial-division"
        else:
            for divisor in range(3, min(math.isqrt(n), trial_limit) + 1, 2):
                if n % divisor == 0:
                    p, q, method = divisor, n // divisor, "trial-division"
                    break
        if p is None and n % 2:
            a = math.isqrt(n)
            if a * a < n:
                a += 1
            for _ in range(fermat_steps):
                b2 = a * a - n
                b = math.isqrt(b2)
                if b * b == b2 and a - b > 1:
                    p, q, method = a - b, a + b, "bounded-fermat"
                    break
                a += 1
    if p is None or q is None:
        return {
            "method": "unsolved",
            "flags": [],
            "note": "Tidak ditemukan faktor dalam batas pencarian; gunakan p/q atau analisis lain",
        }
    if p == q or p * q != n or not probable_prime(p) or not probable_prime(q):
        raise OrbitError("Helper ini membutuhkan n=p*q dengan p dan q prima berbeda")
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise OrbitError("e tidak mempunyai invers modulo phi(n)")
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    if pow(m, e, n) != c:
        raise OrbitError("Validasi ciphertext RSA gagal")
    raw = m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
    return {
        "method": method,
        "p": str(p),
        "q": str(q),
        "d": str(d),
        "m": str(m),
        "padding": "textbook; OAEP/PKCS#1 tidak dilepas",
        "flags": find_flags(raw),
        **preview(raw),
    }


def hash_identify(text: str) -> dict:
    value = text.strip()
    guesses = []
    if re.fullmatch("[0-9a-fA-F]+", value):
        guesses = {
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA-1", "RIPEMD-160"],
            56: ["SHA-224"],
            64: ["SHA-256", "SHA3-256", "Keccak-256"],
            96: ["SHA-384"],
            128: ["SHA-512", "SHA3-512"],
        }.get(len(value), [])
    elif value.startswith(("$2a$", "$2b$", "$2y$")):
        guesses = ["bcrypt"]
    elif value.startswith("$argon2"):
        guesses = ["Argon2"]
    return {
        "length": len(value),
        "possible_algorithms": guesses,
        "note": "Pengenalan format saja; panjang hash tidak membuktikan algoritma",
    }
