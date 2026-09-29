"""Bounded breadth-first decoding of common CTF encodings."""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from collections import deque
from urllib.parse import unquote_to_bytes

from .common import DEFAULT_PREFIXES, OrbitError, bounded, find_flags, preview, text_score

MORSE = dict(
    zip(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.. ----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.".split(),
        strict=True,
    )
)


def morse_decode(text: str) -> str:
    reverse = {v: k for k, v in MORSE.items()}
    result = []
    for word in text.strip().replace("   ", " / ").split("/"):
        try:
            result.append("".join(reverse[token] for token in word.split()))
        except KeyError as exc:
            raise OrbitError(f"Token Morse tidak dikenali: {exc.args[0]}") from exc
    return " ".join(result)


def transformations(data: bytes):
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 2 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", compact):
        payload = compact[2:] if compact.lower().startswith("0x") else compact
        if len(payload) % 2 == 0:
            yield "hex", bytes.fromhex(payload)
    if len(compact) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        padded = compact + "=" * (-len(compact) % 4)
        try:
            yield "base64", base64.b64decode(padded, altchars=b"-_", validate=True)
        except binascii.Error:
            pass
    if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+={0,6}", compact, re.I):
        try:
            yield "base32", base64.b32decode(compact.upper() + "=" * (-len(compact) % 8))
        except binascii.Error:
            pass
    if re.search(r"%[0-9a-fA-F]{2}", text):
        yield "url", unquote_to_bytes(text)
    if re.search(r"&(?:#x?[0-9a-fA-F]+|[A-Za-z]+);", text):
        yield "html", html.unescape(text).encode()
    if re.fullmatch(r"[01\s]+", text) and len(compact) >= 8 and len(compact) % 8 == 0:
        yield "binary", bytes(int(compact[i : i + 8], 2) for i in range(0, len(compact), 8))
    if re.fullmatch(r"\d{1,3}(?:[ ,;]+\d{1,3})+", text):
        values = list(map(int, re.split(r"[ ,;]+", text)))
        if all(v < 256 for v in values):
            yield "decimal-bytes", bytes(values)
    if text and re.fullmatch(r"[.\-/\s]+", text):
        try:
            yield "morse", morse_decode(text).encode()
        except OrbitError:
            pass
    if re.search("[A-Za-z]", text):
        yield "rot13", codecs.encode(text, "rot_13").encode()
    if text:
        yield "reverse", text[::-1].encode()


def decode_layers(
    data: bytes, depth: int = 4, max_nodes: int = 128, prefixes=DEFAULT_PREFIXES
) -> dict:
    bounded(depth, 1, 8, "Depth")
    bounded(max_nodes, 1, 512, "Max nodes")
    if len(data) > 256 * 1024:
        raise OrbitError("Decoder menerima maksimal 256 KiB; pilih potongan yang relevan")
    queue = deque([(data, [])])
    seen = {data}
    results, flags = [], set()
    while queue and len(results) < max_nodes:
        raw, chain = queue.popleft()
        found = find_flags(raw, prefixes)
        flags.update(found)
        results.append(
            {"chain": chain or ["input"], "score": text_score(raw), "flags": found, **preview(raw)}
        )
        if len(chain) >= depth:
            continue
        for method, candidate in transformations(raw):
            if candidate and candidate not in seen and len(seen) < max_nodes:
                seen.add(candidate)
                queue.append((candidate, chain + [method]))
    results.sort(key=lambda item: (bool(item["flags"]), item["score"]), reverse=True)
    return {
        "flags": sorted(flags),
        "nodes_visited": len(results),
        "depth": depth,
        "node_limit_reached": len(seen) >= max_nodes,
        "candidates": results,
    }


def brainfuck(
    program: str, input_data: bytes = b"", max_steps: int = 200000, max_output: int = 65536
) -> dict:
    bounded(max_steps, 1, 2000000, "Max steps")
    code = "".join(c for c in program if c in "><+-.,[]")
    if len(code) > 100000:
        raise OrbitError("Program terlalu panjang")
    stack, jumps = [], {}
    for index, token in enumerate(code):
        if token == "[":
            stack.append(index)
        elif token == "]":
            if not stack:
                raise OrbitError("Kurung Brainfuck tidak seimbang")
            left = stack.pop()
            jumps[left], jumps[index] = index, left
    if stack:
        raise OrbitError("Kurung Brainfuck tidak seimbang")
    tape, pointer, pc, steps, input_pos = bytearray(30000), 0, 0, 0, 0
    output = bytearray()
    while pc < len(code):
        if steps >= max_steps:
            raise OrbitError("Batas langkah Brainfuck tercapai (kemungkinan loop)")
        token = code[pc]
        if token == ">":
            pointer += 1
        elif token == "<":
            pointer -= 1
        if not 0 <= pointer < len(tape):
            raise OrbitError("Pointer Brainfuck keluar dari tape")
        if token == "+":
            tape[pointer] = (tape[pointer] + 1) % 256
        elif token == "-":
            tape[pointer] = (tape[pointer] - 1) % 256
        elif token == ".":
            if len(output) >= max_output:
                raise OrbitError("Batas output Brainfuck tercapai")
            output.append(tape[pointer])
        elif token == ",":
            tape[pointer] = input_data[input_pos] if input_pos < len(input_data) else 0
            input_pos += 1
        elif token == "[" and tape[pointer] == 0:
            pc = jumps[pc]
        elif token == "]" and tape[pointer] != 0:
            pc = jumps[pc]
        pc += 1
        steps += 1
    return {"steps": steps, "flags": find_flags(output), **preview(output)}
