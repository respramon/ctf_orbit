#!/usr/bin/env python3
"""Generate deterministic synthetic challenge fixtures; never fetch remote data."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import math
import struct
import wave
import zipfile
import zlib
from pathlib import Path


def _write(root: Path, name: str, data: bytes):
    destination = root / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _bits(data: bytes):
    return [(value >> shift) & 1 for value in data for shift in range(7, -1, -1)]


def make_dex(values: list[str]) -> bytes:
    header = bytearray(112)
    header[:8] = b"dex\n035\x00"
    table_size, strings = len(values) * 4, bytearray()
    offsets = []
    for value in values:
        raw = value.encode()
        if len(value) > 127:
            raise ValueError("Example string must fit single-byte ULEB128")
        offsets.append(112 + table_size + len(strings))
        strings.extend(bytes([len(value)]) + raw + b"\x00")
    size = 112 + table_size + len(strings)
    struct.pack_into("<III", header, 32, size, 112, 0x12345678)
    struct.pack_into("<II", header, 56, len(values), 112)
    struct.pack_into("<II", header, 104, len(strings), 112 + table_size)
    result = header + b"".join(struct.pack("<I", off) for off in offsets) + strings
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xFFFFFFFF)
    return bytes(result)


def make_axml(values: list[str], utf8: bool = True) -> bytes:
    offsets, body = [], bytearray()
    for value in values:
        offsets.append(len(body))
        encoded = value.encode("utf-8" if utf8 else "utf-16-le")
        if utf8:
            body.extend(bytes([len(value), len(encoded)]) + encoded + b"\x00")
        else:
            body.extend(struct.pack("<H", len(value)) + encoded + b"\x00\x00")
    while len(body) % 4:
        body.append(0)
    start = 28 + 4 * len(values)
    pool = struct.pack(
        "<HHI5I", 1, 28, start + len(body), len(values), 0, 0x100 if utf8 else 0, start, 0
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + body
    return struct.pack("<HHI", 3, 8, 8 + len(pool)) + pool


def make_elf() -> bytes:
    code = bytes.fromhex("b82a000000c3") + b"ORBIT{static_reverse}\x00"
    size = 64 + 2 * 56 + len(code)
    identity = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000B0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return identity + header + load + stack + code


def make_pe() -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", data, optional + 68, 3, 0x140)
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        optional + 240,
        b".text\x00\x00\x00",
        32,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x200:0x206] = bytes.fromhex("b82a000000c3")
    flag = b"ORBIT{static_pe}\x00"
    data[0x210 : 0x210 + len(flag)] = flag
    return bytes(data)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def _packet(
    payload: bytes, seq: int = 1000, proto: int = 6, sport: int = 40000, dport: int = 80
) -> bytes:
    src, dst = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])
    if proto == 6:
        transport = bytearray(
            struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18, 8192, 0, 0)
        )
        transport += payload
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(transport))
        struct.pack_into("!H", transport, 16, _checksum(pseudo + transport))
    else:
        transport = bytearray(struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload)
    header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, len(transport) + 20, 1, 0x4000, 64, proto, 0, src, dst
        )
    )
    struct.pack_into("!H", header, 10, _checksum(header))
    return bytes.fromhex("00112233445566778899aabb0800") + header + transport


def make_pcap(endian: str = "<", nano: bool = False) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
    a = b"GET /hint HTTP/1.1\r\nHost: ctf.example.test\r\n\r\nORBIT{tcp_"
    b = b"reassembled}"
    dns = (
        struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + b"\x03ctf\x07example\x04test\x00\x00\x01\x00\x01"
    )
    frames = [
        _packet(b, 1000 + len(a)),
        _packet(a),
        _packet(a),
        _packet(dns, proto=17, dport=53),
        _packet(b"ORBIT{udp_payload}", proto=17, dport=9000),
    ]
    for index, frame in enumerate(frames):
        result.extend(
            struct.pack(endian + "IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame
        )
    return bytes(result)


def _ihex_record(address: int, kind: int, payload: bytes) -> str:
    raw = bytes([len(payload)]) + address.to_bytes(2, "big") + bytes([kind]) + payload
    return ":" + (raw + bytes([-sum(raw) % 256])).hex().upper()


def generate(root: Path, with_image: bool = True):
    root.mkdir(parents=True, exist_ok=True)
    flag = b"ORBIT{layered_decode}"
    _write(root, "misc/layers.txt", base64.b64encode(flag.hex().encode()) + b"\n")
    _write(root, "misc/hello.bf", b"++++++++[>++++++++<-]>+.")
    _write(root, "crypto/xor.bin", bytes(c ^ 0x42 for c in b"ORBIT{single_byte_xor}"))
    p, q, e = 1000003, 1000033, 65537
    m = int.from_bytes(b"Hi", "big")
    _write(
        root,
        "crypto/rsa.json",
        (
            json.dumps(
                {"n": p * q, "e": e, "c": pow(m, e, p * q), "p": p, "q": q, "expected_text": "Hi"},
                indent=2,
            )
            + "\n"
        ).encode(),
    )
    memory = (
        b"\x00\x01ORBIT{memory_strings}\x00"
        + "ORBIT{utf16_string}".encode("utf-16-le")
        + b"\x00\x00"
    )
    _write(root, "forensics/memory.bin", memory)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target:
        item = zipfile.ZipInfo("notes.txt", date_time=(2020, 1, 1, 0, 0, 0))
        item.compress_type = zipfile.ZIP_DEFLATED
        target.writestr(item, "ORBIT{inside_zip}\n")
        target.comment = b"CTF Orbit synthetic archive"
    _write(root, "forensics/evidence.zip", archive.getvalue())
    _write(root, "reverse/sample.elf", make_elf())
    _write(root, "reverse/sample.exe", make_pe())
    _write(root, "reverse/x64.raw", bytes.fromhex("554889e5b82a0000005dc3"))
    _write(root, "network/traffic.pcap", make_pcap())
    _write(
        root,
        "osint/page.html",
        b'<html><head><title>Orbit challenge</title><meta name="author" content="CTF Organizer"></head><body><a href="https://ctf.example.test/hint">hint</a>team@example.test @orbit_player 192.0.2.10 <!-- ORBIT{html_comment} --></body></html>',
    )
    dex = make_dex(
        ["Lcom/orbit/Challenge;", "https://ctf.example.test/api", "api_key", "ORBIT{dex_string}"]
    )
    axml = make_axml(
        ["manifest", "package", "com.orbit.lab", "android.permission.INTERNET", "debuggable"]
    )
    _write(root, "mobile/classes.dex", dex)
    _write(root, "mobile/AndroidManifest.axml", axml)
    apk = io.BytesIO()
    with zipfile.ZipFile(apk, "w") as target:
        for name, data in (("AndroidManifest.xml", axml), ("classes.dex", dex)):
            target.writestr(zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)), data)
    _write(root, "mobile/challenge.apk", apk.getvalue())
    _write(
        root,
        "blockchain/Challenge.sol",
        b"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Challenge {
    address public owner;
    string public hint = "ORBIT{solidity_hint}";
    constructor() { owner = msg.sender; }
    function check() external view returns (bool) { return tx.origin == owner; }
}
""",
    )
    _write(
        root,
        "hardware/firmware.bin",
        b"\x00" * 32 + b"U-Boot CTF lab\x00BusyBox\x00hsqs\x00ORBIT{firmware_strings}\x00",
    )
    firmware = b"ORBIT{intel_hex}\x00"
    lines = [
        _ihex_record(0, 4, b"\x00\x01"),
        _ihex_record(0x10, 0, firmware),
        _ihex_record(0, 1, b""),
    ]
    _write(root, "hardware/firmware.hex", ("\n".join(lines) + "\n").encode())
    sound = io.BytesIO()
    bits = _bits(b"ORBIT{wav_lsb}\x00")
    samples = bytearray()
    for index in range(4096):
        value = int(1000 * math.sin(index / 10)) & 0xFFFE
        value |= bits[index] if index < len(bits) else 0
        samples.extend(value.to_bytes(2, "little"))
    with wave.open(sound, "wb") as wav:
        wav.setparams((1, 2, 8000, 4096, "NONE", "not compressed"))
        wav.writeframes(samples)
    _write(root, "stego/audio.wav", sound.getvalue())
    if with_image:
        try:
            from PIL import Image
        except ImportError:
            return
        bits = _bits(b"ORBIT{png_lsb}\x00")
        pixels, cursor = [], 0
        for y in range(32):
            for x in range(32):
                values = [(x * 7) % 256, (y * 7) % 256, ((x + y) * 3) % 256]
                for channel in range(3):
                    values[channel] = (values[channel] & 0xFE) | (
                        bits[cursor] if cursor < len(bits) else 0
                    )
                    cursor += 1
                pixels.append(tuple(values))
        with Image.new("RGB", (32, 32)) as image:
            image.putdata(pixels)
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            _write(root, "stego/hidden.png", buffer.getvalue())
            _write(
                root, "forensics/carrier.bin", b"ORBIT-CARRIER\x00" + buffer.getvalue() + b"TRAILER"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", default=str(Path(__file__).resolve().parents[1] / "examples" / "data")
    )
    parser.add_argument("--no-image", action="store_true")
    options = parser.parse_args()
    generate(Path(options.directory), not options.no_image)
    print(f"Contoh dibuat di {Path(options.directory).resolve()}")
