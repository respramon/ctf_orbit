"""Static Solidity clues, Keccak selectors, static ABI words, EVM opcodes."""

from __future__ import annotations

import re

from .common import OrbitError, find_flags, hex_bytes


def inspect(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    token_pattern = r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|//[^\n]*|/\*[\s\S]*?\*/'
    clean = re.sub(
        token_pattern,
        lambda m: (
            re.sub(r"[^\n]", " ", m.group()) if m.group().startswith(("//", "/*")) else m.group()
        ),
        text,
    )
    patterns = {
        "tx.origin": r"\btx\.origin\b",
        "delegatecall": r"\.delegatecall\s*\(",
        "low_level_call": r"\.call\s*(?:\{|\()",
        "selfdestruct": r"\bselfdestruct\s*\(",
        "timestamp_or_block_number": r"\bblock\.(?:timestamp|number)\b",
        "unchecked_arithmetic": r"\bunchecked\s*\{",
    }
    findings = [
        {"clue": name, "line": clean.count("\n", 0, match.start()) + 1}
        for name, pattern in patterns.items()
        for match in list(re.finditer(pattern, clean))[:100]
    ]
    return {
        "pragma": re.findall(r"pragma\s+solidity\s+([^;]+);", clean)[:20],
        "functions": re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", clean)[:500],
        "addresses": sorted(set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", clean)))[:500],
        "clues": findings,
        "flags": find_flags(text),
        "note": "Heuristik source, bukan audit atau bukti exploit; tidak menghubungi RPC dan tidak mengirim transaksi",
    }


def selector(signature: str) -> dict:
    if len(signature) > 512 or not re.fullmatch(
        r"[A-Za-z_$][\w$]*\([A-Za-z0-9_$,()[\]]*\)", signature
    ):
        raise OrbitError(
            "Gunakan signature ABI kanonis tanpa spasi, contoh transfer(address,uint256)"
        )
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise OrbitError('Pasang modul crypto: python -m pip install ".[crypto]"') from exc
    digest = keccak.new(digest_bits=256, data=signature.encode("ascii")).hexdigest()
    return {
        "signature": signature,
        "selector": "0x" + digest[:8],
        "keccak256": "0x" + digest,
        "note": "Signature dipakai persis; uint harus ditulis uint256, SHA3-256 berbeda dari Keccak-256",
    }


def abi_decode(value: str, types: list[str] | None = None, has_selector: bool = False) -> dict:
    data = hex_bytes(value)
    if len(data) > 65536:
        raise OrbitError("ABI input maksimal 64 KiB")
    prefix = None
    if has_selector:
        if len(data) < 4:
            raise OrbitError("Calldata terlalu pendek untuk selector")
        prefix, data = "0x" + data[:4].hex(), data[4:]
    if len(data) % 32:
        raise OrbitError("Payload ABI harus kelipatan 32 byte (setelah selector)")
    words = [data[pos : pos + 32] for pos in range(0, len(data), 32)]
    if types is not None and len(types) != len(words):
        raise OrbitError("Jumlah --types harus sama dengan jumlah word")
    result = []
    for index, word in enumerate(words):
        integer = int.from_bytes(word, "big")
        kind = types[index] if types is not None else "raw"
        if kind == "raw":
            decoded = {
                "uint256": str(integer),
                "address_candidate": "0x" + word[-20:].hex() if not any(word[:12]) else None,
            }
        elif kind == "address":
            if any(word[:12]):
                raise OrbitError("Padding address ABI tidak kanonis")
            decoded = "0x" + word[-20:].hex()
        elif kind == "bool":
            if integer not in (0, 1):
                raise OrbitError("Bool ABI hanya menerima 0 atau 1")
            decoded = bool(integer)
        elif re.fullmatch(r"u?int\d+", kind):
            bits = int(re.search(r"\d+", kind).group())
            if bits < 8 or bits > 256 or bits % 8:
                raise OrbitError("Ukuran integer ABI harus 8–256 dan kelipatan 8")
            if kind.startswith("uint"):
                if integer >= 2**bits:
                    raise OrbitError("Integer ABI keluar rentang")
                decoded = str(integer)
            else:
                signed = int.from_bytes(word, "big", signed=True)
                if not -(2 ** (bits - 1)) <= signed < 2 ** (bits - 1):
                    raise OrbitError("Sign extension ABI tidak kanonis")
                decoded = str(signed)
        elif re.fullmatch(r"bytes\d+", kind):
            size = int(kind[5:])
            if not 1 <= size <= 32 or any(word[size:]):
                raise OrbitError("bytesN harus 1–32 dengan padding nol di kanan")
            decoded = "0x" + word[:size].hex()
        else:
            raise OrbitError(
                "Tipe yang didukung: uintN, intN, address, bool, bytesN; tipe dinamis belum didukung"
            )
        result.append({"index": index, "type": kind, "hex": word.hex(), "value": decoded})
    return {"selector": prefix, "words": result, "flags": find_flags(data)}


OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


def evm_disassemble(value: str) -> dict:
    data = hex_bytes(value)
    if len(data) > 65536:
        raise OrbitError("EVM bytecode maksimal 64 KiB")
    pos, result = 0, []
    while pos < len(data):
        opcode, start = data[pos], pos
        pos += 1
        if 0x60 <= opcode <= 0x7F:
            size = opcode - 0x5F
            operand = data[pos : pos + size]
            result.append(
                {
                    "offset": start,
                    "opcode": f"PUSH{size}",
                    "operand": "0x" + operand.hex(),
                    "truncated": len(operand) < size,
                }
            )
            pos += size
        else:
            name = (
                f"DUP{opcode - 0x7F}"
                if 0x80 <= opcode <= 0x8F
                else f"SWAP{opcode - 0x8F}"
                if 0x90 <= opcode <= 0x9F
                else f"LOG{opcode - 0xA0}"
                if 0xA0 <= opcode <= 0xA4
                else OPCODES.get(opcode, f"OP_{opcode:02X}")
            )
            result.append({"offset": start, "opcode": name})
    return {
        "instructions": result,
        "note": "Disassembler saja, tanpa eksekusi; opcode tidak dikenal diberi OP_XX",
    }
