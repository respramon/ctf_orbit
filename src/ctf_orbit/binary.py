"""Static ELF/PE metadata and optional Capstone raw-byte disassembly."""

from __future__ import annotations

import struct

from .common import OrbitError, bounded, find_flags, strings


def _unpack(fmt: str, data: bytes, offset: int):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise OrbitError("Struktur binary terpotong atau offset tidak valid")
    return struct.unpack_from(fmt, data, offset)


def elf_info(data: bytes) -> dict:
    if len(data) < 16 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise OrbitError("Header ELF tidak valid")
    bits = 32 if data[4] == 1 else 64
    endian = "<" if data[5] == 1 else ">"
    header = _unpack(endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"), data, 16)
    kind, machine, _, entry, phoff, shoff, _, _, phsize, phnum, shsize, shnum, names_idx = header
    if phnum > 4096 or shnum > 4096:
        raise OrbitError("Tabel ELF terlalu besar; extended numbering belum didukung")
    if phnum and phsize < (32 if bits == 32 else 56):
        raise OrbitError("Ukuran program header ELF tidak valid")
    if shnum and shsize < (40 if bits == 32 else 64):
        raise OrbitError("Ukuran section header ELF tidak valid")
    programs, nx, relro, bind_now = [], None, False, False
    interpreter = False
    for index in range(phnum):
        values = _unpack(
            endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), data, phoff + index * phsize
        )
        if bits == 32:
            ptype, off, vaddr, _, filesz, memsz, flags, _ = values
        else:
            ptype, flags, off, vaddr, _, filesz, memsz, _ = values
        programs.append(
            {
                "type": hex(ptype),
                "file_offset": off,
                "virtual_address": hex(vaddr),
                "file_size": filesz,
                "memory_size": memsz,
                "flags": flags,
            }
        )
        if ptype == 0x6474E551:
            nx = not bool(flags & 1)
        if ptype == 0x6474E552:
            relro = True
        if ptype == 3:
            interpreter = True
        if ptype == 2:
            if off + filesz > len(data):
                raise OrbitError("Dynamic table ELF keluar dari file")
            step = 8 if bits == 32 else 16
            for pos in range(off, off + min(filesz, step * 4096) - step + 1, step):
                tag, value = _unpack(endian + ("II" if bits == 32 else "QQ"), data, pos)
                if tag == 0:
                    break
                bind_now |= (
                    tag == 24
                    or (tag == 30 and bool(value & 8))
                    or (tag == 0x6FFFFFFB and bool(value & 1))
                )
    sections = []
    for index in range(shnum):
        section = _unpack(
            endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"), data, shoff + index * shsize
        )
        sections.append(section)
    names = b""
    if sections and names_idx < len(sections):
        table = sections[names_idx]
        if table[4] + table[5] <= len(data):
            names = data[table[4] : table[4] + min(table[5], 1024 * 1024)]

    def name_at(table: bytes, off: int) -> str:
        if off >= len(table):
            return ""
        end = table.find(b"\x00", off, min(len(table), off + 512))
        return table[off : end if end >= 0 else min(len(table), off + 512)].decode(
            "utf-8", "replace"
        )

    symbols = []
    for section in sections:
        if section[1] not in (2, 11) or section[6] >= len(sections) or not section[9]:
            continue
        link = sections[section[6]]
        if link[4] + link[5] > len(data) or section[4] + section[5] > len(data):
            raise OrbitError("Symbol/string table ELF keluar dari file")
        table = data[link[4] : link[4] + min(link[5], 2 * 1024 * 1024)]
        entry_size = section[9]
        if entry_size < (16 if bits == 32 else 24):
            raise OrbitError("Symbol entry ELF terlalu kecil")
        for pos in range(section[4], section[4] + section[5] - entry_size + 1, entry_size):
            if len(symbols) >= 300:
                break
            item = _unpack(endian + ("IIIBBH" if bits == 32 else "IBBHQQ"), data, pos)
            if bits == 32:
                nm, value, size, info, _, ndx = item
            else:
                nm, info, _, ndx, value, size = item
            symbol_name = name_at(table, nm)
            if symbol_name:
                symbols.append(
                    {
                        "name": symbol_name,
                        "address": hex(value),
                        "size": size,
                        "undefined": ndx == 0,
                        "kind": info & 15,
                    }
                )
    return {
        "format": "ELF",
        "bits": bits,
        "endian": "little" if endian == "<" else "big",
        "machine": {
            3: "x86",
            62: "x86-64",
            40: "ARM",
            183: "AArch64",
            8: "MIPS",
            243: "RISC-V",
        }.get(machine, str(machine)),
        "type": {1: "relocatable", 2: "executable", 3: "dynamic"}.get(kind, str(kind)),
        "entry": hex(entry),
        "program_headers": programs,
        "sections": [
            {
                "name": name_at(names, s[0]),
                "type": s[1],
                "offset": s[4],
                "size": s[5],
                "executable": bool(s[2] & 4),
            }
            for s in sections
        ],
        "symbols": symbols,
        "protections": {
            "NX_GNU_STACK": nx,
            "PIE_candidate": kind == 3 and interpreter,
            "RELRO": "full" if relro and bind_now else "partial" if relro else "none",
            "canary_symbol_present": b"__stack_chk_fail" in data,
        },
        "note": "Proteksi adalah indikator statis; canary tidak membuktikan semua fungsi terlindungi",
    }


def pe_info(data: bytes) -> dict:
    if not data.startswith(b"MZ"):
        raise OrbitError("Signature DOS MZ tidak ditemukan")
    (off,) = _unpack("<I", data, 0x3C)
    if data[off : off + 4] != b"PE\x00\x00":
        raise OrbitError("MZ tanpa header PE yang valid")
    machine, count, _, _, _, opt_size, characteristics = _unpack("<HHIIIHH", data, off + 4)
    if count > 256:
        raise OrbitError("PE melebihi 256 section")
    optional = off + 24
    (magic,) = _unpack("<H", data, optional)
    if magic not in (0x10B, 0x20B) or opt_size < 72 or optional + opt_size > len(data):
        raise OrbitError("Optional header PE tidak valid")
    (entry,) = _unpack("<I", data, optional + 16)
    (dll,) = _unpack("<H", data, optional + 70)
    (imagebase,) = _unpack(
        "<Q" if magic == 0x20B else "<I", data, optional + (24 if magic == 0x20B else 28)
    )
    sections = []
    for index in range(count):
        values = _unpack("<8sIIIIIIHHI", data, optional + opt_size + index * 40)
        name, vsize, vaddr, size, rawoff, _, _, _, _, flags = values
        sections.append(
            {
                "name": name.rstrip(b"\x00").decode("ascii", "replace"),
                "offset": rawoff,
                "raw_size": size,
                "rva": hex(vaddr),
                "virtual_size": vsize,
                "executable": bool(flags & 0x20000000),
            }
        )
    return {
        "format": "PE",
        "bits": 64 if magic == 0x20B else 32,
        "machine": {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine, hex(machine)),
        "image_base": hex(imagebase),
        "entry_rva": hex(entry),
        "characteristics": hex(characteristics),
        "sections": sections,
        "protections": {
            "ASLR_flag": bool(dll & 0x40),
            "NX_COMPAT_flag": bool(dll & 0x100),
            "GUARD_CF_flag": bool(dll & 0x4000),
        },
    }


def inspect(data: bytes) -> dict:
    result = {"strings": strings(data, maximum=200), "flags": find_flags(data)}
    if data.startswith(b"\x7fELF"):
        result.update(elf_info(data))
    elif data.startswith(b"MZ"):
        result.update(pe_info(data))
    else:
        result.update({"format": "unknown/raw", "note": "Parser header hanya mendukung ELF dan PE"})
    return result


def disassemble(
    data: bytes, arch: str, offset: int = 0, size: int = 256, base: int = 0, thumb: bool = False
) -> dict:
    bounded(size, 1, 65536, "Bytes disassembly")
    if not 0 <= offset < len(data):
        raise OrbitError("Offset disassembly di luar file")
    if thumb and arch != "arm":
        raise OrbitError("--thumb hanya untuk ARM")
    try:
        import capstone as cs
    except ImportError as exc:
        raise OrbitError('Pasang modul reverse: python -m pip install ".[reverse]"') from exc
    modes = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB if thumb else cs.CS_MODE_ARM),
        "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    }
    machine, mode = modes[arch]
    engine = cs.Cs(machine, mode)
    raw = data[offset : offset + size]
    instructions = [
        {
            "address": hex(ins.address),
            "bytes": ins.bytes.hex(),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        for ins in engine.disasm(raw, base)
    ]
    consumed = sum(len(bytes.fromhex(ins["bytes"])) for ins in instructions)
    return {
        "arch": arch,
        "file_offset": offset,
        "base_address": hex(base),
        "bytes_requested": size,
        "bytes_read": len(raw),
        "bytes_decoded": consumed,
        "instructions": instructions,
        "note": "Offset file mentah; tidak otomatis memetakan alamat ELF/PE",
    }
