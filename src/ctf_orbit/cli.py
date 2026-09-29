"""Argparse CLI. Commands print JSON; --out also writes JSON and Markdown."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import platform
import shutil
import sys
from pathlib import Path

from . import (
    __version__,
    artifacts,
    binary,
    blockchain,
    codecs,
    crypto,
    hardware,
    mobile,
    network,
    osint,
    pipeline,
    pwn,
    stego,
    templates,
    web,
)
from .common import (
    DEFAULT_PREFIXES,
    OrbitError,
    emit,
    find_flags,
    hex_bytes,
    parse_int,
    preview,
    read_file,
    strings,
    write_new,
)


def _report(parser):
    parser.add_argument(
        "--out", metavar="DIRECTORY", help="Simpan report.json dan report.md (direktori baru)"
    )
    return parser


def _input(parser, hex_option=False):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Input UTF-8 literal")
    group.add_argument("--file", help="Baca input dari file")
    if hex_option:
        group.add_argument("--hex", help="Input dalam bentuk hex")


def _prefixes(args):
    return tuple(DEFAULT_PREFIXES) + tuple(getattr(args, "flag_prefix", None) or ())


def _data(args, limit=32 * 1024 * 1024):
    if getattr(args, "file", None):
        return read_file(args.file, limit)
    if getattr(args, "hex", None) is not None:
        data = hex_bytes(args.hex)
    else:
        data = args.text.encode("utf-8")
    if len(data) > limit:
        raise OrbitError(f"Input melebihi {limit} byte")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-orbit", description="Otomasi triase CTF lintas kategori; panduan: docs/USAGE.md"
    )
    parser.add_argument("--version", action="version", version=f"CTF Orbit {__version__}")
    groups = parser.add_subparsers(dest="command", required=True)

    p = _report(groups.add_parser("doctor", help="Periksa Python, extras dan tool eksternal"))
    p = _report(groups.add_parser("analyze", help="Triase otomatis satu file atau direktori lokal"))
    p.add_argument("path")
    p.add_argument("--category", choices=("auto", "all", *pipeline.CATEGORIES), default="auto")
    p.add_argument("--recursive", action="store_true")
    p.add_argument("--max-files", type=int, default=50)
    p.add_argument("--max-size-mib", type=int, default=32)
    p.add_argument(
        "--flag-prefix", action="append", help="Tambahkan prefix literal, contoh GEMASTIK"
    )
    p = _report(groups.add_parser("init", help="Buat workspace challenge dan solver awal"))
    p.add_argument("name")
    p.add_argument("--directory")
    p.add_argument("--category", choices=pipeline.CATEGORIES, default="misc")
    p.add_argument("--url")

    parent = groups.add_parser("misc", help="Decode, flag, Morse, Brainfuck")
    sub = parent.add_subparsers(dest="action", required=True)
    p = _report(sub.add_parser("decode"))
    _input(p)
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--max-nodes", type=int, default=128)
    p.add_argument("--flag-prefix", action="append")
    p = _report(sub.add_parser("flags"))
    p.add_argument("file")
    p.add_argument("--flag-prefix", action="append")
    p = _report(sub.add_parser("morse"))
    p.add_argument("text")
    p = _report(sub.add_parser("brainfuck"))
    _input(p)
    p.add_argument("--input", default="")
    p.add_argument("--max-steps", type=int, default=200000)

    parent = groups.add_parser("crypto", help="Caesar, Vigenere, XOR, RSA, format hash")
    sub = parent.add_subparsers(dest="action", required=True)
    p = _report(sub.add_parser("caesar"))
    p.add_argument("text")
    p.add_argument("--shift", type=int)
    p = _report(sub.add_parser("vigenere"))
    p.add_argument("text")
    p.add_argument("--key", required=True)
    p.add_argument("--encrypt", action="store_true")
    p = _report(sub.add_parser("xor"))
    _input(p, hex_option=True)
    key = p.add_mutually_exclusive_group()
    key.add_argument("--key-hex")
    key.add_argument("--key-text")
    p.add_argument("--top", type=int, default=10)
    p = _report(sub.add_parser("rsa"))
    for option in ("n", "e", "c"):
        p.add_argument("--" + option, required=True, type=parse_int)
    p.add_argument("--p", type=parse_int)
    p.add_argument("--q", type=parse_int)
    p.add_argument("--trial-limit", type=int, default=100000)
    p.add_argument("--fermat-steps", type=int, default=0)
    p = _report(sub.add_parser("hash"))
    p.add_argument("text")

    parent = groups.add_parser("forensics", help="Metadata, strings, arsip, carving")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("inspect", "strings", "carve"):
        p = _report(sub.add_parser(action))
        p.add_argument("file")
        if action == "strings":
            p.add_argument("--min", type=int, default=4)
            p.add_argument("--max", type=int, default=500)
        elif action == "carve":
            p.add_argument("--offset", type=parse_int, default=0)
            p.add_argument("--length", type=parse_int)
            p.add_argument("--signature", choices=("png", "jpeg", "zip", "pdf"))
            p.add_argument("--save", required=True)

    parent = groups.add_parser("reverse", help="ELF/PE dan disassembly raw bytes")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("inspect", "disasm"):
        p = _report(sub.add_parser(action))
        p.add_argument("file")
        if action == "disasm":
            p.add_argument("--arch", choices=("x86", "x64", "arm", "arm64"), required=True)
            p.add_argument("--offset", type=parse_int, default=0)
            p.add_argument("--bytes", type=int, default=256)
            p.add_argument("--base", type=parse_int, default=0)
            p.add_argument("--thumb", action="store_true")

    parent = groups.add_parser("pwn", help="Cyclic, offset, pack/unpack, template lokal")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("cyclic", "offset"):
        p = _report(sub.add_parser(action))
        p.add_argument("--n", type=int, default=4)
        p.add_argument("--alphabet", default="abcdefghijklmnopqrstuvwxyz")
        if action == "cyclic":
            p.add_argument("--length", type=int, default=200)
            p.add_argument("--save")
        else:
            p.add_argument("value")
            p.add_argument("--encoding", choices=("text", "hex", "int"), default="text")
            p.add_argument("--endian", choices=("little", "big"), default="little")
            p.add_argument("--max-length", type=int, default=1000000)
    p = _report(sub.add_parser("pack"))
    p.add_argument("value", type=parse_int)
    p.add_argument("--bits", type=int, choices=(8, 16, 32, 64), default=64)
    p.add_argument("--endian", choices=("little", "big"), default="little")
    p = _report(sub.add_parser("unpack"))
    p.add_argument("hex")
    p.add_argument("--endian", choices=("little", "big"), default="little")
    p = _report(sub.add_parser("template"))
    p.add_argument("--directory", required=True)

    parent = groups.add_parser("stego", help="Metadata gambar/WAV, LSB dan bit planes")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("inspect", "image-lsb", "wav-lsb", "planes"):
        p = _report(sub.add_parser(action))
        p.add_argument("file")
        if action in ("image-lsb", "wav-lsb"):
            p.add_argument("--plane", type=int, default=0)
            p.add_argument("--bit-order", choices=("msb", "lsb"), default="msb")
            p.add_argument("--limit-bytes", type=int, default=131072)
            p.add_argument("--save")
            if action == "image-lsb":
                p.add_argument("--channels", default="rgb")
                p.add_argument("--skip-bits", type=int, default=0)
            else:
                p.add_argument("--channel", type=int, help="Indeks channel mulai 0; default semua")
        if action == "planes":
            p.add_argument("--channel", choices=tuple("rgba"), default="r")
            p.add_argument("--directory", required=True)

    parent = groups.add_parser("network", help="Analisis PCAP klasik offline")
    sub = parent.add_subparsers(dest="action", required=True)
    p = _report(sub.add_parser("pcap"))
    p.add_argument("file")
    p.add_argument("--max-packets", type=int, default=5000)
    p.add_argument("--save-streams")

    parent = groups.add_parser("web", help="Inspeksi URL, path, HTML lokal dan JWT")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("inspect", "paths"):
        p = _report(sub.add_parser(action))
        p.add_argument("url")
        p.add_argument("--timeout", type=float, default=8)
        p.add_argument("--max-bytes", type=int, default=1048576)
        if action == "paths":
            source = p.add_mutually_exclusive_group()
            source.add_argument("--wordlist")
            source.add_argument("--path", action="append", help="Ulangi opsi untuk beberapa path")
            p.add_argument("--max-requests", type=int, default=20)
            p.add_argument("--delay", type=float, default=0.2)
    p = _report(sub.add_parser("jwt"))
    p.add_argument("token")
    p = _report(sub.add_parser("html"))
    p.add_argument("file")

    parent = groups.add_parser("osint", help="Ekstrak petunjuk URL/email/domain dari file lokal")
    sub = parent.add_subparsers(dest="action", required=True)
    p = _report(sub.add_parser("inspect"))
    p.add_argument("file")

    parent = groups.add_parser("mobile", help="APK, DEX dan string pool manifest Android")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("apk", "dex", "manifest"):
        p = _report(sub.add_parser(action))
        p.add_argument("file")

    parent = groups.add_parser("blockchain", help="Source Solidity, selector, ABI dan EVM")
    sub = parent.add_subparsers(dest="action", required=True)
    p = _report(sub.add_parser("inspect"))
    p.add_argument("file")
    p = _report(sub.add_parser("selector"))
    p.add_argument("signature")
    p = _report(sub.add_parser("abi"))
    p.add_argument("--hex", required=True)
    p.add_argument("--types", help="Tipe statis dipisah koma, contoh uint256,address,bool")
    p.add_argument("--has-selector", action="store_true")
    p = _report(sub.add_parser("evm"))
    p.add_argument("--hex", required=True)

    parent = groups.add_parser("hardware", help="Firmware dan konversi Intel HEX")
    sub = parent.add_subparsers(dest="action", required=True)
    for action in ("inspect", "ihex"):
        p = _report(sub.add_parser(action))
        p.add_argument("file")
        if action == "ihex":
            p.add_argument("--save")
    return parser


def doctor() -> dict:
    dependencies = {}
    for package, module, extra in (
        ("Pillow", "PIL", "image"),
        ("pycryptodome", "Crypto", "crypto"),
        ("capstone", "capstone", "reverse"),
        ("pwntools", "pwn", "pwn"),
    ):
        available = importlib.util.find_spec(module) is not None
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            version = None
        dependencies[extra] = {"available": available, "version": version}
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "core_ready": sys.version_info >= (3, 11),
        "optional_dependencies": dependencies,
        "external_tools": {
            name: shutil.which(name)
            for name in (
                "file",
                "readelf",
                "objdump",
                "strings",
                "exiftool",
                "tshark",
                "binwalk",
                "gdb",
                "rizin",
                "radare2",
                "jadx",
                "zbarimg",
            )
        },
        "note": "Tool eksternal hanya dideteksi, tidak dijalankan. Inti dapat berjalan tanpa extras.",
    }


def dispatch(args) -> dict:
    command, action = args.command, getattr(args, "action", None)
    if command == "doctor":
        return doctor()
    if command == "analyze":
        return pipeline.analyze(
            args.path,
            args.category,
            args.recursive,
            args.max_files,
            args.max_size_mib,
            _prefixes(args),
        )
    if command == "init":
        return templates.init_challenge(args.name, args.directory, args.category, args.url)
    if command == "misc":
        if action == "decode":
            return codecs.decode_layers(
                _data(args, 256 * 1024), args.depth, args.max_nodes, _prefixes(args)
            )
        if action == "flags":
            data = read_file(args.file)
            extracted = strings(data, maximum=1000)
            flags = set(find_flags(data, _prefixes(args)))
            for item in extracted:
                flags.update(find_flags(item["text"], _prefixes(args)))
            return {"flags": sorted(flags), "bytes_scanned": len(data)}
        if action == "morse":
            text = codecs.morse_decode(args.text)
            return {"text": text, "flags": find_flags(text)}
        return codecs.brainfuck(
            _data(args, 256 * 1024).decode("utf-8"), args.input.encode(), args.max_steps
        )
    if command == "crypto":
        if action == "caesar":
            return crypto.caesar(args.text, args.shift)
        if action == "vigenere":
            return crypto.vigenere(args.text, args.key, args.encrypt)
        if action == "xor":
            key = (
                hex_bytes(args.key_hex)
                if args.key_hex is not None
                else args.key_text.encode()
                if args.key_text is not None
                else None
            )
            return crypto.xor(_data(args, 65536), key, args.top)
        if action == "rsa":
            return crypto.rsa(
                args.n, args.e, args.c, args.p, args.q, args.trial_limit, args.fermat_steps
            )
        return crypto.hash_identify(args.text)
    if command == "forensics":
        data = read_file(args.file)
        if action == "inspect":
            return artifacts.inspect(data, args.file)
        if action == "strings":
            result = strings(data, args.min, args.max)
            return {
                "strings": result,
                "flags": sorted({f for item in result for f in find_flags(item["text"])}),
            }
        return artifacts.carve(data, args.offset, args.save, args.length, args.signature)
    if command == "reverse":
        data = read_file(args.file)
        return (
            binary.inspect(data)
            if action == "inspect"
            else binary.disassemble(data, args.arch, args.offset, args.bytes, args.base, args.thumb)
        )
    if command == "pwn":
        if action == "cyclic":
            raw = pwn.cyclic(args.length, args.alphabet, args.n)
            result = {"n": args.n, "alphabet": args.alphabet, **preview(raw)}
            if args.save:
                result["saved"] = write_new(args.save, raw)
            return result
        if action == "offset":
            return pwn.offset(
                args.value, args.encoding, args.endian, args.n, args.alphabet, args.max_length
            )
        if action == "pack":
            return pwn.pack(args.value, args.bits, args.endian)
        if action == "unpack":
            return pwn.unpack(hex_bytes(args.hex), args.endian)
        return templates.pwn_template(args.directory)
    if command == "stego":
        data = read_file(args.file)
        if action == "inspect":
            return (
                stego.wav_info(data)
                if artifacts.detect_type(data) == "wav"
                else stego.image_info(data)
            )
        if action == "planes":
            return stego.bit_planes(data, args.directory, args.channel)
        if action == "image-lsb":
            raw = stego.image_lsb(
                data, args.channels, args.plane, args.bit_order, args.skip_bits, args.limit_bytes
            )
        else:
            raw = stego.wav_lsb(data, args.channel, args.plane, args.bit_order, args.limit_bytes)
        return stego.extraction_result(raw, args.save)
    if command == "network":
        return network.inspect(read_file(args.file), args.max_packets, args.save_streams)
    if command == "web":
        if action == "jwt":
            return web.jwt_inspect(args.token)
        if action == "html":
            return web.html_info(read_file(args.file, 1048576).decode("utf-8", "replace"))
        if action == "inspect":
            return web.fetch(args.url, args.timeout, args.max_bytes)
        entries = (
            read_file(args.wordlist, 65536).decode("utf-8").splitlines()
            if args.wordlist
            else args.path
            or ["/", "/robots.txt", "/sitemap.xml", "/admin", "/.well-known/security.txt"]
        )
        return web.paths(
            args.url, entries, args.max_requests, args.delay, args.timeout, args.max_bytes
        )
    if command == "osint":
        return osint.inspect(read_file(args.file, 1048576))
    if command == "mobile":
        data = read_file(args.file)
        if action == "apk":
            return mobile.inspect(data)
        values = mobile.dex_strings(data) if action == "dex" else mobile.axml_strings(data)
        return {"strings": values, "flags": find_flags("\n".join(values))}
    if command == "blockchain":
        if action == "selector":
            return blockchain.selector(args.signature)
        if action == "abi":
            return blockchain.abi_decode(
                args.hex,
                [t.strip() for t in args.types.split(",")] if args.types else None,
                args.has_selector,
            )
        if action == "evm":
            return blockchain.evm_disassemble(args.hex)
        return blockchain.inspect(read_file(args.file, 1048576))
    if command == "hardware":
        data = read_file(args.file)
        return (
            hardware.inspect(data, args.file)
            if action == "inspect"
            else hardware.intel_hex(data.decode("ascii"), args.save)
        )
    raise OrbitError("Command tidak dikenal")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        print("CTF Orbit membutuhkan Python 3.11+", file=sys.stderr)
        return 2
    try:
        if args.out and any(
            (Path(args.out) / name).exists() or (Path(args.out) / name).is_symlink()
            for name in ("report.json", "report.md")
        ):
            raise OrbitError("Laporan sudah ada; gunakan direktori --out yang baru")
        result = dispatch(args)
        name = " ".join(filter(None, (args.command, getattr(args, "action", ""))))
        report = emit(result, name, args.out)
        if args.out:
            report = {
                "saved_reports": [
                    str((Path(args.out) / file).resolve()) for file in ("report.json", "report.md")
                ],
                "flags": result.get("flags", []),
            }
            if args.command == "analyze":
                report.update(
                    {k: result[k] for k in ("files_analyzed", "file_limit_reached", "errors")}
                )
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 1 if args.command == "analyze" and result.get("errors") else 0
    except (OrbitError, OSError, UnicodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
