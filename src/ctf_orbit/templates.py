"""Templates shipped inside the Python package, including wheel installations."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .common import OrbitError, write_new
from .web import validate_url

PWN_TEMPLATE = '''#!/usr/bin/env python3
"""Harness lokal pwntools. Menjalankan binary hanya saat script ini dipanggil."""
import argparse
from pwn import context, process

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Path binary latihan yang akan dijalankan")
    parser.add_argument("--line", default="hello", help="Input contoh; sesuaikan protokol challenge")
    parser.add_argument("--timeout", type=float, default=2)
    args = parser.parse_args()
    context.log_level = "error"
    with process([args.binary]) as io:
        io.sendline(args.line.encode())
        print(repr(io.recvrepeat(args.timeout)))

if __name__ == "__main__":
    main()
'''

SOLVE_TEMPLATE = '''#!/usr/bin/env python3
"""Titik awal solver file lokal: python solve.py input.txt."""
import argparse
import json
from ctf_orbit.codecs import decode_layers
from ctf_orbit.common import read_file

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    result = decode_layers(read_file(args.file, 256 * 1024))
    print(json.dumps(result, indent=2, ensure_ascii=True))

if __name__ == "__main__":
    main()
'''


def pwn_template(directory: str) -> dict:
    destination = Path(directory) / "solve.py"
    return {
        "saved": write_new(destination, PWN_TEMPLATE.encode()),
        "note": "Template lokal memerlukan extra pwn. Periksa binary sebelum menjalankan harness.",
    }


def init_challenge(name: str, directory: str | None, category: str, url: str | None = None) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise OrbitError("Nama challenge harus berupa slug 1–64 karakter")
    if url:
        url = validate_url(url)
    folder = Path(directory or f"challenges/{name}")
    folder.mkdir(parents=True, exist_ok=False)
    metadata = {"name": name, "category": category, "challenge_url": url, "status": "in-progress"}
    saved = [write_new(folder / "challenge.json", (json.dumps(metadata, indent=2) + "\n").encode())]
    notes = f"""# {name}

Kategori: {category}

## Deskripsi challenge

Tuliskan deskripsi dan format flag dari penyelenggara.

## Artefak dan batas target

Catat file, hash SHA-256, serta URL/host lab yang diberikan.

## Hasil triase

Simpan hasil `ctf-orbit analyze artifacts --recursive --out reports/triage-01`.

## Hipotesis dan langkah

Catat input, alasan mencoba, output, dan keputusan berikutnya.

## Solver dan flag

Dokumentasikan cara mereproduksi hasil. Periksa aturan lomba sebelum membagikan flag/writeup.
"""
    saved.append(write_new(folder / "README.md", notes.encode()))
    saved.append(
        write_new(
            folder / "solve.py", (PWN_TEMPLATE if category == "pwn" else SOLVE_TEMPLATE).encode()
        )
    )
    (folder / "artifacts").mkdir()
    (folder / "reports").mkdir()
    return {"directory": str(folder.resolve()), "saved": saved, "metadata": metadata}
