#!/usr/bin/env python3
"""Create a deterministic source ZIP with one root folder and SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    ".qa-venv",
    ".core-venv",
    "__pycache__",
    ".ruff_cache",
    "reports",
    "challenges",
    "build",
    "dist",
    "wheelhouse",
}


def sources(root: Path, output: Path) -> list[Path]:
    selected = []
    for file in root.rglob("*"):
        relative = file.relative_to(root)
        if any(part in EXCLUDED or part.endswith(".egg-info") for part in relative.parts):
            continue
        if file.is_symlink() or not file.is_file() or file.resolve() == output.resolve():
            continue
        if file.name == "CHECKSUMS.sha256" or file.suffix in (".pyc", ".pyo", ".log"):
            continue
        if file.name == ".env" or file.name.startswith(".env."):
            continue
        selected.append(file)
    return sorted(selected, key=lambda p: p.relative_to(root).as_posix())


def package(output: Path, force: bool = False) -> dict:
    output = output.resolve()
    if output.is_symlink():
        raise ValueError("Output tidak boleh berupa symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not force:
        raise FileExistsError("ZIP sudah ada; gunakan path baru atau --force")
    files = sources(ROOT, output)
    manifest = "".join(
        f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.relative_to(ROOT).as_posix()}\n"
        for file in files
    )
    manifest_path = ROOT / "CHECKSUMS.sha256"
    if manifest_path.is_symlink():
        raise ValueError("Manifest tidak boleh berupa symlink")
    manifest_path.write_text(manifest, encoding="utf-8", newline="\n")
    files.append(manifest_path)
    files.sort(key=lambda file: file.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(
        output, "w" if force else "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for file in files:
            name = "ctf-orbit/" + file.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if file.suffix == ".sh" else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, file.read_bytes(), compresslevel=9)
    return {
        "output": str(output),
        "files": len(files),
        "size_bytes": output.stat().st_size,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "ctf-orbit-v1.0.0.zip")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.output, args.force), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
