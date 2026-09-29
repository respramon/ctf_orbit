#!/usr/bin/env bash
set -euo pipefail

orbit_mode="${1:-full}"
case "$orbit_mode" in
  core) orbit_extras="" ;;
  standard) orbit_extras="image,crypto,reverse" ;;
  full) orbit_extras="full" ;;
  dev) orbit_extras="full,dev" ;;
  *) echo "Penggunaan: bash scripts/install.sh {core|standard|full|dev}" >&2; exit 2 ;;
esac

orbit_repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
orbit_python="${CTF_ORBIT_PYTHON:-python3}"
"$orbit_python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Butuh Python 3.11+")'
cd "$orbit_repo"
"$orbit_python" -m venv .venv
orbit_venv_python="$orbit_repo/.venv/bin/python"
"$orbit_venv_python" -m pip install --upgrade pip
if [ -n "$orbit_extras" ]; then
  "$orbit_venv_python" -m pip install -e ".[${orbit_extras}]"
else
  "$orbit_venv_python" -m pip install -e .
fi
"$orbit_venv_python" -m ctf_orbit doctor
echo "Selesai. Aktifkan: source .venv/bin/activate"

