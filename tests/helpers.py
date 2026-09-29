"""Paths and fixture imports for stdlib unittest discovery."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

HAS_IMAGE = importlib.util.find_spec("PIL") is not None
HAS_CRYPTO = importlib.util.find_spec("Crypto") is not None
HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None
HAS_PWN = importlib.util.find_spec("pwn") is not None
