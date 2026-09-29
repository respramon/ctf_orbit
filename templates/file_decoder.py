#!/usr/bin/env python3
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
