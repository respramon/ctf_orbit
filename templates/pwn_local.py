#!/usr/bin/env python3
"""Harness lokal pwntools. Menjalankan binary hanya saat script ini dipanggil."""

import argparse
from pwn import context, process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Path binary latihan yang akan dijalankan")
    parser.add_argument(
        "--line", default="hello", help="Input contoh; sesuaikan protokol challenge"
    )
    parser.add_argument("--timeout", type=float, default=2)
    args = parser.parse_args()
    context.log_level = "error"
    with process([args.binary]) as io:
        io.sendline(args.line.encode())
        print(repr(io.recvrepeat(args.timeout)))


if __name__ == "__main__":
    main()
