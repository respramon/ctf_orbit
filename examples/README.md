# Artefak latihan

`data/` berisi 20 file sintetik untuk menguji dan mempelajari command secara
offline. Jangan mengganti fixture ini dengan artefak lomba aktif yang belum
boleh dipublikasikan. Hasil latihan ada di `docs/RECIPES.md`.

| Folder | Artefak | Hasil/petunjuk |
|---|---|---|
| `misc/` | `layers.txt`, `hello.bf` | Base64→hex; Brainfuck menghasilkan `A` |
| `crypto/` | `xor.bin`, `rsa.json` | XOR key `42`; RSA textbook plaintext `Hi` |
| `forensics/` | `memory.bin`, `evidence.zip`, `carrier.bin` | ASCII/UTF-16, ZIP sample, PNG offset 14 |
| `reverse/` | `sample.elf`, `sample.exe`, `x64.raw` | Header binary dan instruksi pendek x64 |
| `network/` | `traffic.pcap` | TCP out-of-order/retransmission, UDP dan DNS |
| `osint/` | `page.html` | Komentar flag, URL/email/handle/IP contoh |
| `mobile/` | `classes.dex`, `AndroidManifest.axml`, `challenge.apk` | String DEX, manifest string pool, ZIP APK |
| `blockchain/` | `Challenge.sol` | String flag dan petunjuk `tx.origin` |
| `hardware/` | `firmware.bin`, `firmware.hex` | Firmware string/magic dan Intel HEX dengan checksum |
| `stego/` | `audio.wav`, `hidden.png` | Sample/pixel LSB |

`web_lab.py` adalah server HTTP terikat `127.0.0.1`. `echo.c` adalah fixture
I/O C dengan input dibatasi, untuk template proses lokal pwntools.

Fixture APK/DEX/AXML/ELF/PE cukup untuk subset parser yang diuji; tidak
dimaksudkan sebagai aplikasi terpasang atau binary produksi. Signature
SquashFS pada contoh firmware hanya petunjuk magic. Generator bersifat
deterministik dan tidak mengambil data dari internet.

```bash
python scripts/generate_examples.py --directory examples/data
```
