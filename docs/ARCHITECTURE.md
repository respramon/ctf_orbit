# Arsitektur dan API

## Lapisan kode

| Modul | Tanggung jawab |
|---|---|
| `cli.py` | Parsing argparse, validasi boundary command, dispatch, stdout/error, exit code |
| `common.py` | Bounded I/O, exclusive write, flag, hashes/entropy, strings, report JSON/Markdown |
| `pipeline.py` | Routing format/kategori, traversal direktori, triase lokal, status per modul |
| `codecs.py` | BFS decoding dan interpreter Brainfuck bounded |
| `artifacts.py` | Signature, ZIP/gzip sample, strings dan carving |
| `crypto.py` | Classical ciphers, XOR scoring, helper RSA, hash format |
| `binary.py` | ELF/PE metadata dan Capstone |
| `pwn.py` | Streaming de Bruijn, offset dan integer packing |
| `stego.py` | Pillow lazy import, RGBA bit extraction, WAV PCM |
| `network.py` | Classic PCAP, L2/IP/TCP/UDP, DNS, directional reconstruction |
| `web.py` | Bounded single-origin GET, HTML parser, offline JWT |
| `osint.py` | Ekstraksi petunjuk dari teks lokal |
| `mobile.py` | ZIP APK, AXML string pool, DEX string IDs |
| `blockchain.py` | Solidity regex clues, Keccak, static ABI, EVM disassembly |
| `hardware.py` | Firmware clues dan Intel HEX parser |
| `templates.py` | Template solver yang ikut wheel, workspace initializer |

Semua parser menerima bytes/string dan mengembalikan dict yang dapat
di-serialize. Operasi tulis hanya terjadi pada command yang meminta ekspor,
workspace init, atau report output. Import modul tidak menjalankan binary,
shell, jaringan, atau installer dependency.

## Jalur eksekusi

1. CLI membaca opsi dan memeriksa tujuan laporan agar tidak menimpa hasil.
2. Dispatch membaca input dengan ukuran maksimum.
3. Command menjalankan satu fungsi kategori, atau pipeline memilih modul.
4. Fungsi mengembalikan dict dengan hasil dan keterbatasan/sampel.
5. `emit()` menambahkan metadata dan menulis JSON/Markdown jika diminta.
6. CLI menampilkan JSON lengkap atau ringkasan hasil tersimpan.

`analyze` tidak memanggil command web HTTP. Kategori `web` dalam pipeline
berarti parsing **HTML lokal**, sehingga URL pada artefak tidak di-fetch.

## Schema laporan v1

Contoh struktur yang disederhanakan (bukan salinan laporan nyata):

```json
{
  "schema_version": 1,
  "tool_version": "1.0.0",
  "command": "analyze",
  "generated_at": "2026-09-30T00:00:00+00:00",
  "target": "examples/data",
  "category": "auto",
  "files_analyzed": 20,
  "file_limit_reached": false,
  "flags": ["ORBIT{layered_decode}"],
  "files": [
    {
      "path": "examples/data/misc/layers.txt",
      "detected_type": "text",
      "categories": ["forensics", "misc", "crypto", "osint"],
      "modules": {
        "misc": {"status": "ok", "result": {"flags": ["ORBIT{layered_decode}"]}}
      },
      "module_errors": []
    }
  ],
  "errors": []
}
```

Timestamp selalu UTC ISO 8601. Field hasil berbeda per command. Integer
besar RSA/ABI disimpan sebagai string decimal. `null` dipakai jika nilai
belum diketahui, misalnya offset tidak ditemukan atau status NX tanpa
header. Hasil parser dapat diberi `skipped` pada pipeline; command langsung
menyajikan error ke stderr dan exit 2.

`errors` pada level pipeline memuat kegagalan baca file. `module_errors`
memuat kategori yang tidak bisa diproses. Ini dibedakan agar satu file
malformed tidak menghentikan analisis artefak lain yang bisa dibaca.

## Batas resource

| Operasi | Batas |
|---|---|
| File command langsung | Default 32 MiB; command teks tertentu lebih kecil |
| Pipeline file | Default 32 MiB, dapat 1–128 MiB |
| Direktori | Default 50 file, maksimum 500; traversal 10.000 entri |
| Decode langsung | 256 KiB, depth<=8, nodes<=512 |
| Auto decode | Maksimal 16 potongan, 48 node/potongan, depth 4 |
| XOR search | Input<=64 KiB; auto memakai sampel awal 2 KiB |
| RSA | Integer<=8192 bit, trial divisor/Fermat steps<=1.000.000 |
| ZIP | <=5.000 entri, central directory<=8 MiB, sample total<=2 MiB |
| Gzip | Decompressed sample<=2 MiB |
| Image | <=8.000.000 piksel; LSB output<=1 MiB |
| PCAP | <=20.000 paket, <=512 directional flow, payload TCP total<=2 MiB |
| HTTP | <=100 request/batch, <=4 MiB body/request, delay>=0,05 detik |
| APK | <=10 DEX, <=8 MiB/manifest atau DEX, <=5.000 string/DEX |
| ABI / EVM | Input<=64 KiB |
| Intel HEX | Data/span<=4 MiB |
| Brainfuck | Tape 30.000, steps<=2.000.000, output<=65.536 byte |

Batas tersebut mengendalikan pekerjaan parser, bukan sandbox eksekusi
kode atau jaminan CPU/memori untuk setiap format pihak ketiga. Pillow
digunakan dengan pemeriksaan pixel count dan decompression warnings; frame
pertama dianalisis. Pipeline sengaja tidak menjalankan program dari artefak.

## API sebagai library Python

```python
from ctf_orbit.codecs import decode_layers
from ctf_orbit.common import read_file
from ctf_orbit.pipeline import analyze

decoded = decode_layers(b"T1JCSVQ=", depth=3)
triage = analyze("./artifacts", recursive=True, max_files=20)
raw = read_file("challenge.bin", limit=1024 * 1024)
print(decoded["candidates"][0])
```

API belum mempunyai jaminan stabil di luar release 1.x. `OrbitError` adalah
error input/format yang diharapkan; fungsi write dapat mengeluarkan
`OSError/FileExistsError`. CLI menanganinya. Caller yang memakai API perlu
menangani keduanya.

## Menambah kemampuan

1. Tambahkan fungsi pada modul terkait dengan input bytes dan output dict.
2. Batasi ukuran/iterasi dan gunakan `OrbitError` untuk format yang ditolak.
3. Hindari subprocess/shell dalam `analyze`.
4. Tambahkan subcommand di `build_parser()` dan branch di `dispatch()`.
5. Jika cocok untuk auto, tambahkan kondisi `route()`/`analyze_bytes()`.
6. Tambahkan fixture kecil, hasil yang diketahui, dan tes malformed/boundary
   yang relevan. Hindari tes yang hanya menyalin implementasi.
7. Perbarui tabel cakupan dan panduan penggunaan.

Dependency opsional harus di-import di fungsi yang memerlukannya, sehingga
inti tetap berjalan pada instalasi tanpa extras. Tidak ada plugin discovery
yang mengeksekusi module arbitrary dari direktori challenge.

