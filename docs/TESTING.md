# Verifikasi paket

Verifikasi source 1.0.0 dilakukan pada 30 September 2026 (Asia/Bangkok),
dengan Linux x86-64 dan Python **3.12.14**. Hasil tes untuk profil penuh:
**64 tes berhasil, tanpa skip**. Pada venv core yang tidak memiliki extras:
**56 tes berhasil, 8 tes extras dilewati**. Keempat tes HTTP memakai server
yang terikat ke localhost dan tidak menghubungi target eksternal.

## Yang diverifikasi

| Area | Hasil |
|---|---|
| Instalasi editable full + dev | Berhasil melalui pip dan build isolation |
| Core tanpa third-party dependency | Doctor menyatakan seluruh extra tidak tersedia; core tests berhasil |
| Parser dan helper matematika | Vektor diketahui Caesar/Vigenere/XOR/RSA, integer packing, ABI/Keccak dan EVM berhasil |
| Forensics | ASCII/UTF-16, ZIP sample, penandaan path traversal, rasio kompresi, carving PNG exact-byte berhasil |
| Reverse | Fixture ELF/PE, GNU_STACK NX, section offset, Capstone x64 berhasil |
| Stego | PNG RGB LSB, WAV sample LSB, export 8 bit-plane berhasil |
| Network | PCAP big/little-endian micro/nanosecond, TCP out-of-order/overlap/retransmission/gap, UDP, IPv6, DNS berhasil |
| Web | GET localhost, batas body/request, penolakan path luar-origin dan redirect tidak diikuti berhasil |
| Mobile/hardware | DEX/AXML UTF-8/UTF-16, APK inventory, versi container ditolak, Intel HEX checksum/alamat berhasil |
| Input malformed/resource limit | Batas decoder, Brainfuck loop/pointer/bracket, file size, cyclic dan JWT nesting diperiksa |
| CLI dan report | Command kategori, exit error tanpa traceback, JSON/Markdown, file export, custom prefix dan no-overwrite berhasil |
| Pwntools | Cyclic kompatibel dengan pustaka; harness lokal mengirim `hello` ke fixture C dan menerima `echo:hello` |
| Batch contoh | 20 artefak; 16 kandidat flag yang diharapkan ditemukan pada profil full |
| Build Python | Wheel dan source distribution berhasil dibuat |
| Installer Bash | Syntax diperiksa; profil core diuji dengan venv baru |
| Formatter/lint | Ruff lint dan format check berhasil |

Command langsung juga memverifikasi contoh RSA pada `RECIPES.md` menghasilkan
teks `Hi`, dan template file decoder menemukan `ORBIT{layered_decode}`.

## Versi extras yang diuji

| Paket | Versi |
|---|---|
| Pillow | 12.3.0 |
| PyCryptodome | 3.23.0 |
| Capstone | 5.0.9 |
| pwntools | 4.15.0 |
| Ruff | 0.16.9 |
| build | 1.6.1 |
| setuptools dalam build isolation | 84.0.0 |
| wheel dalam build isolation | 0.48.0 |

`pyproject.toml` memakai rentang versi, bukan lock lintas-platform. Versi
transitif yang dipasang dapat berubah pada instalasi berikutnya. Simpan
snapshot environment milik Anda bila perlu reproduksi deployment yang
lebih ketat:

```bash
python -m pip freeze > reports/environment.txt
```

Snapshot environment tidak wajib untuk core yang tidak memiliki runtime
dependency pihak ketiga.

## Menjalankan ulang

```bash
python -m pip install -e ".[full,dev]"
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
python -m build
ctf-orbit analyze examples/data --recursive --out reports/test-demo-01
```

Core saja:

```bash
python -m pip install .
python -m unittest discover -s tests -v
```

Jika environment sengaja melarang bind localhost, empat tes HTTP dapat
dilewati dengan `ORBIT_SKIP_HTTP=1`. Itu berarti fitur HTTP belum diuji
dalam run tersebut; pada verifikasi yang dilaporkan di atas, tes HTTP
dijalankan dan berhasil.

```bash
ORBIT_SKIP_HTTP=1 python -m unittest discover -s tests -v
```

## Batas verifikasi

- Windows, macOS, dan Python 3.11/3.13 belum dijalankan dalam lingkungan
  pembuatan ini; matriks CI disediakan untuk memeriksanya setelah push.
- Script PowerShell belum dieksekusi di Windows.
- Build/run Docker belum diuji karena Docker tidak tersedia pada environment
  pembuatan. Dockerfile dan panduannya tersedia untuk diuji pada host Anda.
- Fixture sintetik memverifikasi subset parser, bukan semua binary/APK/image
  dari software dunia nyata. Tidak ada pengujian terhadap target eksternal.
- Test suite tidak menyatakan toolkit mampu menyelesaikan setiap challenge
  atau melakukan audit keamanan umum.

Laporan ini menggambarkan validasi yang benar-benar dilakukan dan tidak
mengganti hasil GitHub Actions pada repo yang Anda buat.
