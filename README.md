# CTF Orbit

Toolkit CLI Python untuk **otomasi triase CTF lintas kategori**, pencarian
kandidat flag, decoding berlapis, dan laporan JSON/Markdown. Dibuat dengan
inti tanpa dependensi pihak ketiga; fitur gambar, Keccak, disassembly, dan
template pwntools tersedia melalui extras.

**Python 3.11+ · Linux / macOS / Windows untuk inti · MIT · 12 kategori**

Toolkit membantu mengolah artefak dan mempercepat langkah awal. Kemampuan
solver mengikuti teknik yang diimplementasikan; tidak semua challenge,
format, atau kerentanan dapat diselesaikan otomatis. Gunakan pada challenge
CTF/lab dan target yang diizinkan penyelenggara.

## Mulai dalam 5 menit

Ekstrak folder `ctf-orbit`, buka terminal di dalamnya, lalu:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[full]"
ctf-orbit doctor
ctf-orbit analyze examples/data --recursive --out reports/demo-01
```

Hasil berada di `reports/demo-01/report.json` dan `report.md`. Perintah dengan
`--out` menampilkan ringkasan dan path laporan. Tanpa `--out`, JSON lengkap
dicetak ke terminal. Gunakan nama direktori baru pada pengulangan.

Untuk Windows native, gunakan extras yang mendukung platform:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[image,crypto,reverse]"
.\.venv\Scripts\ctf-orbit.exe doctor
.\.venv\Scripts\ctf-orbit.exe analyze examples/data --recursive --out reports/demo-01
```

Template pwntools direkomendasikan melalui Linux/WSL. Petunjuk lengkap untuk
Ubuntu/Kali, macOS, Windows/WSL, Docker, dan instalasi tanpa internet ada di
[INSTALL.md](docs/INSTALL.md).

### Mode inti tanpa instalasi

```bash
python3 run.py --help
python3 run.py misc decode --file examples/data/misc/layers.txt
python3 run.py analyze examples/data --recursive --out reports/core-01
```

Inti langsung berjalan tanpa `pip`. Ganti awalan `ctf-orbit` pada panduan
dengan `python3 run.py` bila memakai cara ini. LSB gambar memerlukan Pillow;
WAV LSB tetap berjalan tanpa Pillow. Modul yang tidak sesuai format atau
belum mempunyai dependensi ditandai `skipped` dalam pipeline.

## Cakupan kategori

| Kategori | Otomasi yang tersedia | Batas utama |
|---|---|---|
| Web | GET satu URL, inventaris path satu origin, HTML/comment/form, header/cookie attribute, decode JWT | Tidak otomatis mengeksploitasi SQLi/XSS/SSRF; signature JWT tidak diverifikasi |
| Crypto | Caesar 26 shift, Vigenere dengan key, single-byte XOR, repeating-key XOR dengan key, RSA textbook, identifikasi format hash | Tidak memecahkan cipher modern secara umum; RSA hanya faktor diberikan / trial / Fermat bounded / exact root |
| Forensics | Hash, magic/signature offset, entropy, strings ASCII/UTF-16, ZIP inventory/sampel, gzip sample, carving | ZIP tidak diekstrak otomatis; analisis disk/memory image mendalam memerlukan tool khusus |
| Steganography | Metadata/EXIF gambar, LSB kanal/bit-plane, delapan visualisasi bit-plane, LSB sampel WAV PCM | LSB JPEG domain frekuensi, QR, spectrogram, dan algoritma stego khusus belum diimplementasikan |
| Reverse | Header/section ELF dan PE, indikator proteksi, simbol ELF, strings, disassembly x86/x64/ARM/ARM64 | Tidak melakukan decompile; Mach-O dan mapping VA otomatis belum tersedia |
| Pwn | Cyclic de Bruijn, pencarian offset, pack/unpack, template proses lokal pwntools | Payload/ROP/heap exploit spesifik challenge harus dikembangkan sendiri |
| Network | PCAP klasik, Ethernet/VLAN/raw IP/SLL/SLL2, TCP per arah, UDP, DNS question, petunjuk HTTP | PCAPNG perlu dikonversi; tanpa dekripsi TLS, IP fragment reassembly, TCP sequence wrap |
| OSINT | URL, domain, email, IP, handle candidate, metadata HTML dari artefak lokal | Tidak mencari identitas/orang, mengunjungi URL, atau melakukan scraping akun |
| Mobile | APK inventory, string pool manifest Android, DEX strings, permission, URL, native library | Analisis statis saja; tidak menginstal APK atau merekonstruksi manifest lengkap |
| Blockchain | Petunjuk Solidity, selector Keccak-256, static ABI word decode, disassembly EVM | Tidak mengirim transaksi/RPC; tipe ABI dinamis, analisis storage dan exploit memerlukan solver khusus |
| Hardware | Signature/string/entropy firmware, petunjuk U-Boot/BusyBox, Intel HEX ke binary | Tidak membaca perangkat, mem-flash, atau mengekstrak filesystem firmware |
| Misc | Decode BFS: hex/base64/base32/URL/HTML/binary/decimal/ROT13/reverse/Morse; Brainfuck bounded; flag scan | Tidak menjalankan kode challenge otomatis; format encoding khusus perlu ditambahkan |

## Contoh perintah

```bash
# Otomasi lokal: pilih kategori dari signature dan ekstensi
ctf-orbit analyze ./challenges --recursive --max-files 50 --out reports/triage-01

# Coba seluruh modul; modul yang tidak cocok dicatat sebagai skipped
ctf-orbit analyze examples/data/forensics/evidence.zip --category all --out reports/all-01

# Prefix lomba tambahan; opsi bisa diulang
ctf-orbit analyze ./challenge.txt --flag-prefix GEMASTIK --out reports/gemastik-01

# Decoder berlapis + XOR
ctf-orbit misc decode --file examples/data/misc/layers.txt --depth 4
ctf-orbit crypto xor --file examples/data/crypto/xor.bin --top 5

# Binary dan offset pwn
ctf-orbit reverse inspect examples/data/reverse/sample.elf
ctf-orbit pwn cyclic --length 200 --save reports/pattern.bin
ctf-orbit pwn offset 0x61616162 --encoding int --endian little

# LSB dan capture lokal
ctf-orbit stego image-lsb examples/data/stego/hidden.png --channels rgb
ctf-orbit network pcap examples/data/network/traffic.pcap --out reports/pcap-01

# Workspace challenge dengan catatan dan solver awal
ctf-orbit init warmup --category crypto --directory challenges/warmup
```

### Lab web lokal

Terminal pertama:

```bash
python examples/web_lab.py --port 8765
```

Terminal kedua:

```bash
ctf-orbit web inspect http://127.0.0.1:8765/
ctf-orbit web paths http://127.0.0.1:8765/ --wordlist wordlists/web-small.txt --max-requests 20 --delay 0.2 --out reports/web-01
```

Kandidat flag lab: `ORBIT{local_web_lab}`. Hentikan server dengan Ctrl+C.
Permintaan web tidak mengikuti redirect dan tidak memakai proxy dari
environment secara otomatis. Wordlist harus berupa path pada origin URL
yang diberikan.

## Isi repositori

| Path | Isi |
|---|---|
| `src/ctf_orbit/` | CLI, pipeline, 12 kategori, utilitas, template yang ikut terpasang dalam wheel |
| `docs/INSTALL.md` | Instalasi OS, extras, Docker, offline, troubleshooting instalasi |
| `docs/USAGE.md` | Alur dan parameter setiap kategori, contoh serta interpretasi output |
| `docs/RECIPES.md` | Latihan bertahap dengan hasil yang diharapkan |
| `docs/ARCHITECTURE.md` | API internal, format laporan, routing, batas resource, cara menambah modul |
| `docs/TESTING.md` | Verifikasi yang dilakukan dan cara menjalankan tes |
| `docs/GITHUB.md` | Upload lewat Git atau web GitHub, CI, release ZIP |
| `docs/REFERENCES.md` | Dokumentasi resmi format dan dependensi |
| `examples/data/` | Fixture latihan sintetik siap dipakai |
| `examples/web_lab.py` | Server HTTP localhost untuk latihan web |
| `scripts/` | Installer Bash/PowerShell, generator fixture, pembuat ZIP release |
| `templates/` | Salinan template solver agar mudah dibaca/dimodifikasi |
| `tests/` | Tes stdlib unittest, format malformed, CLI dan HTTP localhost |
| `wordlists/` | Daftar path kecil buatan proyek |
| `.github/` | GitHub Actions CI, template issue dan pull request |

Contoh APK/DEX/AXML/ELF/PE adalah fixture sintetik untuk inspeksi parser.
Contoh APK tidak ditujukan untuk diinstal. Sampel firmware dengan magic
filesystem tidak berarti berisi filesystem valid. Seluruh contoh dibuat
ulang oleh `scripts/generate_examples.py`.

## Pengembangan

```bash
python -m pip install -e ".[full,dev]"
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
python -m build
```

Tes inti tidak membutuhkan framework pihak ketiga. Tes extras dilewati jika
extras belum terpasang. GitHub Actions menguji inti pada Linux, macOS,
Windows dan Python 3.11–3.13 dalam matriks yang ditentukan di workflow;
fitur lengkap diuji di Linux. Hasil CI baru tersedia setelah repo di-push.

## Siap untuk GitHub

Folder ini sudah memuat `pyproject.toml`, lisensi, `.gitignore`, CI, template
issue/PR, Dockerfile, dokumentasi, dan tes. Ekstrak ZIP lalu upload **isi folder
`ctf-orbit`** sebagai root repositori. Ikuti [GITHUB.md](docs/GITHUB.md) untuk
langkah Git dan upload melalui browser. Tidak memerlukan secret GitHub untuk
menjalankan tes.

Lisensi source buatan proyek: [MIT](LICENSE). Dependensi mempertahankan
lisensinya masing-masing; lihat [NOTICE.md](NOTICE.md).

