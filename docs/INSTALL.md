# Instalasi lengkap

Semua command di panduan dijalankan dari root folder `ctf-orbit`. Dibutuhkan
Python **3.11 atau lebih baru**. Python 3.12 adalah versi yang digunakan
untuk verifikasi paket ini. Inti memakai standard library; extras menambah
kemampuan tertentu.

## 1. Pilih profil

| Profil | Perintah | Kemampuan |
|---|---|---|
| Core | `python -m pip install -e .` | Decoder, crypto klasik/RSA, forensics, ELF/PE, pwn utilities, WAV, PCAP, web, OSINT, APK/DEX, static ABI/EVM, firmware |
| Gambar | `python -m pip install -e ".[image]"` | Core + Pillow untuk metadata/LSB/bit-plane gambar |
| Keccak | `python -m pip install -e ".[crypto]"` | Core + PyCryptodome untuk selector Ethereum |
| Disassembly | `python -m pip install -e ".[reverse]"` | Core + Capstone untuk disassembly raw bytes |
| Standard | `python -m pip install -e ".[image,crypto,reverse]"` | Direkomendasikan untuk Windows native; tanpa template pwntools |
| Full | `python -m pip install -e ".[full]"` | Semua extras termasuk pwntools; direkomendasikan Linux/WSL |
| Development | `python -m pip install -e ".[full,dev]"` | Full + Ruff dan build frontend |

Extras adalah tambahan pada paket yang sama. Memasang extra baru tidak
menghapus extra yang sudah terpasang. `-e` berarti perubahan source langsung
berlaku. Untuk instalasi salinan tetap, hilangkan `-e`.

## 2. Ubuntu, Debian, Kali, dan WSL

Cek versi:

```bash
python3 --version
```

Jika Python sudah 3.11+, siapkan venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[full]"
ctf-orbit --version
ctf-orbit doctor
```

Pada distro yang belum memiliki modul venv/pip, pasang melalui package
manager. Contoh Debian 12+, Ubuntu 24.04+, dan Kali dengan Python yang sesuai:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
```

Jika pwntools/dependensi perlu dikompilasi karena wheel platform tidak
tersedia:

```bash
sudo apt-get install -y build-essential python3-dev libssl-dev libffi-dev
```

Jika `python3` pada distro adalah 3.10, gunakan interpreter 3.11+ yang sudah
Anda instal, misalnya `python3.12 -m venv .venv`. Jangan menjalankan `pip`
global dengan `sudo` atau memaksa `--break-system-packages`.

### Installer Bash

```bash
bash scripts/install.sh full
# Alternatif profil:
bash scripts/install.sh core
bash scripts/install.sh standard
bash scripts/install.sh dev
```

Installer membuat `.venv` di root repo, memperbarui pip, memasang profil,
dan menjalankan `doctor`. Installer tidak mengubah package OS atau shell
profile. Aktivasi venv setelah installer:

```bash
source .venv/bin/activate
```

Interpreter khusus dapat dipilih dengan:

```bash
CTF_ORBIT_PYTHON=python3.12 bash scripts/install.sh full
```

## 3. macOS

Gunakan Python 3.11+ dari distribusi Python yang Anda pilih. Setelah
`python3 --version` sesuai, gunakan langkah venv yang sama seperti Linux.
Core, Pillow, PyCryptodome, dan Capstone memakai distribusi platform yang
tersedia dari pip. Template pwn untuk binary ELF Linux tetap perlu lingkungan
Linux; memasang pwntools di macOS tidak membuat binary Linux dapat berjalan.

Tool OS opsional seperti `objdump`, `readelf`, atau `gdb` tidak diwajibkan
CLI dan tidak diinstal otomatis.

## 4. Windows native (PowerShell)

Periksa Python launcher:

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[image,crypto,reverse]"
.\.venv\Scripts\ctf-orbit.exe doctor
```

Tidak perlu mengubah execution policy karena perintah memakai executable
venv secara langsung. Jika policy Anda mengizinkan aktivasi:

```powershell
.\.venv\Scripts\Activate.ps1
ctf-orbit --help
```

Installer alternatif jika script PowerShell diizinkan:

```powershell
.\scripts\install.ps1 -Mode standard
```

Untuk pwntools, GDB, dan binary ELF Linux, gunakan WSL lalu ikuti bagian
Linux. Mode Windows native tidak menjanjikan proses pwntools untuk binary
Linux.

## 5. Tanpa pip atau tanpa internet

Core dapat langsung dipanggil dari source:

```bash
python3 run.py doctor
python3 run.py misc decode --file examples/data/misc/layers.txt
python3 run.py network pcap examples/data/network/traffic.pcap
```

Semua contoh CLI pada dokumen bisa memakai awalan `python3 run.py`.
`python -m ctf_orbit` tersedia setelah paket terpasang, atau dengan
`PYTHONPATH=src` pada POSIX. Extras belum tersedia jika dependensinya belum
ada; pipeline mencatatnya sebagai `skipped`.

### Menyiapkan wheelhouse offline

Pada mesin yang mempunyai internet dengan **OS, arsitektur, dan versi Python
yang sama** dengan mesin tujuan:

```bash
python -m pip wheel ".[full]" --wheel-dir wheelhouse
```

Salin `wheelhouse/` ke mesin offline, lalu:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links wheelhouse "ctf-orbit[full]==1.0.0"
ctf-orbit doctor
```

Contoh ini menggunakan wheel paket dan seluruh dependensinya, sehingga tidak
memerlukan build isolation yang mengunduh setuptools di mesin offline.
Wheelhouse bukan bagian ZIP source agar paket tetap kecil.

## 6. Docker

Build memerlukan internet untuk mengambil base image dan dependensi:

```bash
docker build -t ctf-orbit:1.0.0 .
```

Jalankan analisis lokal dari root repo (Linux/macOS):

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work ctf-orbit:1.0.0 analyze examples/data --recursive --out reports/docker-01
```

PowerShell:

```powershell
docker run --rm --network none -v "${PWD}:/work" -w /work ctf-orbit:1.0.0 analyze examples/data --recursive --out reports/docker-01
```

Container memakai user non-root. Pada Linux, `--user` menyamakan pemilik
hasil dengan user host. Profil build default `full`; pilih core dengan:

```bash
docker build --build-arg EXTRAS= -t ctf-orbit:core .
```

Mode `--network none` cocok untuk analisis file. Untuk web lab, jalankan CLI
host atau atur jaringan container ke lab yang Anda sediakan. `127.0.0.1`
di container mengacu pada container itu sendiri.

Dockerfile tersedia dan alurnya didokumentasikan. Status uji build Docker
tercantum di `TESTING.md`; jangan menyamakan tersedianya Dockerfile dengan
build yang sudah dijalankan di setiap platform.

## 7. Tool eksternal opsional

| Kebutuhan lanjutan | Tool yang dapat dipakai terpisah |
|---|---|
| Metadata rinci | ExifTool |
| PCAPNG/protokol kompleks | Wireshark / tshark |
| ELF, debug dan decompile | binutils, GDB, Ghidra, Rizin/radare2 |
| Firmware filesystem | binwalk, unsquashfs sesuai format/versi |
| APK decompile | JADX / apktool |
| QR dan barcode | zbarimg |
| Memory/disk forensics | Volatility, Sleuth Kit sesuai artefak |

`doctor` mendeteksi sebagian tool di PATH, tanpa menjalankannya. Integrasi
eksekusi otomatis tool-tool tersebut bukan kemampuan CLI saat ini. Pasang
hanya jika tahap analisis Anda membutuhkannya.

## 8. Troubleshooting

| Gejala | Penyebab dan tindakan |
|---|---|
| `ctf-orbit: command not found` | Aktifkan venv atau panggil `.venv/bin/ctf-orbit`; di Windows gunakan `.venv\Scripts\ctf-orbit.exe` |
| `externally-managed-environment` | Gunakan venv, bukan pip sistem |
| `No module named PIL/Crypto/capstone/pwn` | Pasang extra dengan `python -m pip install -e ".[image]"` atau extra yang sesuai |
| `No matching distribution` | Cek koneksi, versi Python, arsitektur, index pip, dan ketersediaan wheel; jangan abaikan pesan error resolver |
| `Cannot import setuptools.build_meta` | Jika memakai `--no-build-isolation`, pasang setuptools>=77 dan wheel lebih dahulu; instalasi normal tidak memerlukan opsi tersebut |
| Error tulis laporan / permission denied | Pilih folder hasil yang dapat ditulis; cek user bind mount Docker |
| PowerShell menolak `.ps1` | Gunakan perintah executable venv langsung seperti contoh di atas |
| HTTP timeout / SSL error | Cek lab aktif, host/port benar, dan sertifikat dipercaya; CLI mempertahankan verifikasi TLS |
| PCAPNG ditolak | Konversi dengan tshark seperti `USAGE.md`; pilih format PCAP klasik |

## 9. Memperbarui dan menghapus instalasi

Untuk source yang telah diperbarui:

```bash
python -m pip install -e ".[full]"
ctf-orbit doctor
python -m unittest discover -s tests -v
```

Keluar dari venv dengan `deactivate`. Untuk menghapus paket dari venv,
jalankan `python -m pip uninstall ctf-orbit`. Artefak dan laporan di folder
proyek tidak dihapus oleh uninstall.

