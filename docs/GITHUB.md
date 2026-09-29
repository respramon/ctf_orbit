# Mengunggah ke GitHub

ZIP mengekstrak satu folder `ctf-orbit/`. Root repo sebaiknya berisi
`README.md`, `pyproject.toml`, `src/`, `docs/`, dan `.github/` langsung, bukan
lapisan folder `ctf-orbit/` tambahan.

## Melalui Git

1. Ekstrak dan buka terminal di folder `ctf-orbit`.
2. Buat repository baru di GitHub. Pilih public/private sesuai kebutuhan.
3. Jika akan push source ini, buat repository kosong tanpa README tambahan
   untuk menghindari konflik commit awal.
4. Ganti `USERNAME` dengan username Anda, lalu:

```bash
git init
git branch -M main
git add .
git status --short
git commit -m "Initial release: CTF Orbit toolkit"
git remote add origin https://github.com/USERNAME/ctf-orbit.git
git push -u origin main
```

Git akan menggunakan mekanisme autentikasi Anda. Jangan memasukkan token
ke source atau URL remote. Jika repo tujuan sudah berisi commit, clone dulu
repo itu dan salin source ke checkout, lalu tinjau diff sebelum commit.

## Upload melalui browser

1. Ekstrak ZIP.
2. Buat repository baru pada [github.com/new](https://github.com/new).
3. Pilih **Add file → Upload files** sesuai antarmuka GitHub yang tersedia.
4. Upload seluruh isi folder `ctf-orbit`.
5. Pastikan file tersembunyi `.github/`, `.gitignore`, `.dockerignore` ikut
   masuk. File picker OS dapat menyembunyikannya; Git lebih andal untuk ini.
6. Commit hasil upload.

Mengunggah ZIP sebagai satu file hanya menyimpan arsip; GitHub tidak
otomatis mengubah isinya menjadi source tree. Ekstrak dan unggah isinya agar
README/CI dapat digunakan.

## Verifikasi setelah push

Periksa README dan tautan docs. Pada tab Actions, workflow CI melakukan:

- Core tests pada Linux Python 3.11/3.12/3.13, Windows 3.12, macOS 3.12.
- Full tests, lint dan build pada Linux Python 3.12.

Workflow menggunakan permission `contents: read`, tidak memerlukan token
khusus, tidak menerbitkan paket, dan tidak menghubungi target CTF eksternal.
HTTP tests hanya membuat server localhost pada runner. Hasil CI tergantung
runner dan dependency yang tersedia saat run.

Folder `reports/`, `challenges/`, environment, build output, dan credential
environment tidak ikut Git karena `.gitignore`. Contoh latihan tetap
disertakan dalam `examples/data/`.

## Membuat release source ZIP

```bash
python scripts/package_release.py --output dist/ctf-orbit-v1.0.0.zip
```

Script mengumpulkan file source/dokumentasi/fixture, mengabaikan environment
dan output lokal, menghasilkan `CHECKSUMS.sha256`, dan membuat satu folder
top-level dalam ZIP. Output ZIP yang sudah ada ditolak kecuali memakai
`--force`. Tinjau file manifest sebelum membagikan release dari repo yang
sudah Anda modifikasi.

Untuk wheel/sdist Python:

```bash
python -m pip install -e ".[dev]"
python -m build
```

Wheel memasang CLI dan module/template internal; source ZIP menyertakan
seluruh dokumen, CI, installer dan latihan. Menjalankan build tidak
menerbitkan paket ke PyPI atau GitHub. Buat GitHub Release dan lampirkan ZIP
jika Anda ingin membagikan snapshot yang dapat diunduh.
