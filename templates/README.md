# Template solver

- `file_decoder.py`: menerima satu file lokal, lalu menjalankan decoder berlapis.
- `pwn_local.py`: menjalankan binary latihan lokal dengan pwntools, mengirim
  satu baris dan membaca respons. Memerlukan extra pwn dan lingkungan yang
  mendukung binary itu.

Contoh decoder:

```bash
python templates/file_decoder.py examples/data/misc/layers.txt
```

Contoh harness lokal di Linux/WSL dengan compiler C:

```bash
mkdir -p reports
cc examples/echo.c -o reports/echo-lab
python templates/pwn_local.py reports/echo-lab --line hello
```

Respons contoh: `b'echo:hello\n'`. Ini latihan I/O lokal; payload khusus
challenge dikembangkan berdasarkan analisis. `ctf-orbit pwn template`
menyalin template dari modul internal, sehingga tetap tersedia saat paket
dipasang melalui wheel tanpa folder repo.

