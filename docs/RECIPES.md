# Latihan dengan hasil diketahui

Latihan memakai `examples/data/` dan tidak membutuhkan challenge eksternal.
Perintah dijalankan dari root repo. Hasil ekspor memakai `reports/`; pilih
nama baru ketika mengulang. Semua artefak sintetik disertakan dalam source.

## 1. Triase seluruh artefak

```bash
ctf-orbit analyze examples/data --recursive --out reports/recipe-01
```

Profil full: 20 file dianalisis, 16 kandidat flag ditemukan. Modul tambahan
yang tidak tersedia pada profil core dapat mengurangi hasil gambar. Lihat
bagian `flags` pada `report.json`, lalu `files[].modules` untuk asal hasil.

## 2. Base64 lalu hex

```bash
ctf-orbit misc decode --file examples/data/misc/layers.txt --out reports/recipe-02
```

Hasil: `ORBIT{layered_decode}`, dengan chain `base64` lalu `hex`. Perhatikan
bahwa decoder menemukan kandidat beberapa transformasi; chain yang benar
terbukti menghasilkan flag dengan struktur yang sesuai.

## 3. Single-byte XOR

```bash
ctf-orbit crypto xor --file examples/data/crypto/xor.bin --top 5
ctf-orbit crypto xor --file examples/data/crypto/xor.bin --key-hex 42
```

Hasil: key hex `42`, plaintext `ORBIT{single_byte_xor}`. Gunakan percobaan
kedua untuk mereproduksi hasil dengan key yang sudah diketahui.

## 4. RSA faktor diketahui

```bash
ctf-orbit crypto rsa --n 1000036000099 --e 65537 --c 831552346467 --p 1000003 --q 1000033
```

Parameter ciphertext di `examples/data/crypto/rsa.json` adalah sumber
latihan. Gunakan nilai `c` persis dari file jika regenerasi fixture dilakukan.
Plaintext yang diharapkan adalah `Hi`. Untuk contoh textbook yang lebih
kecil dan stabil:

```bash
ctf-orbit crypto rsa --n 3233 --e 17 --c 2790 --p 61 --q 53
```

Hasil `A` (`m=65`), bukan flag. Latihan ini menunjukkan helper matematika,
bukan pemecahan RSA modern.

## 5. Strings dan ZIP

```bash
ctf-orbit forensics inspect examples/data/forensics/memory.bin
ctf-orbit forensics inspect examples/data/forensics/evidence.zip
```

Hasil: `ORBIT{memory_strings}`, `ORBIT{utf16_string}`, dan
`ORBIT{inside_zip}`. Flag UTF-16 berasal dari string hasil decoding,
sehingga scan raw ASCII saja tidak cukup.

## 6. Carving PNG dan LSB

```bash
ctf-orbit forensics carve examples/data/forensics/carrier.bin --offset 14 --signature png --save reports/recipe-06.png
ctf-orbit stego image-lsb reports/recipe-06.png --channels rgb --plane 0 --save reports/recipe-06-lsb.bin
```

Hasil: `ORBIT{png_lsb}`. PNG dimulai di offset 14; parser carving berhenti
di IEND sehingga trailer tidak ikut diekspor. Extra `image` diperlukan.
Anda dapat membandingkan SHA-256 PNG hasil carving dengan
`examples/data/stego/hidden.png`.

## 7. WAV sample LSB

```bash
ctf-orbit stego wav-lsb examples/data/stego/audio.wav --channel 0
```

Hasil: `ORBIT{wav_lsb}`. Ini PCM 16-bit mono, payload ditulis pada bit 0
byte rendah setiap sampel. Tidak memerlukan Pillow.

## 8. Reverse dan utilitas pwn

```bash
ctf-orbit reverse inspect examples/data/reverse/sample.elf
ctf-orbit reverse disasm examples/data/reverse/sample.elf --arch x64 --offset 176 --bytes 6 --base 0x4000b0
ctf-orbit pwn offset 0x61616162 --encoding int --endian little --n 4
```

ELF: x86-64 little-endian, entry `0x4000b0`, GNU_STACK NX aktif, string
`ORBIT{static_reverse}`. Disassembly: `mov eax, 0x2a` kemudian `ret`.
Pencarian cyclic menghasilkan offset 4. Disassembly memerlukan Capstone;
inspeksi/offset tidak.

## 9. TCP terpecah dan retransmission

```bash
ctf-orbit network pcap examples/data/network/traffic.pcap --save-streams reports/recipe-09-streams
```

Capture 5 paket sengaja menyimpan segmen TCP di luar urutan dan satu
retransmission. Hasil reassembly: `ORBIT{tcp_reassembled}`. Payload UDP:
`ORBIT{udp_payload}`. DNS question: `ctf.example.test`. Ini menunjukkan
bahwa mencari flag per-paket saja dapat melewatkan flag yang terbelah.

## 10. Web dan OSINT

```bash
ctf-orbit osint inspect examples/data/osint/page.html
python examples/web_lab.py --port 8765
```

Pada terminal kedua:

```bash
ctf-orbit web inspect http://127.0.0.1:8765/robots.txt
ctf-orbit web paths http://127.0.0.1:8765/ --path /admin --path /robots.txt
```

HTML lokal: `ORBIT{html_comment}`, `team@example.test`, `@orbit_player`,
dan alamat dokumentasi `192.0.2.10`. Web lab: `ORBIT{local_web_lab}` pada
`/admin`, dengan petunjuk pada robots/comment. Tutup server dengan Ctrl+C.

## 11. APK/DEX statis

```bash
ctf-orbit mobile apk examples/data/mobile/challenge.apk
ctf-orbit mobile dex examples/data/mobile/classes.dex
```

Hasil: `ORBIT{dex_string}`, URL contoh dan permission INTERNET.
APK/manifest/DEX ini fixture parser minimal, bukan aplikasi yang dapat
diinstal. Tidak ada kebutuhan emulator atau device.

## 12. Solidity, selector dan ABI

```bash
ctf-orbit blockchain inspect examples/data/blockchain/Challenge.sol
ctf-orbit blockchain selector 'transfer(address,uint256)'
ctf-orbit blockchain abi --hex 0000000000000000000000000000000000000000000000000000000000000007 --types uint256
```

Hasil: `ORBIT{solidity_hint}`, petunjuk `tx.origin`, selector `0xa9059cbb`,
dan uint256 `7`. Pembacaan source/ABI tidak membutuhkan RPC; hanya selector
memerlukan extra crypto.

## 13. Firmware dan Intel HEX

```bash
ctf-orbit hardware inspect examples/data/hardware/firmware.bin
ctf-orbit hardware ihex examples/data/hardware/firmware.hex --save reports/recipe-13.bin
```

Hasil: `ORBIT{firmware_strings}` dan `ORBIT{intel_hex}`. Binary Intel HEX
memiliki `base_address=0x10010`. Signature `hsqs` di fixture pertama hanya
kandidat magic, bukan filesystem SquashFS yang valid.

## Membuat ulang fixture

```bash
python scripts/generate_examples.py --directory examples/data
```

Generator menimpa fixture di direktori yang Anda pilih, sehingga jangan
menunjuk folder berisi artefak challenge asli. Jika Pillow tidak terpasang,
fixture gambar tidak dibuat ulang, tetapi fixture gambar yang sudah ada
tidak dihapus. `--no-image` secara eksplisit melewati pembuatan gambar.
