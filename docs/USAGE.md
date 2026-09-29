# Panduan penggunaan

Jalankan command dari root repositori dengan venv aktif. `ctf-orbit --help`
menampilkan kategori; `ctf-orbit crypto --help` menampilkan subcommand;
`ctf-orbit crypto rsa --help` menampilkan opsi. Semua contoh bisa memakai
`python3 run.py` sebagai pengganti `ctf-orbit`.

## 1. Alur kerja umum

1. Simpan deskripsi challenge, kategori, format flag, dan artefak.
2. Buat workspace: `ctf-orbit init warmup --category misc`.
3. Salin artefak ke `challenges/warmup/artifacts/`.
4. Jalankan triase otomatis.
5. Baca kandidat flag, string, tipe file, dan modul yang dilewati.
6. Pilih command kategori dengan parameter yang sesuai petunjuk.
7. Simpan laporan baru tiap percobaan, lalu catat metode yang menghasilkan
   hasil pada README workspace.

```bash
ctf-orbit init warmup --category misc
ctf-orbit analyze challenges/warmup/artifacts --recursive --out challenges/warmup/reports/triage-01
```

`init` membuat `challenge.json`, `README.md`, `solve.py`, `artifacts/`, dan
`reports/`. Folder tujuan harus belum ada. `--url` hanya mencatat URL, tidak
mengunjungi URL. `--category pwn` memilih template proses lokal pwntools.
Kategori lainnya mendapat solver decoder file lokal yang dapat dikembangkan.

## 2. Output dan error

Setiap subcommand menerima `--out DIRECTORY` **setelah nama command/subcommand**:

```bash
ctf-orbit crypto caesar "Khoor" --shift 3 --out reports/caesar-01
```

| Bentuk output | Isi |
|---|---|
| Tanpa `--out` | JSON lengkap ke stdout |
| Dengan `--out` | `report.json`, `report.md`, dan ringkasan ke stdout |
| `--save FILE` | Byte hasil mentah tambahan, misalnya LSB, carving, cyclic, Intel HEX |
| `--save-streams DIRECTORY` | Potongan TCP hasil rekonstruksi |

File hasil yang sudah ada tidak ditimpa. Pilih nama baru atau pindahkan
hasil lama. JSON stdout meng-escape karakter kontrol agar byte artefak tidak
diperlakukan sebagai kode terminal. `text` dalam preview adalah UTF-8 dengan
replacement; `hex` menyediakan representasi byte yang tepat untuk bagian
preview. Banyak preview berhenti pada 1.024 byte dan 256 byte hex; gunakan
`--save` untuk mengambil byte lengkap bila subcommand menyediakannya.

| Exit code | Arti |
|---|---|
| `0` | Command selesai, termasuk hasil heuristik kosong / RSA unsolved / pipeline module skipped |
| `1` | `analyze` selesai sebagian tetapi ada file yang gagal dibaca |
| `2` | Input/argumen/format salah, dependensi command langsung hilang, atau kegagalan I/O |

`flags` berisi **kandidat** flag. Teks berbentuk flag di komentar atau data
umpan tetap dapat muncul. Periksa konteks dan validasi melalui mekanisme
submission lomba; toolkit tidak mengirim flag otomatis.

## 3. Pipeline otomatis: `analyze`

```bash
ctf-orbit analyze examples/data --recursive --out reports/triage-01
ctf-orbit analyze examples/data/mobile/challenge.apk --category mobile
ctf-orbit analyze examples/data/forensics/evidence.zip --category all
```

| Opsi | Default | Makna |
|---|---|---|
| `--category` | `auto` | `auto`, `all`, atau salah satu dari 12 kategori |
| `--recursive` | Mati | Masuk ke subfolder |
| `--max-files` | `50` | Batas 1–500 file |
| `--max-size-mib` | `32` | Batas 1–128 MiB per file untuk pipeline |
| `--flag-prefix` | Prefix bawaan | Tambahkan prefix literal; bisa diulang |
| `--out` | Tidak ada | Simpan laporan |

Prefix bawaan: `flag`, `ctf`, `picoCTF`, `HTB`, `THM`, dan `ORBIT`, tanpa
membedakan huruf besar/kecil. Prefix tambahan hanya menerima huruf ASCII,
angka, underscore, maksimal 40 karakter:

```bash
ctf-orbit analyze challenge.txt --flag-prefix GEMASTIK --flag-prefix TEAMFLAG
```

Isi dalam kurung `{...}` dibatasi 1–200 karakter ASCII printable. Format
flag yang tidak memakai kurung kurawal perlu Anda cari melalui strings atau
adaptasi fungsi deteksi.

`auto` memakai signature dan ekstensi. Forensics/misc selalu berjalan;
binary ELF/PE menambah reverse/pwn, gambar/WAV menambah stego, capture
menambah network, APK/DEX/AXML menambah mobile, source `.sol` menambah
blockchain, dan firmware menambah hardware. Teks dianalisis dengan crypto
klasik serta OSINT; file raw kecil juga dicoba dengan single-byte XOR.

Pipeline tidak menjalankan binary/script yang dianalisis, tidak mengikuti
URL, dan tidak mengekstrak arsip ke filesystem. Decoder mencoba maksimal
16 potongan per file, dengan sampel kandidat dibatasi. `all` mencoba seluruh
modul dan biasanya menghasilkan beberapa `skipped` karena format tidak
cocok. `skipped` bukan bukti bahwa challenge gagal atau file kosong.

Pada scan direktori, symlink file/subfolder dilewati. Folder `.git`, `.venv`,
`venv`, `node_modules`, `__pycache__`, `reports`, `build`, `dist`, dan
subfolder tersembunyi dilewati saat rekursi. Pilih direktori artefak yang
spesifik: traversal dibatasi 10.000 entri dan tidak menjamin urutan file
antar-filesystem. `file_limit_reached` menunjukkan ada file tambahan.

## 4. Misc dan encoding

### Decode berlapis

```bash
ctf-orbit misc decode --file examples/data/misc/layers.txt --depth 4 --max-nodes 128
ctf-orbit misc decode --text "T1JCSVQ="
ctf-orbit misc flags examples/data/forensics/memory.bin
```

`decode` menerima tepat satu dari `--file` atau `--text`, maksimal 256 KiB.
Depth 1–8; jumlah node 1–512. Pencarian breadth-first melakukan deduplikasi
byte yang sudah dikunjungi. `chain` mencatat urutan transformasi, misalnya
`["base64", "hex"]`. Ranking memakai printable text dan kandidat flag,
sehingga hasil dengan skor tinggi tetap perlu dibaca.

Transformasi: hex, base64/base64url, base32, URL percent decoding, HTML
entity, binary 8-bit, decimal byte list, Morse, ROT13, dan reverse. Encoding
dikenali dari seluruh potongan, bukan parser untuk segala jenis container.
Base64 tidak otomatis berarti enkripsi.

`flags` memindai raw bytes dan string ASCII/UTF-16 yang disampel. Perintah
`flags` dan `decode` mendukung `--flag-prefix`.

### Morse dan Brainfuck

```bash
ctf-orbit misc morse "... --- ... / .-"
ctf-orbit misc brainfuck --file examples/data/misc/hello.bf
ctf-orbit misc brainfuck --text ",[.,]" --input "hello" --max-steps 10000
```

Morse memakai spasi antarhuruf dan `/` antarkata (tiga spasi juga diterima).
Interpreter Brainfuck memakai 30.000 cell 8-bit, EOF input=0, maksimal
100.000 token kode, default 200.000 langkah, dan maksimal 65.536 byte
output. `--max-steps` dapat dipilih sampai 2.000.000. Kurung tidak seimbang,
pointer keluar tape, dan loop yang melewati batas ditolak.

## 5. Crypto

### Caesar dan Vigenere

```bash
ctf-orbit crypto caesar "RUELW{fdhvdu}"
ctf-orbit crypto caesar "Khoor" --shift 3
ctf-orbit crypto vigenere "LXFOPVEFRNHR" --key LEMON
ctf-orbit crypto vigenere "ATTACKATDAWN" --key LEMON --encrypt
```

Caesar tanpa `--shift` mencoba 26 shift. Shift positif pada command ini
berarti **mengurangi** shift saat dekripsi; `Khoor` dengan 3 menjadi `Hello`.
Vigenere menggunakan key huruf ASCII, mempertahankan case/punctuation,
dan hanya memajukan posisi key pada karakter huruf.

### XOR

```bash
ctf-orbit crypto xor --file examples/data/crypto/xor.bin --top 5
ctf-orbit crypto xor --hex 202022 --key-text AB
ctf-orbit crypto xor --file cipher.bin --key-hex 414243
```

Input: tepat satu `--file`, `--text`, atau `--hex`, maksimal 64 KiB. Tanpa
key, command mencoba 256 key single-byte. `--key-text` atau `--key-hex`
melakukan XOR dengan key berulang; tidak mencari repeating key secara
otomatis. `--top` 1–256, default 10. English-like scoring dapat kurang tepat
untuk bahasa lain atau plaintext binary; `flags` tetap dikumpulkan dari
seluruh kandidat, bukan hanya kandidat yang ditampilkan.

### RSA textbook

```bash
ctf-orbit crypto rsa --n 3233 --e 17 --c 2790 --p 61 --q 53
ctf-orbit crypto rsa --n 3233 --e 17 --c 2790 --trial-limit 1000
ctf-orbit crypto rsa --n 3233 --e 17 --c 2790 --trial-limit 0 --fermat-steps 20
```

Hasil contoh: `m=65`, byte `41`, teks `A`.

| Opsi | Makna |
|---|---|
| `--n`, `--e`, `--c` | Integer decimal atau `0x...`; wajib |
| `--p`, `--q` | Faktor prima yang diketahui; memberi satu faktor cukup bila membagi n |
| `--trial-limit` | Nilai divisor maksimum yang dicoba, default 100.000, rentang 0–1.000.000 |
| `--fermat-steps` | Iterasi Fermat untuk faktor berdekatan, default 0, maksimum 1.000.000 |

Urutan: faktor diberikan, atau exact integer-root untuk e<=64, lalu trial
division, lalu Fermat bila diaktifkan. Faktor harus berbeda dan lolos tes
prima; untuk faktor >=2^64, pemeriksaan merupakan probable-prime check.
Integer dibatasi 8192 bit. Jika pencarian gagal, `method="unsolved"`.

Tidak melakukan factoring RSA modern secara umum, multiprime RSA, Wiener,
broadcast attack, atau pelepasan padding OAEP/PKCS#1. `d`, `m`, `p`, `q`
ditulis sebagai string agar presisi tetap utuh dalam konsumen JSON.

### Format hash

```bash
ctf-orbit crypto hash d41d8cd98f00b204e9800998ecf8427e
```

Ini mengidentifikasi **kemungkinan** algoritma berdasarkan bentuk/panjang,
termasuk bcrypt/Argon2 prefix. Tidak melakukan cracking atau membuktikan
algoritma dari hash saja.

## 6. Forensics

```bash
ctf-orbit forensics inspect examples/data/forensics/evidence.zip
ctf-orbit forensics inspect examples/data/forensics/memory.bin --out reports/memory-01
ctf-orbit forensics strings examples/data/forensics/memory.bin --min 4 --max 500
```

Laporan: ukuran, tipe berdasarkan magic, MD5/SHA-1/SHA-256, Shannon entropy
0–8 bit/byte, entropy block, kandidat signature/offset, strings dan flags.
Entropy tinggi dapat menunjukkan kompresi, enkripsi, atau data acak; tidak
membedakan ketiganya dengan sendirinya. Signature internal hanya kandidat.

Strings menyertakan offset byte dan encoding (`ascii`, `utf-16-le`,
`utf-16-be`). Panjang minimum 2–128, jumlah maksimum 1–10.000. Sampel string
panjang dipotong agar laporan tetap terbatas.

ZIP: maksimum 5.000 entri; central directory maksimal 8 MiB; multi-volume
ditolak. Sampel maksimal 50 entri, 256 KiB per entri, dan total 2 MiB.
Entri terenkripsi, file >8 MiB, atau rasio kompresi >200 dilewati. Path
traversal ditandai tetapi tidak diekstrak. Gzip didekompresi sebagai sampel
maksimal 2 MiB; `complete=false` menunjukkan stream belum habis. TAR,
7z, RAR, PDF object parsing, disk dan memory image mendalam tidak diparse;
sebagian signature tetap dideteksi.

### Carving

Cari signature dan offset melalui `inspect`, lalu:

```bash
ctf-orbit forensics carve examples/data/forensics/carrier.bin --offset 14 --signature png --save reports/carved.png
ctf-orbit forensics carve examples/data/forensics/memory.bin --offset 2 --length 21 --save reports/slice.bin
```

PNG mengikuti chunk sampai IEND tanpa memvalidasi CRC. JPEG memakai EOI
pertama sebagai heuristik. ZIP/PDF atau tanpa signature memakai offset
sampai EOF kecuali `--length` diberikan. Command tidak otomatis menentukan
ujung lengkap ZIP/PDF atau melakukan recursive extraction. `--length`
eksplisit harus berada di dalam file dan lebih dari nol.

## 7. Steganography

```bash
ctf-orbit stego inspect examples/data/stego/hidden.png
ctf-orbit stego image-lsb examples/data/stego/hidden.png --channels rgb --plane 0 --save reports/lsb-rgb.bin
ctf-orbit stego image-lsb examples/data/stego/hidden.png --channels bgr --bit-order lsb --skip-bits 0
ctf-orbit stego planes examples/data/stego/hidden.png --channel r --directory reports/planes-r
```

Gambar dibatasi 8.000.000 piksel. Decoder menormalkan warna menjadi RGBA
dan menggunakan scan baris dari kiri ke kanan, lalu kanal dalam urutan
`--channels` (unik, r/g/b/a). `--plane 0` mengambil LSB; plane 7 mengambil
MSB. Alpha harus benar-benar tersedia. Normalisasi palette/grayscale dapat
mengubah representasi indeks aslinya; decoder ini mencari bit pada piksel
warna hasil normalisasi, bukan pada raw palette index.

`--bit-order msb` menganggap bit yang dibaca pertama sebagai bit tinggi
dalam output byte. `lsb` memakai bit rendah terlebih dahulu. `--skip-bits`
melewati bit awal. Default `--limit-bytes` 131.072, maksimum 1.048.576.
Bit sisa yang belum membentuk byte lengkap dibuang; tidak otomatis berhenti
pada NUL atau terminator flag.

`planes` menghasilkan delapan PNG hitam-putih untuk satu kanal. Dependency
Pillow diperlukan untuk semua fitur gambar. Gambar animasi hanya dianalisis
frame pertama.

### Audio PCM WAV

```bash
ctf-orbit stego inspect examples/data/stego/audio.wav
ctf-orbit stego wav-lsb examples/data/stego/audio.wav --channel 0 --plane 0 --save reports/audio-lsb.bin
```

WAV LSB memakai byte paling rendah setiap sampel PCM integer little-endian,
mendukung sampel 8/16/24/32-bit. `--channel` adalah indeks mulai 0; tanpa
opsi, semua channel dibaca sesuai urutan frame. MP3, float WAV, codec
terkompresi, spectrogram dan frequency-domain stego belum didukung.

## 8. Reverse engineering

```bash
ctf-orbit reverse inspect examples/data/reverse/sample.elf
ctf-orbit reverse inspect examples/data/reverse/sample.exe
ctf-orbit reverse disasm examples/data/reverse/x64.raw --arch x64 --offset 0 --bytes 32 --base 0x400000
ctf-orbit reverse disasm examples/data/reverse/sample.elf --arch x64 --offset 0xb0 --bytes 6 --base 0x4000b0
```

`inspect` ELF menampilkan architecture, endian, entry, section, hingga 300
simbol, program header, NX dari GNU_STACK, kandidat PIE, RELRO, dan petunjuk
simbol canary. `NX_GNU_STACK=null` berarti header tidak ditemukan.
`canary_symbol_present` tidak membuktikan setiap fungsi memiliki canary.
PIE candidate mengacu ET_DYN dengan interpreter, bukan semua shared library.
Extended numbering ELF belum didukung secara umum.

PE menampilkan machine, image base, entry RVA, section, flag ASLR/NX/CFG.
Flag header tidak memverifikasi efektivitas mitigasi saat runtime.

Disassembly memerlukan extra `reverse` (Capstone). Architecture: `x86`,
`x64`, `arm`, `arm64`; `--thumb` hanya ARM. Offset adalah **offset file**;
`--base` adalah alamat label instruksi pertama, bukan auto-mapping virtual
address. `--bytes` 1–65.536. Jika decoding berhenti sebelum seluruh byte,
periksa arsitektur, mode, offset, atau batas instruksi. ARM/ARM64 command ini
menggunakan little-endian.

## 9. Pwn utilities

```bash
ctf-orbit pwn cyclic --length 200 --n 4 --save reports/pattern-4.bin
ctf-orbit pwn offset baaa --n 4
ctf-orbit pwn offset 0x61616162 --encoding int --endian little --n 4
ctf-orbit pwn pack 0xdeadbeef --bits 32 --endian little
ctf-orbit pwn unpack efbeadde --endian little
```

Pattern de Bruijn kompatibel dengan default lowercase pwntools. Contoh
`baaa` atau integer little-endian `0x61616162` menghasilkan offset **4**.
`n` 2–8; alphabet 2–64 karakter printable ASCII unik tanpa spasi. Panjang
pattern maksimal 1 MiB dan tidak boleh melebihi `len(alphabet)**n`.

Offset menerima `text`, `hex`, atau `int`; panjang needle harus tepat `n`
byte. Gunakan **n/alphabet yang sama** saat membuat dan mencari pattern.
Pencarian default dibatasi 1.000.000 byte, maksimum 1.048.576. `offset=null`
berarti belum ditemukan dalam rentang itu. Dengan n=8, gunakan byte crash
8-byte lengkap dan periksa endian.

Pack menerima unsigned integer 8/16/32/64-bit. Unpack menerima 1/2/4/8 byte.
Nilai tidak otomatis dipotong jika melampaui ukuran.

### Template lokal

```bash
ctf-orbit pwn template --directory challenges/pwn-lab
python challenges/pwn-lab/solve.py ./binary-latihan --line hello --timeout 2
```

Template menjalankan satu proses lokal hanya ketika script itu Anda panggil.
Ia mengirim baris input dan menampilkan respons; sesuaikan protokol dan
solver berdasarkan hasil analisis. Tidak ada shellcode, remote shell, atau
payload exploit universal yang dibuat otomatis. Pemasangan extra `pwn`
diperlukan untuk template; cyclic dan packing tetap memakai core.

## 10. Network dan PCAP

```bash
ctf-orbit network pcap examples/data/network/traffic.pcap --max-packets 5000 --out reports/network-01
ctf-orbit network pcap examples/data/network/traffic.pcap --save-streams reports/tcp-streams
```

Format: PCAP klasik v2.4, endian big/little dan timestamp micro/nanosecond.
Linktype Ethernet (VLAN sampai dua lapis), raw IP, DLT_IPV4/DLT_IPV6,
Linux SLL/SLL2. IPv4/IPv6 TCP/UDP dianalisis; sebagian extension header
IPv6 umum diteruskan. Linktype radio, USB, loopback BSD, dan protokol lain
tidak dianalisis.

`--max-packets` 1–20.000, default 5.000. Maksimal 512 directional flow,
512 segmen per flow, dan total 2 MiB payload TCP untuk reassembly. Segmen
diurutkan menurut sequence number; overlap mempertahankan data sebelumnya,
gap memisahkan chunk. Capture yang snaplen-nya memotong paket dicatat.
Check checksum paket bukan kemampuan parser ini.

Output meliputi flow/byte count, DNS questions, potongan HTTP, kandidat
flag dan alasan paket yang dilewati. Arah request/response tidak digabung;
IP fragment, sequence number wrap, atau reuse tuple pada sesi TCP berbeda
memerlukan tool lanjutan. TLS tidak didekripsi.

### Konversi PCAPNG

```bash
tshark -r challenge.pcapng -F pcap -w challenge.pcap
ctf-orbit network pcap challenge.pcap
```

Pastikan capture hanya memiliki satu tipe link yang dapat ditulis ke PCAP
klasik. Untuk capture/protokol kompleks, gunakan Wireshark/tshark langsung.

## 11. Web

Jalankan lab lokal terlebih dahulu sebagaimana README:

```bash
ctf-orbit web inspect http://127.0.0.1:8765/ --timeout 8 --max-bytes 1048576
ctf-orbit web paths http://127.0.0.1:8765/ --wordlist wordlists/web-small.txt --max-requests 20 --delay 0.2
ctf-orbit web paths http://127.0.0.1:8765/ --path /robots.txt --path /admin
ctf-orbit web html examples/data/osint/page.html
```

| Opsi | Batas/perilaku |
|---|---|
| `--timeout` | 0,1–30 detik per operasi socket; bukan deadline total seluruh batch |
| `--max-bytes` | 1–4.194.304 byte per body, default 1.048.576 |
| `--max-requests` | 1–100, default 20; path duplikat dideduplikasi |
| `--delay` | 0,05–10 detik antarrequest, default 0,2 |
| `--wordlist` | File UTF-8 maksimal 64 KiB, satu path per baris |
| `--path` | Dapat diulang; alternatif wordlist |

Tanpa wordlist/path, daftar default adalah `/`, `/robots.txt`, `/sitemap.xml`,
`/admin`, `/.well-known/security.txt`. Path memakai root origin, bukan
relative terhadap subfolder URL awal. Tidak mengikuti link/form, redirect,
atau mengirim metode selain GET. TLS diverifikasi. Cookie tidak disimpan
sebagai sesi; laporan menampilkan nama dan atribut cookie tanpa nilainya.
Body diminta tanpa kompresi; server yang tetap mengirim body terkompresi
mungkin tidak menghasilkan HTML yang terbaca.

Status HTTP, header, komentar, input name/form action, dan script URL
merupakan petunjuk. Header keamanan yang hilang bukan bukti exploit;
soft-404 perlu dibandingkan manual. URL yang mengandung username/password
ditolak. Tidak ada opsi brute-force login, SQLi/XSS payload, auth bypass,
atau crawler lintas-origin.

### JWT

```bash
ctf-orbit web jwt 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.'
```

Command memeriksa compact JWS tiga bagian (maksimal 64 KiB dan nesting JSON 32), decode JSON header/payload,
menandai `alg_none`, dan selalu mengembalikan `signature_verified=false`.
Tidak memverifikasi key, expiry, issuer/audience, atau keaslian claims.

## 12. OSINT dari artefak lokal

```bash
ctf-orbit osint inspect examples/data/osint/page.html --out reports/osint-01
```

Input maksimal 1 MiB. Hasil: URL, hostname, email, IPv4/IPv6, kandidat handle,
title/meta/link/comment HTML, dan flag. Pencarian hanya dilakukan di file
yang Anda berikan. Domain tidak di-resolve, URL tidak di-fetch, dan handle
tidak dipastikan sebagai akun nyata. Data umpan dari challenge dapat
menyerupai identitas asli; periksa konteks challenge.

## 13. Mobile/Android

```bash
ctf-orbit mobile apk examples/data/mobile/challenge.apk
ctf-orbit mobile dex examples/data/mobile/classes.dex
ctf-orbit mobile manifest examples/data/mobile/AndroidManifest.axml
```

APK diperlakukan sebagai ZIP. Parser menampilkan inventory, library native,
file sertifikat META-INF, permission, URL, string menarik, dan flag. Sampel
manifest/DEX maksimal 8 MiB, 10 file DEX, dan 5.000 string per DEX. String
yang sangat panjang disampel/dilewati.

Manifest teks XML atau string pool binary Android XML UTF-8/UTF-16 didukung.
Ini bukan rekonstruksi tree manifest; keberadaan string `exported` atau
`debuggable` tidak membuktikan nilai atribut. DEX standar dengan table string
versi 035/037/038/039/040 didukung; compact DEX dan container 041 belum didukung. MUTF-8 NUL dinormalisasi; surrogate pairs dapat
menjadi replacement character. Resource obfuscation/decompile memerlukan
analisis lain seperti JADX/apktool. Sertifikat dan APK signing block tidak
diverifikasi.

## 14. Blockchain

### Solidity source

```bash
ctf-orbit blockchain inspect examples/data/blockchain/Challenge.sol
```

Ekstrak pragma, function name, address, flag dan petunjuk penggunaan
`tx.origin`, `delegatecall`, low-level `.call`, `selfdestruct`, block
timestamp/number, dan `unchecked`. Komentar diabaikan untuk petunjuk kode.
Petunjuk regex bukan audit atau bukti exploit; konteks AST dan kontrol akses
tetap perlu dibaca.

### Selector, ABI dan EVM

```bash
ctf-orbit blockchain selector 'transfer(address,uint256)'
ctf-orbit blockchain abi --hex 0000000000000000000000000000000000000000000000000000000000000007 --types uint256
ctf-orbit blockchain evm --hex 60016002015f00
```

Selector memakai empat byte pertama **Keccak-256**, memerlukan extra crypto.
Signature diberikan persis dan harus kanonis: tulis `uint256`, bukan `uint`.
Keccak-256 berbeda dari `hashlib.sha3_256`. Contoh `transfer(address,uint256)`
harus menghasilkan `0xa9059cbb`.

ABI menerima hex maksimal 64 KiB dan word 32-byte. Gunakan `--has-selector`
untuk melepas empat byte selector calldata. Tipe dipisah koma pada `--types`:
`uintN`, `intN` (kelipatan 8 sampai 256), `address`, `bool`, `bytesN` (1–32).
Jumlah tipe harus sama dengan word dan padding kanonis diperiksa. Tanpa
tipe, tampilkan raw word/uint256/address candidate. Tipe dinamis, array, dan
tuple belum didukung.

EVM disassembly mengenali opcode umum, PUSH/DUP/SWAP/LOG dan mencatat
PUSH yang terpotong. Opcode lain ditulis `OP_XX`. Ini tidak memvalidasi fork,
mengikuti control flow, atau menjalankan kontrak. Tidak ada akses RPC,
wallet, atau transaksi dalam command blockchain.

## 15. Hardware/firmware

```bash
ctf-orbit hardware inspect examples/data/hardware/firmware.bin
ctf-orbit hardware ihex examples/data/hardware/firmware.hex --save reports/firmware.bin
```

`inspect` memakai signature/strings/entropy forensics dengan petunjuk
U-Boot, BusyBox, kernel, UART, bootargs, SquashFS/JFFS2/UBI. Signature hanya
menentukan kandidat offset, bukan validitas filesystem.

Intel HEX memeriksa record length/checksum, address range, EOF, extended
segment/linear address, start segment/linear address, dan overlap byte.
Gap diisi `0xff`. Output dimulai dari alamat data paling rendah; lihat
`base_address` untuk memetakan kembali binary ke alamat firmware. Batas total
data dan span alamat masing-masing 4 MiB. Tidak membaca UART/JTAG, melakukan
flashing, atau mengeksekusi firmware.

## 16. Membaca hasil yang tidak menemukan flag

Periksa `detected_type`, `modules.*.status`, `reason`, `preview_truncated`,
`file_limit_reached`, `packet_limit_reached`, atau batas sampel. Pilih potongan
file yang relevan, format/endianness/key/kanal yang benar, atau gunakan tool
lanjutan. Hasil heuristik kosong tidak membuktikan artefak tidak berisi flag.
Lihat [RECIPES.md](RECIPES.md) untuk latihan yang mempunyai hasil diketahui.
