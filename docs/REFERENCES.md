# Referensi resmi

Dokumentasi primer berikut dipakai untuk memeriksa API/formats dan pilihan
dependensi. Diakses 30 September 2026 (zona waktu pengguna). Implementasi
CTF Orbit adalah subset sebagaimana dijelaskan pada tabel cakupan, bukan
klaim dukungan penuh terhadap semua format pada referensi.

| Topik | Referensi |
|---|---|
| Packaging dan extras | [Python Packaging User Guide: pyproject.toml](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/) |
| Distribusi Python | [Packaging Python Projects](https://packaging.python.org/en/latest/tutorials/packaging-projects/) |
| ZIP API | [Python zipfile](https://docs.python.org/3/library/zipfile.html) |
| ELF | [Linux man-pages elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html) |
| PCAP format | [libpcap pcap-savefile manual source](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in) |
| Image parser limits | [Pillow security](https://pillow.readthedocs.io/en/stable/handbook/security.html) |
| Pillow formats | [Pillow image file formats](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html) |
| Capstone Python | [Capstone language API](https://www.capstone-engine.org/lang_python.html) |
| Cyclic sequences | [pwntools cyclic](https://docs.pwntools.com/en/stable/util/cyclic.html) |
| pwntools instalasi | [pwntools install](https://docs.pwntools.com/en/stable/install.html) |
| Keccak API | [PyCryptodome Keccak](https://pycryptodome.readthedocs.io/en/latest/src/hash/keccak.html) |
| Ethereum ABI | [Solidity Contract ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html) |
| DEX format | [Android Open Source Project: DEX format](https://source.android.com/docs/core/runtime/dex-format) |
| Android risk context | [Android Developers security risks](https://developer.android.com/privacy-and-security/risks) |
| CI checkout | [actions/checkout](https://github.com/actions/checkout) |
| CI Python runtime | [actions/setup-python](https://github.com/actions/setup-python) |

Distribusi extras: [Pillow](https://pypi.org/project/Pillow/),
[PyCryptodome](https://pypi.org/project/pycryptodome/),
[Capstone](https://pypi.org/project/capstone/),
[pwntools](https://pypi.org/project/pwntools/).

Keccak Ethereum tidak boleh diganti SHA3-256 standar. Integers, endian,
offset file versus virtual address, dan dukungan versi container harus
divalidasi saat menambah parser. Lihat `docs/TESTING.md` untuk versi yang
benar-benar dipakai dalam verifikasi source ini.
