import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from helpers import HAS_CAPSTONE, HAS_IMAGE
from scripts.generate_examples import generate, make_axml, make_dex, make_elf, make_pe
from ctf_orbit import artifacts, binary, blockchain, hardware, mobile, osint, stego
from ctf_orbit.common import OrbitError


class FormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        generate(cls.root, with_image=HAS_IMAGE)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_memory_ascii_and_utf16_flags(self):
        result = artifacts.inspect((self.root / "forensics/memory.bin").read_bytes())
        self.assertIn("ORBIT{memory_strings}", result["flags"])
        self.assertIn("ORBIT{utf16_string}", result["flags"])

    def test_archive_sample_without_extraction(self):
        result = artifacts.inspect((self.root / "forensics/evidence.zip").read_bytes())
        self.assertIn("ORBIT{inside_zip}", result["flags"])
        self.assertEqual(result["archive"]["entries"][0]["name"], "notes.txt")

    def test_archive_traversal_and_bomb_detection(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../../outside", b"A" * 100000)
        result = artifacts.archive_inventory(buffer.getvalue())["entries"][0]
        self.assertTrue(result["unsafe_path"])
        self.assertIn("sample_skipped", result)

    def test_invalid_zip_eocd_entry_limit(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w"):
            pass
        raw = bytearray(buffer.getvalue())
        struct.pack_into("<HH", raw, 8, 5001, 5001)
        with self.assertRaises(OrbitError):
            artifacts.open_zip(raw)

    def test_elf_static_header(self):
        result = binary.elf_info(make_elf())
        self.assertEqual(result["bits"], 64)
        self.assertEqual(result["entry"], "0x4000b0")
        self.assertTrue(result["protections"]["NX_GNU_STACK"])
        self.assertFalse(result["protections"]["PIE_candidate"])
        with self.assertRaises(OrbitError):
            binary.elf_info(make_elf()[:60])

    def test_pe_header(self):
        result = binary.pe_info(make_pe())
        self.assertTrue(result["protections"]["ASLR_flag"])
        self.assertTrue(result["protections"]["NX_COMPAT_flag"])
        self.assertEqual(result["sections"][0]["offset"], 512)
        with self.assertRaises(OrbitError):
            binary.pe_info(b"MZ" + bytes(100))

    @unittest.skipUnless(HAS_CAPSTONE, "extra reverse tidak dipasang")
    def test_capstone_x64_vector(self):
        result = binary.disassemble(bytes.fromhex("b82a000000c3"), "x64")
        self.assertEqual([i["mnemonic"] for i in result["instructions"]], ["mov", "ret"])
        self.assertEqual(result["bytes_decoded"], 6)

    @unittest.skipUnless(HAS_IMAGE, "extra image tidak dipasang")
    def test_png_lsb_and_planes(self):
        data = (self.root / "stego/hidden.png").read_bytes()
        self.assertTrue(stego.image_lsb(data).startswith(b"ORBIT{png_lsb}\x00"))
        self.assertEqual(stego.image_info(data)["width"], 32)
        with tempfile.TemporaryDirectory() as directory:
            result = stego.bit_planes(data, directory)
            self.assertEqual(len(result["saved"]), 8)
            with self.assertRaises(OrbitError):
                stego.bit_planes(data, directory)

    @unittest.skipUnless(HAS_IMAGE, "extra image tidak dipasang")
    def test_png_carving_preserves_exact_file(self):
        data = (self.root / "forensics/carrier.bin").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "carved.png"
            artifacts.carve(data, 14, str(path), signature="png")
            self.assertEqual(path.read_bytes(), (self.root / "stego/hidden.png").read_bytes())

    def test_wav_lsb_sample_width(self):
        data = (self.root / "stego/audio.wav").read_bytes()
        self.assertEqual(stego.wav_info(data)["sample_width"], 2)
        self.assertTrue(stego.wav_lsb(data).startswith(b"ORBIT{wav_lsb}\x00"))
        with self.assertRaises(OrbitError):
            stego.wav_lsb(data, channel=1)

    def test_dex_and_axml_strings(self):
        values = ["hello", "ORBIT{mobile}"]
        self.assertEqual(mobile.dex_strings(make_dex(values)), values)
        self.assertEqual(mobile.axml_strings(make_axml(values)), values)
        self.assertEqual(mobile.axml_strings(make_axml(values, utf8=False)), values)

    def test_malformed_dex_and_axml(self):
        for data in (b"dex\n", bytes(112)):
            with self.subTest(data=data[:8]), self.assertRaises(OrbitError):
                mobile.dex_strings(data)
        raw = bytearray(make_axml(["hi"]))
        struct.pack_into("<I", raw, 12, 999999)
        with self.assertRaises(OrbitError):
            mobile.axml_strings(raw)

    def test_unsupported_dex_container_and_axml_bounds(self):
        dex = bytearray(make_dex(["fixture"]))
        dex[4:7] = b"041"
        with self.assertRaises(OrbitError):
            mobile.dex_strings(dex)
        xml = bytearray(make_axml(["fixture"]))
        struct.pack_into("<I", xml, 4, 1)
        with self.assertRaises(OrbitError):
            mobile.axml_strings(xml)

    def test_apk_static_inventory(self):
        result = mobile.inspect((self.root / "mobile/challenge.apk").read_bytes())
        self.assertIn("ORBIT{dex_string}", result["flags"])
        self.assertIn("android.permission.INTERNET", result["permissions"])

    def test_solidity_heuristic_ignores_comments(self):
        result = blockchain.inspect(
            b"// tx.origin\ncontract X { function f() public { x = tx.origin; } }"
        )
        self.assertEqual(result["clues"], [{"clue": "tx.origin", "line": 2}])

    def test_osint_offline_clues(self):
        result = osint.inspect((self.root / "osint/page.html").read_bytes())
        self.assertIn("team@example.test", result["emails"])
        self.assertIn("ctf.example.test", result["domains"])
        self.assertIn("192.0.2.10", result["ip_addresses"])
        self.assertIn("ORBIT{html_comment}", result["flags"])

    def test_intel_hex_checksum_and_address(self):
        data = (self.root / "hardware/firmware.hex").read_text()
        result = hardware.intel_hex(data)
        self.assertEqual(result["base_address"], "0x10010")
        self.assertIn("ORBIT{intel_hex}", result["flags"])
        with self.assertRaises(OrbitError):
            hardware.intel_hex(data.replace(":020000040001F9", ":02000004000100"))


if __name__ == "__main__":
    unittest.main()
