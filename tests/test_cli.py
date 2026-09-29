import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import HAS_CAPSTONE, HAS_CRYPTO, HAS_IMAGE, ROOT
from scripts.generate_examples import generate
from ctf_orbit import pipeline


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.data = Path(cls.temp.name) / "data"
        generate(cls.data, with_image=HAS_IMAGE)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_cli(self, *args, expected=0):
        result = subprocess.run(
            [sys.executable, str(ROOT / "run.py"), *map(str, args)],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=30,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return json.loads(result.stdout if expected == 0 else result.stderr)

    def test_every_core_command(self):
        cases = [
            ("doctor",),
            ("misc", "decode", "--file", self.data / "misc/layers.txt"),
            ("misc", "flags", self.data / "forensics/memory.bin"),
            ("misc", "morse", "... --- ..."),
            ("misc", "brainfuck", "--file", self.data / "misc/hello.bf"),
            ("crypto", "caesar", "Khoor", "--shift", "3"),
            ("crypto", "vigenere", "LXFOPVEFRNHR", "--key", "LEMON"),
            ("crypto", "xor", "--file", self.data / "crypto/xor.bin"),
            ("crypto", "rsa", "--n", "3233", "--e", "17", "--c", "2790"),
            ("crypto", "hash", "a" * 32),
            ("forensics", "inspect", self.data / "forensics/evidence.zip"),
            ("forensics", "strings", self.data / "forensics/memory.bin"),
            ("reverse", "inspect", self.data / "reverse/sample.elf"),
            ("pwn", "cyclic", "--length", "200"),
            ("pwn", "offset", "baaa"),
            ("pwn", "pack", "0xdeadbeef", "--bits", "32"),
            ("pwn", "unpack", "efbeadde"),
            ("stego", "inspect", self.data / "stego/audio.wav"),
            ("stego", "wav-lsb", self.data / "stego/audio.wav"),
            ("network", "pcap", self.data / "network/traffic.pcap"),
            ("web", "html", self.data / "osint/page.html"),
            ("web", "jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."),
            ("osint", "inspect", self.data / "osint/page.html"),
            ("mobile", "apk", self.data / "mobile/challenge.apk"),
            ("mobile", "dex", self.data / "mobile/classes.dex"),
            ("mobile", "manifest", self.data / "mobile/AndroidManifest.axml"),
            ("blockchain", "inspect", self.data / "blockchain/Challenge.sol"),
            ("blockchain", "abi", "--hex", "00" * 31 + "07", "--types", "uint256"),
            ("blockchain", "evm", "--hex", "600160020100"),
            ("hardware", "inspect", self.data / "hardware/firmware.bin"),
            ("hardware", "ihex", self.data / "hardware/firmware.hex"),
        ]
        for args in cases:
            with self.subTest(command=args[:2]):
                self.assertEqual(self.run_cli(*args)["schema_version"], 1)

    def test_automatic_pipeline_discovers_expected_flags(self):
        result = pipeline.analyze(str(self.data), recursive=True)
        expected = {
            "ORBIT{layered_decode}",
            "ORBIT{single_byte_xor}",
            "ORBIT{memory_strings}",
            "ORBIT{utf16_string}",
            "ORBIT{inside_zip}",
            "ORBIT{static_reverse}",
            "ORBIT{static_pe}",
            "ORBIT{tcp_reassembled}",
            "ORBIT{udp_payload}",
            "ORBIT{html_comment}",
            "ORBIT{dex_string}",
            "ORBIT{solidity_hint}",
            "ORBIT{firmware_strings}",
            "ORBIT{intel_hex}",
            "ORBIT{wav_lsb}",
        }
        if HAS_IMAGE:
            expected.add("ORBIT{png_lsb}")
        self.assertTrue(expected.issubset(result["flags"]), expected - set(result["flags"]))
        self.assertEqual(result["errors"], [])

    def test_cli_reports_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "report"
            result = self.run_cli("analyze", self.data / "misc/layers.txt", "--out", folder)
            self.assertEqual(len(result["saved_reports"]), 2)
            self.run_cli("analyze", self.data / "misc/layers.txt", "--out", folder, expected=2)

    def test_category_all_reports_skips(self):
        result = pipeline.analyze(str(self.data / "misc/layers.txt"), category="all")
        modules = result["files"][0]["modules"]
        self.assertEqual(set(modules), set(pipeline.CATEGORIES))
        self.assertEqual(modules["network"]["status"], "skipped")

    def test_custom_flag_in_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "encoded.txt"
            file.write_text("47454d415354494b7b637573746f6d7d")
            result = self.run_cli("analyze", file, "--flag-prefix", "GEMASTIK")
            self.assertIn("GEMASTIK{custom}", result["flags"])

    def test_init_and_packaged_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "lab"
            result = self.run_cli("init", "lab", "--category", "crypto", "--directory", folder)
            self.assertEqual(result["metadata"]["category"], "crypto")
            self.assertTrue((folder / "solve.py").is_file())
            self.run_cli("init", "lab", "--directory", folder, expected=2)
            self.run_cli("pwn", "template", "--directory", Path(tmp) / "pwn")

    def test_binary_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.run_cli(
                "forensics",
                "carve",
                self.data / "forensics/memory.bin",
                "--offset",
                "0",
                "--length",
                "2",
                "--save",
                folder / "slice.bin",
            )
            self.assertEqual((folder / "slice.bin").read_bytes(), b"\x00\x01")
            self.run_cli("pwn", "cyclic", "--length", "32", "--save", folder / "pattern.bin")
            self.run_cli(
                "hardware",
                "ihex",
                self.data / "hardware/firmware.hex",
                "--save",
                folder / "firmware.bin",
            )
            self.run_cli(
                "network",
                "pcap",
                self.data / "network/traffic.pcap",
                "--save-streams",
                folder / "streams",
            )
            self.assertTrue(list((folder / "streams").glob("*.bin")))

    def test_limits_and_error_exit(self):
        self.run_cli("pwn", "cyclic", "--length", "0", expected=2)
        self.run_cli("misc", "decode", "--text", "x", "--depth", "9", expected=2)
        self.run_cli("hardware", "ihex", self.data / "misc/layers.txt", expected=2)
        result = pipeline.analyze(str(self.data), recursive=True, max_files=2)
        self.assertEqual(result["files_analyzed"], 2)
        self.assertTrue(result["file_limit_reached"])

    @unittest.skipUnless(HAS_IMAGE, "extra image tidak dipasang")
    def test_image_cli_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = self.data / "stego/hidden.png"
            self.run_cli("stego", "image-lsb", file, "--save", Path(tmp) / "hidden.bin")
            self.run_cli("stego", "planes", file, "--directory", Path(tmp) / "planes")
            self.run_cli("stego", "inspect", file)

    @unittest.skipUnless(HAS_CAPSTONE, "extra reverse tidak dipasang")
    def test_reverse_cli(self):
        self.run_cli("reverse", "disasm", self.data / "reverse/x64.raw", "--arch", "x64")

    @unittest.skipUnless(HAS_CRYPTO, "extra crypto tidak dipasang")
    def test_blockchain_selector_cli(self):
        self.assertEqual(
            self.run_cli("blockchain", "selector", "transfer(address,uint256)")["selector"],
            "0xa9059cbb",
        )


if __name__ == "__main__":
    unittest.main()
