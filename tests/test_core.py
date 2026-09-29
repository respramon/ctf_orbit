import base64
import json
import tempfile
import unittest
from pathlib import Path

from helpers import HAS_CRYPTO, HAS_PWN  # noqa: F401
from ctf_orbit import blockchain, codecs, crypto, pwn
from ctf_orbit.common import OrbitError, emit, entropy, find_flags, hex_bytes, read_file, write_new


class CoreTests(unittest.TestCase):
    def test_nested_hex_base64(self):
        data = base64.b64encode(b"ORBIT{decode_ok}".hex().encode())
        result = codecs.decode_layers(data)
        self.assertIn("ORBIT{decode_ok}", result["flags"])
        self.assertTrue(any(c["chain"] == ["base64", "hex"] for c in result["candidates"]))

    def test_url_html_binary_decimal(self):
        for payload in (b"ORBIT%7Burl%7D", b"CTF&#123;html&#125;", b"01000001 01000010", b"65,66"):
            with self.subTest(payload=payload):
                results = codecs.decode_layers(payload)["candidates"]
                self.assertTrue(any(c["chain"] != ["input"] for c in results))
        self.assertIn("CTF{html}", codecs.decode_layers(b"CTF&#123;html&#125;")["flags"])

    def test_decoder_limit(self):
        self.assertLessEqual(codecs.decode_layers(b"aGVsbG8=", max_nodes=3)["nodes_visited"], 3)
        with self.assertRaises(OrbitError):
            codecs.decode_layers(b"A" * (256 * 1024 + 1))

    def test_custom_flags_literal(self):
        self.assertEqual(find_flags("GEMASTIK{test}", ("GEMASTIK",)), ["GEMASTIK{test}"])
        with self.assertRaises(OrbitError):
            find_flags("x", (".*",))
        self.assertEqual(find_flags("xORBIT{false_prefix}"), [])

    def test_entropy_known(self):
        self.assertEqual(entropy(b"AAAA"), 0)
        self.assertEqual(entropy(bytes(range(256))), 8)

    def test_exclusive_writes_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "input.bin"
            write_new(file, b"original")
            with self.assertRaises(FileExistsError):
                write_new(file, b"modified")
            self.assertEqual(file.read_bytes(), b"original")
            result = emit({"flags": ["ORBIT{report}"]}, "test", str(Path(tmp) / "reports"))
            self.assertEqual(
                json.loads((Path(tmp) / "reports/report.json").read_text())["schema_version"], 1
            )
            self.assertIn("ORBIT{report}", (Path(tmp) / "reports/report.md").read_text())
            self.assertIn("generated_at", result)
            with self.assertRaises(OrbitError):
                emit({}, "test", str(Path(tmp) / "reports"))

    def test_file_limit_and_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x"
            path.write_bytes(b"12345")
            with self.assertRaises(OrbitError):
                read_file(path, 4)
        self.assertEqual(hex_bytes("0x41 42"), b"AB")
        with self.assertRaises(OrbitError):
            hex_bytes("A")

    def test_caesar_known(self):
        result = crypto.caesar("RUELW{fdhvdu}")
        self.assertIn("ORBIT{caesar}", result["flags"])
        self.assertEqual(crypto.caesar("Khoor", 3)["candidates"][0]["text"], "Hello")

    def test_vigenere_published_vector(self):
        self.assertEqual(crypto.vigenere("LXFOPVEFRNHR", "LEMON")["text"], "ATTACKATDAWN")
        self.assertEqual(crypto.vigenere("ATTACKATDAWN", "LEMON", True)["text"], "LXFOPVEFRNHR")
        with self.assertRaises(OrbitError):
            crypto.vigenere("x", "")

    def test_single_byte_xor(self):
        plain = b"ORBIT{xor_ok}"
        result = crypto.xor(bytes(c ^ 0x42 for c in plain))
        self.assertEqual(result["candidates"][0]["key_hex"], "42")
        self.assertIn(plain.decode(), result["flags"])

    def test_repeating_key_xor(self):
        self.assertEqual(crypto.xor(b"\x20\x20\x22", b"AB")["candidates"][0]["hex"], "616263")
        with self.assertRaises(OrbitError):
            crypto.xor(b"x", b"")

    def test_textbook_rsa_known_vector(self):
        result = crypto.rsa(3233, 17, 2790, p=61, q=53)
        self.assertEqual(result["m"], "65")
        self.assertEqual(result["text"], "A")
        self.assertEqual(crypto.rsa(3233, 17, 2790)["m"], "65")

    def test_rsa_other_paths(self):
        self.assertEqual(crypto.rsa(1000000007, 3, 65**3, trial_limit=0)["m"], "65")
        self.assertEqual(crypto.rsa(61 * 53, 17, 2790, trial_limit=0, fermat_steps=20)["m"], "65")
        self.assertEqual(crypto.rsa(3233, 17, 2790, trial_limit=0)["method"], "unsolved")

    def test_rsa_invalid_inputs(self):
        for parameters in ((3233, 17, 3233), (25, 3, 1, 5, 5), (3233, 12, 1, 61, 53)):
            with self.subTest(parameters=parameters), self.assertRaises(OrbitError):
                crypto.rsa(*parameters)

    def test_hash_ambiguity(self):
        self.assertGreater(len(crypto.hash_identify("a" * 32)["possible_algorithms"]), 1)

    def test_cyclic_known_offsets_and_uniqueness(self):
        sequence = pwn.cyclic(200)
        self.assertEqual(sequence[:20], b"aaaabaaacaaadaaaeaaa")
        self.assertEqual(pwn.offset("0x61616162", "int")["offset"], 4)
        self.assertEqual(pwn.offset("baaa")["offset"], 4)
        windows = [sequence[i : i + 4] for i in range(len(sequence) - 3)]
        self.assertEqual(len(windows), len(set(windows)))

    def test_cyclic_64bit_and_bounds(self):
        sequence = pwn.cyclic(512, n=8)
        self.assertEqual(
            pwn.offset(sequence[200:208].hex(), "hex", n=8, max_length=512)["offset"], 200
        )
        with self.assertRaises(OrbitError):
            pwn.cyclic(20, "aa")
        with self.assertRaises(OrbitError):
            pwn.offset("abcdef", n=4)

    @unittest.skipUnless(HAS_PWN, "extra pwn tidak dipasang")
    def test_pwntools_interoperability(self):
        from pwnlib.util.cyclic import cyclic as official_cyclic

        self.assertEqual(pwn.cyclic(256), official_cyclic(256))

    def test_pack_vector(self):
        self.assertEqual(pwn.pack(0xDEADBEEF, 32)["hex"], "efbeadde")
        self.assertEqual(pwn.unpack(bytes.fromhex("efbeadde"))["value_hex"], "0xdeadbeef")
        with self.assertRaises(OrbitError):
            pwn.pack(256, 8)

    def test_morse_and_brainfuck(self):
        self.assertEqual(codecs.morse_decode("... --- ... / .-"), "SOS A")
        self.assertEqual(codecs.brainfuck("++++++++[>++++++++<-]>+.")["text"], "A")
        self.assertEqual(codecs.brainfuck(",[.,]", b"Hi")["text"], "Hi")
        for program in ("[", "<", "+[]"):
            with self.subTest(program=program), self.assertRaises(OrbitError):
                codecs.brainfuck(program, max_steps=50)

    @unittest.skipUnless(HAS_CRYPTO, "extra crypto tidak dipasang")
    def test_keccak_ethereum_selector(self):
        self.assertEqual(blockchain.selector("transfer(address,uint256)")["selector"], "0xa9059cbb")

    def test_abi_static_types_and_canonical_padding(self):
        words = (
            (7).to_bytes(32, "big") + bytes(12) + bytes.fromhex("11" * 20) + (1).to_bytes(32, "big")
        )
        result = blockchain.abi_decode(
            "a9059cbb" + words.hex(), ["uint256", "address", "bool"], True
        )
        self.assertEqual(result["words"][0]["value"], "7")
        self.assertEqual(result["words"][1]["value"], "0x" + "11" * 20)
        self.assertTrue(result["words"][2]["value"])
        self.assertEqual(blockchain.abi_decode("ff" * 32, ["int8"])["words"][0]["value"], "-1")
        for value, kind in (
            ("00" * 31 + "02", "bool"),
            ("01" + "00" * 31, "address"),
            ("00" * 31 + "ff", "int8"),
        ):
            with self.subTest(kind=kind), self.assertRaises(OrbitError):
                blockchain.abi_decode(value, [kind])

    def test_evm_push_boundaries(self):
        operations = blockchain.evm_disassemble("60016002015f00")["instructions"]
        self.assertEqual(
            [op["opcode"] for op in operations], ["PUSH1", "PUSH1", "ADD", "PUSH0", "STOP"]
        )
        self.assertTrue(blockchain.evm_disassemble("61ff")["instructions"][0]["truncated"])


if __name__ == "__main__":
    unittest.main()
