import base64
import json
import os
import socket
import struct
import threading
import unittest
from http.server import HTTPServer

from helpers import ROOT  # noqa: F401
from scripts.generate_examples import make_pcap
from examples.web_lab import Handler
from ctf_orbit import network, web
from ctf_orbit.common import OrbitError


class NetworkTests(unittest.TestCase):
    def test_endianness_micro_and_nanoseconds(self):
        for endian in ("<", ">"):
            for nano in (True, False):
                with self.subTest(endian=endian, nano=nano):
                    result = network.inspect(make_pcap(endian, nano))
                    self.assertEqual(result["packets_processed"], 5)
                    self.assertIn("ORBIT{tcp_reassembled}", result["flags"])
                    self.assertIn("ORBIT{udp_payload}", result["flags"])
                    self.assertEqual(result["dns_questions"][0]["name"], "ctf.example.test")

    def test_tcp_retransmission_overlap_and_gap(self):
        chunks, gaps = network.reconstruct(
            [(13, b"def"), (10, b"abcd"), (10, b"abcd"), (30, b"tail")]
        )
        self.assertEqual(chunks, [b"abcdef", b"tail"])
        self.assertEqual(gaps, 1)

    def test_packet_limit_and_truncated_pcap(self):
        self.assertTrue(network.inspect(make_pcap(), max_packets=1)["packet_limit_reached"])
        with self.assertRaises(OrbitError):
            network.inspect(make_pcap()[:-1])
        with self.assertRaises(OrbitError):
            network.inspect(bytes.fromhex("0a0d0d0a"))

    def test_ipv6_udp(self):
        src, dst = (
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        )
        payload = b"hello"
        udp = struct.pack("!HHHH", 10, 20, len(payload) + 8, 0) + payload
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, src, dst) + udp
        result = network.packet_payload(ip, 101)
        self.assertEqual(result["src"], "2001:db8::1")
        self.assertEqual(result["payload"], b"hello")

    def test_dns_pointer_cycle(self):
        with self.assertRaises(OrbitError):
            network.dns_name(b"\xc0\x00", 0)

    def test_invalid_wordlist_blocked_before_network(self):
        for value in ("//evil.example/", "https://evil.example/x", "\\evil", "/x#fragment"):
            with self.subTest(value=value), self.assertRaises(OrbitError):
                web.paths("http://127.0.0.1:1", [value])

    def test_url_credentials_and_scheme(self):
        for value in (
            "file:///tmp/x",
            "https://user:pass@example.test/",
            "http://example.test:99999/",
            "http://example.test/\n",
        ):
            with self.subTest(value=value), self.assertRaises(OrbitError):
                web.validate_url(value)

    def test_jwt_unverified_claims(self):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

        token = (
            encode({"alg": "none"}) + "." + encode({"sub": "lab", "hint": "ORBIT{jwt_claim}"}) + "."
        )
        result = web.jwt_inspect(token)
        self.assertFalse(result["signature_verified"])
        self.assertTrue(result["alg_none"])
        self.assertIn("ORBIT{jwt_claim}", result["flags"])
        with self.assertRaises(OrbitError):
            web.jwt_inspect("x.y")

    def test_jwt_rejects_deep_json(self):
        payload = '{"x":' * 40 + "0" + "}" * 40
        body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        with self.assertRaises(OrbitError):
            web.jwt_inspect("eyJhbGciOiJub25lIn0." + body + ".")


@unittest.skipIf(os.getenv("ORBIT_SKIP_HTTP") == "1", "HTTP localhost sengaja dilewati")
class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_live_local_inspect(self):
        result = web.fetch(self.url + "/admin")
        self.assertEqual(result["status"], 200)
        self.assertIn("ORBIT{local_web_lab}", result["flags"])

    def test_redirect_not_followed(self):
        result = web.fetch(self.url + "/redirect")
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["headers"]["location"], "https://example.test/out-of-scope")

    def test_paths_request_limit_and_origin(self):
        result = web.paths(self.url, ["/", "/robots.txt", "/admin"], max_requests=2, delay=0.05)
        self.assertEqual(result["requests"], 2)
        self.assertTrue(all(r["url"].startswith(self.url) for r in result["results"]))

    def test_http_body_limit(self):
        result = web.fetch(self.url, max_bytes=16)
        self.assertEqual(result["bytes"], 16)
        self.assertTrue(result["truncated"])


if __name__ == "__main__":
    unittest.main()
