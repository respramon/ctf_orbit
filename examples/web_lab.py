#!/usr/bin/env python3
"""Small local HTTP challenge. Bind only to loopback; stop with Ctrl+C."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

ROUTES = {
    "/": (
        "text/html",
        '<html><head><title>CTF Orbit Lab</title></head><body><a href="/robots.txt">robots</a><script src="/assets/app.js"></script><!-- clue: check /admin --></body></html>',
    ),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\n"),
    "/sitemap.xml": ("application/xml", "<urlset><url><loc>/admin</loc></url></urlset>"),
    "/admin": ("text/html", "<h1>Lab flag</h1>ORBIT{local_web_lab}"),
    "/assets/app.js": ("text/javascript", 'const hint = "/admin";'),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.test/out-of-scope")
            self.end_headers()
            return
        content_type, text = ROUTES.get(self.path, ("text/plain", "Not found"))
        body = text.encode()
        self.send_response(200 if self.path in ROUTES else 404)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"CTF Orbit web lab: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
