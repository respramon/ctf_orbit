"""Single-origin bounded HTTP inspection and offline JWT/HTML helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .common import OrbitError, bounded, find_flags


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.scripts, self.comments, self.forms, self.meta, self.title = (
            [],
            [],
            [],
            [],
            {},
            "",
        )
        self._title = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self._title = True
        if tag in ("a", "link") and values.get("href") and len(self.links) < 1000:
            self.links.append(values["href"])
        if tag == "script" and values.get("src") and len(self.scripts) < 500:
            self.scripts.append(values["src"])
        if tag == "meta" and len(self.meta) < 100:
            key = values.get("name", values.get("property", ""))
            if key:
                self.meta[key] = values.get("content", "")[:2048]
        if tag == "form" and len(self.forms) < 100:
            self.forms.append(
                {"action": values.get("action", ""), "method": values.get("method", "get")}
            )
        if tag == "input" and self.forms and len(self.forms[-1].get("inputs", [])) < 100:
            self.forms[-1].setdefault("inputs", []).append(
                {"name": values.get("name", ""), "type": values.get("type", "text")}
            )

    def handle_endtag(self, tag):
        if tag == "title":
            self._title = False

    def handle_data(self, data):
        if self._title:
            self.title = (self.title + data)[:2048]

    def handle_comment(self, data):
        if len(self.comments) < 100:
            self.comments.append(data[:4096])


def html_info(text: str) -> dict:
    parser = PageParser()
    parser.feed(text)
    return {
        "title": parser.title,
        "links": sorted(set(parser.links)),
        "scripts": sorted(set(parser.scripts)),
        "comments": parser.comments,
        "forms": parser.forms,
        "meta": parser.meta,
        "flags": find_flags(text),
    }


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise OrbitError("URL/port tidak valid") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise OrbitError("Gunakan URL http:// atau https:// lengkap")
    if parsed.username is not None or parsed.password is not None:
        raise OrbitError("Credential di URL tidak didukung")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise OrbitError("URL mengandung karakter kontrol")
    if port is not None and not 1 <= port <= 65535:
        raise OrbitError("Port URL di luar rentang")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def fetch(url: str, timeout: float = 8, max_bytes: int = 1048576) -> dict:
    url = validate_url(url)
    if not 0.1 <= timeout <= 30:
        raise OrbitError("Timeout harus 0.1–30 detik")
    bounded(max_bytes, 1, 4 * 1024 * 1024, "Max bytes")
    # Do not follow redirects or automatically use ambient proxy credentials.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request(
        url,
        headers={
            "User-Agent": "CTF-Orbit/1.0 (CTF challenge inspection)",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            raw = raw[:max_bytes]
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                text = raw.decode(charset, "replace")
            except LookupError:
                text = raw.decode("utf-8", "replace")
            headers = {
                k.lower(): v for k, v in response.headers.items() if k.lower() != "set-cookie"
            }
            cookie_attributes = []
            for cookie in (response.headers.get_all("Set-Cookie") or [])[:50]:
                attrs = [p.strip() for p in cookie.split(";")[1:]]
                cookie_attributes.append({"name": cookie.split("=", 1)[0], "attributes": attrs})
            return {
                "url": url,
                "status": response.status,
                "headers": headers,
                "cookies": cookie_attributes,
                "bytes": len(raw),
                "truncated": truncated,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "html": html_info(text),
                "flags": find_flags(text),
                "missing_headers": [
                    h
                    for h in ("content-security-policy", "x-content-type-options")
                    if h not in headers
                ],
                "note": "Header hilang bukan bukti kerentanan; redirect dicatat tanpa diikuti",
            }
    except (URLError, TimeoutError, OSError) as exc:
        raise OrbitError(f"HTTP gagal: {exc}") from exc


def paths(
    url: str,
    entries: list[str],
    max_requests: int = 20,
    delay: float = 0.2,
    timeout: float = 8,
    max_bytes: int = 1048576,
) -> dict:
    target = validate_url(url)
    bounded(max_requests, 1, 100, "Max requests")
    if not 0.05 <= delay <= 10:
        raise OrbitError("Delay harus 0.05–10 detik")
    parsed = urlsplit(target)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
    selected = []
    for line in entries:
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        if path.startswith("//") or "\\" in path or ":" in path or "#" in path:
            raise OrbitError(f"Wordlist harus berupa path pada origin yang sama: {path}")
        normalized = "/" + path.lstrip("/")
        joined = validate_url(urljoin(origin, normalized))
        candidate = urlsplit(joined)
        if (candidate.scheme, candidate.netloc) != (parsed.scheme, parsed.netloc):
            raise OrbitError("Path keluar dari origin")
        if joined not in selected:
            selected.append(joined)
        if len(selected) >= max_requests:
            break
    results = []
    for index, endpoint in enumerate(selected):
        if index:
            time.sleep(delay)
        try:
            results.append(fetch(endpoint, timeout, max_bytes))
        except OrbitError as exc:
            results.append({"url": endpoint, "error": str(exc), "flags": []})
    return {
        "origin": origin,
        "requests": len(results),
        "results": results,
        "flags": sorted({f for result in results for f in result["flags"]}),
        "note": "Soft-404 perlu dibandingkan manual; status 200 tidak menjamin endpoint berbeda",
    }


def jwt_inspect(token: str) -> dict:
    if len(token) > 65536:
        raise OrbitError("JWT terlalu panjang")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise OrbitError("JWT compact JWS harus mempunyai 3 bagian")
    decoded = []
    for part in parts[:2]:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", part):
            raise OrbitError("JWT header/payload bukan base64url")
        try:
            value = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        except (ValueError, binascii.Error, UnicodeError, RecursionError) as exc:
            raise OrbitError("JWT tidak berisi JSON valid") from exc
        if not isinstance(value, dict):
            raise OrbitError("JWT header dan payload harus berupa object JSON")
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32:
                raise OrbitError("JWT JSON melewati batas nesting 32")
            if isinstance(item, dict):
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
        decoded.append(value)
    if parts[2] and not re.fullmatch(r"[A-Za-z0-9_-]+", parts[2]):
        raise OrbitError("Signature JWT bukan base64url")
    return {
        "header": decoded[0],
        "payload": decoded[1],
        "signature_verified": False,
        "alg_none": str(decoded[0].get("alg", "")).lower() == "none",
        "flags": find_flags(json.dumps(decoded)),
        "note": "Decode saja; tidak memverifikasi signature, keaslian, atau masa berlaku",
    }
