"""Offline challenge clues; no person lookup or social-account scraping."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .common import find_flags
from .web import html_info


def inspect(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    urls = sorted({u.rstrip(".,);]'\"") for u in re.findall(r"https?://[^\s<>\"']{1,2048}", text)})[
        :1000
    ]
    domains = set()
    for url in urls:
        try:
            host = urlsplit(url).hostname
            if host:
                domains.add(host)
        except ValueError:
            pass
    emails = sorted(
        set(re.findall(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b", text))
    )[:500]
    addresses = set()
    for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)[:2000]:
        try:
            addresses.add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass
    for token in re.split(r"[\s,<>()\[\]]+", text[:262144]):
        if ":" in token:
            try:
                addresses.add(str(ipaddress.ip_address(token.strip("\"';"))))
            except ValueError:
                pass
    handles = sorted(set(re.findall(r"(?<![\w.])@[A-Za-z_][A-Za-z0-9_]{1,31}\b", text)))[:500]
    return {
        "urls": urls,
        "domains": sorted(domains),
        "emails": emails,
        "ip_addresses": sorted(addresses)[:500],
        "handle_candidates": handles,
        "html": html_info(text),
        "flags": find_flags(text),
        "note": "Petunjuk dari artefak lokal; alamat/handle belum diverifikasi dan URL tidak dibuka",
    }
