"""Classic PCAP parser with bounded directional TCP reconstruction."""

from __future__ import annotations

import ipaddress
import re
import struct
from collections import Counter
from pathlib import Path

from .common import OrbitError, bounded, find_flags, preview, write_new

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),
    b"\xa1\xb2\xc3\xd4": (">", 1000000),
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),
}


def dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels, seen, end = [], set(), None
    for _ in range(128):
        if offset >= len(data) or offset in seen:
            raise OrbitError("DNS name terpotong atau pointer berputar")
        seen.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise OrbitError("DNS pointer terpotong")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length > 63:
            raise OrbitError("DNS label tidak valid")
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        if offset + length > len(data):
            raise OrbitError("DNS label terpotong")
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    raise OrbitError("DNS name terlalu panjang")


def dns_questions(data: bytes) -> list[dict]:
    if len(data) < 12:
        return []
    count = int.from_bytes(data[4:6], "big")
    offset, found = 12, []
    for _ in range(min(count, 20)):
        name, offset = dns_name(data, offset)
        if offset + 4 > len(data):
            raise OrbitError("DNS question terpotong")
        kind, cls = struct.unpack_from("!HH", data, offset)
        found.append({"name": name, "type": kind, "class": cls})
        offset += 4
    return found


def packet_payload(frame: bytes, linktype: int) -> dict:
    if linktype == 1:
        if len(frame) < 14:
            raise OrbitError("Ethernet header terpotong")
        proto, offset = int.from_bytes(frame[12:14], "big"), 14
        for _ in range(2):
            if proto in (0x8100, 0x88A8):
                if offset + 4 > len(frame):
                    raise OrbitError("VLAN header terpotong")
                proto = int.from_bytes(frame[offset + 2 : offset + 4], "big")
                offset += 4
        if proto not in (0x0800, 0x86DD):
            raise OrbitError("Ethernet non-IP")
        ip = frame[offset:]
    elif linktype == 113:
        if len(frame) < 16 or int.from_bytes(frame[14:16], "big") not in (0x0800, 0x86DD):
            raise OrbitError("Linux cooked SLL non-IP/terpotong")
        ip = frame[16:]
    elif linktype == 276:
        if len(frame) < 20 or int.from_bytes(frame[:2], "big") not in (0x0800, 0x86DD):
            raise OrbitError("Linux cooked SLL2 non-IP/terpotong")
        ip = frame[20:]
    elif linktype in (101, 228, 229):
        ip = frame
    else:
        raise OrbitError(f"Linktype {linktype} belum didukung")
    if not ip:
        raise OrbitError("Paket IP kosong")
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            raise OrbitError("IPv4 header terpotong")
        header_size = (ip[0] & 15) * 4
        total_size = int.from_bytes(ip[2:4], "big")
        if header_size < 20 or header_size > len(ip) or total_size < header_size:
            raise OrbitError("IPv4 length tidak valid")
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            raise OrbitError("IPv4 fragment; reassembly IP belum didukung")
        src, dst = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
        proto = ip[9]
        transport = ip[header_size : min(total_size, len(ip))]
    elif version == 6:
        if len(ip) < 40:
            raise OrbitError("IPv6 header terpotong")
        src, dst = str(ipaddress.ip_address(ip[8:24])), str(ipaddress.ip_address(ip[24:40]))
        size, proto, offset = int.from_bytes(ip[4:6], "big"), ip[6], 40
        if size == 0:
            raise OrbitError("IPv6 jumbogram belum didukung")
        ip = ip[: min(len(ip), 40 + size)]
        for _ in range(8):
            if proto not in (0, 43, 60, 51):
                break
            if offset + 2 > len(ip):
                raise OrbitError("IPv6 extension terpotong")
            following, units = ip[offset], ip[offset + 1]
            offset += (units + 2) * 4 if proto == 51 else (units + 1) * 8
            if offset > len(ip):
                raise OrbitError("IPv6 extension length tidak valid")
            proto = following
        if proto == 44:
            raise OrbitError("IPv6 fragment; reassembly IP belum didukung")
        transport = ip[offset:]
    else:
        raise OrbitError("Versi IP tidak didukung")
    if proto == 6:
        if len(transport) < 20:
            raise OrbitError("TCP header terpotong")
        sport, dport, seq = struct.unpack_from("!HHI", transport)
        header = (transport[12] >> 4) * 4
        if header < 20 or header > len(transport):
            raise OrbitError("TCP data offset tidak valid")
        payload = transport[header:]
        return {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "protocol": "TCP",
            "sequence": (seq + bool(transport[13] & 2)) % (2**32),
            "payload": payload,
        }
    if proto == 17:
        if len(transport) < 8:
            raise OrbitError("UDP header terpotong")
        sport, dport, size = struct.unpack_from("!HHH", transport)
        if size < 8:
            raise OrbitError("UDP length tidak valid")
        return {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "protocol": "UDP",
            "payload": transport[8 : min(size, len(transport))],
        }
    raise OrbitError(f"Protokol IP {proto} belum dianalisis")


def reconstruct(segments: list[tuple[int, bytes]]) -> tuple[list[bytes], int]:
    chunks, current, next_seq, gaps = [], bytearray(), None, 0
    for seq, payload in sorted(segments, key=lambda item: item[0]):
        if next_seq is None or seq > next_seq:
            if current:
                chunks.append(bytes(current))
                current.clear()
                gaps += 1
            current.extend(payload)
            next_seq = seq + len(payload)
        else:
            overlap = next_seq - seq
            if overlap < len(payload):
                current.extend(payload[overlap:])
                next_seq = seq + len(payload)
    if current:
        chunks.append(bytes(current))
    return chunks, gaps


def inspect(data: bytes, max_packets: int = 5000, save_streams: str | None = None) -> dict:
    bounded(max_packets, 1, 20000, "Max packets")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise OrbitError(
            "PCAPNG belum didukung. Konversi: tshark -r input.pcapng -F pcap -w output.pcap"
        )
    if data[:4] not in PCAP_MAGICS or len(data) < 24:
        raise OrbitError("Header PCAP klasik tidak valid")
    endian, resolution = PCAP_MAGICS[data[:4]]
    major, minor, _, _, snaplen, link_raw = struct.unpack_from(endian + "HHIIII", data, 4)
    linktype = link_raw & 0xFFFF
    if (major, minor) != (2, 4) or not snaplen:
        raise OrbitError("PCAP membutuhkan format versi 2.4 dan snaplen positif")
    if linktype not in (1, 101, 113, 228, 229, 276):
        raise OrbitError(f"Linktype {linktype} belum didukung (Ethernet/raw IP/SLL/SLL2 saja)")
    pos, count, budget = 24, 0, 2 * 1024 * 1024
    flows, dns, flags, skipped = {}, {}, set(), Counter()
    capture_truncated, payload_limit = False, False
    while pos < len(data) and count < max_packets:
        if pos + 16 > len(data):
            raise OrbitError("PCAP record header terpotong")
        seconds, subseconds, size, original = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if size > snaplen or size > original or pos + size > len(data) or subseconds >= resolution:
            raise OrbitError("PCAP record length/timestamp tidak valid atau terpotong")
        frame, pos, count = data[pos : pos + size], pos + size, count + 1
        capture_truncated |= size < original
        try:
            packet = packet_payload(frame, linktype)
        except OrbitError as exc:
            skipped[str(exc)] += 1
            continue
        payload = packet.pop("payload")
        flags.update(find_flags(payload))
        key = (packet["protocol"], packet["src"], packet["sport"], packet["dst"], packet["dport"])
        if key not in flows:
            if len(flows) >= 512:
                payload_limit = True
                continue
            flows[key] = {**packet, "packets": 0, "payload_bytes": 0, "segments": [], "sample": b""}
        flow = flows[key]
        flow["packets"] += 1
        flow["payload_bytes"] += len(payload)
        if not flow["sample"] and payload:
            flow["sample"] = payload[:1024]
        if packet["protocol"] == "TCP" and payload:
            if budget and len(flow["segments"]) < 512:
                part = payload[:budget]
                flow["segments"].append((packet["sequence"], part))
                budget -= len(part)
                payload_limit |= len(part) < len(payload)
            else:
                payload_limit = True
        if packet["protocol"] == "UDP" and 53 in (packet["sport"], packet["dport"]):
            try:
                for question in dns_questions(payload):
                    if len(dns) < 500:
                        dns[(question["name"], question["type"])] = question
            except OrbitError as exc:
                skipped[str(exc)] += 1
    result_flows = []
    for index, flow in enumerate(flows.values()):
        chunks, gaps = reconstruct(flow.pop("segments"))
        sample = flow.pop("sample")
        stream_flags = sorted({f for chunk in chunks for f in find_flags(chunk)})
        flags.update(stream_flags)
        http = []
        for chunk in chunks:
            text = chunk[:262144].decode("latin-1")
            http.extend(
                re.findall(
                    r"(?m)^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^\r\n]{1,1024}|^HTTP/1\.[01] [^\r\n]{1,200}|^[Hh]ost: [^\r\n]{1,256}",
                    text,
                )[:50]
            )
        flow.update(
            {
                "sample": preview(sample, 512),
                "reassembled_bytes": sum(map(len, chunks)),
                "gaps": gaps,
                "flags": stream_flags,
                "http_lines": http[:50],
            }
        )
        if save_streams:
            flow["saved_chunks"] = [
                write_new(Path(save_streams) / f"flow-{index:04d}-{j:03d}.bin", chunk)
                for j, chunk in enumerate(chunks)
            ]
        result_flows.append(flow)
    return {
        "linktype": linktype,
        "snaplen": snaplen,
        "packets_processed": count,
        "packet_limit_reached": pos < len(data),
        "capture_truncated": capture_truncated,
        "payload_limit_reached": payload_limit,
        "flows": result_flows,
        "dns_questions": list(dns.values()),
        "skipped_packets_or_dns": dict(skipped),
        "flags": sorted(flags),
        "note": "Reassembly TCP per arah, overlap pertama dipakai, gap dipisah. Tidak mendekripsi TLS; tidak menggabungkan IP fragment, sequence wrap, atau sesi yang memakai ulang tuple sama.",
    }
