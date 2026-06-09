"""Minimal read-only PCAP parsing (DNS/HTTP summaries without tshark)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC = 0x0A0D0D0A


def _read_pcap_packets(path: Path, max_packets: int = 5000) -> list[bytes]:
    raw = path.read_bytes()
    if len(raw) < 24:
        return []
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAPNG_MAGIC):
        return []
    if magic == PCAPNG_MAGIC:
        return _read_pcapng_packets(raw, max_packets)
    endian = "<" if magic == PCAP_MAGIC_LE else ">"
    packets: list[bytes] = []
    offset = 24
    while offset + 16 <= len(raw) and len(packets) < max_packets:
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(f"{endian}IIII", raw, offset)
        offset += 16
        frame = raw[offset : offset + incl_len]
        offset += incl_len
        if frame:
            packets.append(frame)
    return packets


def _read_pcapng_packets(raw: bytes, max_packets: int) -> list[bytes]:
    packets: list[bytes] = []
    offset = 0
    while offset + 8 <= len(raw) and len(packets) < max_packets:
        block_type, block_len = struct.unpack_from("<II", raw, offset)
        if block_len < 12 or offset + block_len > len(raw):
            break
        if block_type == 0x00000006:  # Enhanced Packet Block
            cap_len = struct.unpack_from("<I", raw, offset + 20)[0]
            frame_start = offset + 28
            frame = raw[frame_start : frame_start + cap_len]
            if frame:
                packets.append(frame)
        offset += block_len
    return packets


def _ipv4_payload(frame: bytes) -> tuple[int, bytes] | None:
    if len(frame) < 14:
        return None
    eth_type = struct.unpack_from("!H", frame, 12)[0]
    if eth_type != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl:
        return None
    proto = ip[9]
    return proto, ip[ihl:]


def extract_dns_queries(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    queries: list[dict[str, Any]] = []
    domain_counts: dict[str, int] = {}
    for frame in _read_pcap_packets(path):
        parsed = _ipv4_payload(frame)
        if not parsed:
            continue
        proto, payload = parsed
        if proto != 17 or len(payload) < 8:
            continue
        src_port, dst_port = struct.unpack_from("!HH", payload, 0)
        if dst_port != 53 and src_port != 53:
            continue
        udp_payload = payload[8:]
        if len(udp_payload) < 12:
            continue
        try:
            qname = _parse_dns_qname(udp_payload, 12)
        except (IndexError, struct.error):
            continue
        if not qname:
            continue
        label = qname.lower().rstrip(".")
        queries.append({"query": label, "length": len(label.split("."))})
        domain_counts[label] = domain_counts.get(label, 0) + 1
        if len(queries) >= max_records:
            break
    top = sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    return {
        "source": str(path),
        "parser": "pcap-dns-minimal",
        "queries": queries,
        "query_count": len(queries),
        "top_domains": [{"domain": d, "count": c} for d, c in top],
    }


def _parse_dns_qname(payload: bytes, offset: int) -> str:
    labels: list[str] = []
    idx = offset
    jumps = 0
    while idx < len(payload) and jumps < 8:
        length = payload[idx]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", payload, idx)[0] & 0x3FFF
            idx = ptr
            jumps += 1
            continue
        idx += 1
        labels.append(payload[idx : idx + length].decode("ascii", errors="replace"))
        idx += length
    return ".".join(labels)


def extract_http_hosts(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    host_sizes: dict[str, list[int]] = {}
    for frame in _read_pcap_packets(path):
        parsed = _ipv4_payload(frame)
        if not parsed:
            continue
        proto, payload = parsed
        if proto != 6 or len(payload) < 20:
            continue
        tcp = payload
        src_port, dst_port = struct.unpack_from("!HH", tcp, 0)
        if dst_port not in {80, 443, 8080} and src_port not in {80, 443, 8080}:
            continue
        data_offset = ((tcp[12] >> 4) * 4) if len(tcp) >= 13 else 20
        body = tcp[data_offset:]
        if not body:
            continue
        text = body.decode("latin-1", errors="ignore")
        host = None
        size = len(body)
        for line in text.split("\r\n")[:20]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip().lower()
                break
            if line.upper().startswith("POST ") or line.upper().startswith("GET "):
                parts = line.split()
                if len(parts) >= 2:
                    host = parts[1].split("/")[2] if "://" in parts[1] else parts[1]
        if host:
            hosts.append({"host": host, "size": size, "dst_port": dst_port})
            host_sizes.setdefault(host, []).append(size)
            if len(hosts) >= max_records:
                break
    periodic: list[dict[str, Any]] = []
    for host, sizes in host_sizes.items():
        if len(sizes) >= 3 and len(set(sizes)) == 1:
            periodic.append({"host": host, "size": sizes[0], "count": len(sizes)})
    return {
        "source": str(path),
        "parser": "pcap-http-minimal",
        "requests": hosts,
        "request_count": len(hosts),
        "periodic_same_size": periodic,
    }


def summarize_pcap(path: Path, *, max_packets: int = 5000) -> dict[str, Any]:
    packets = _read_pcap_packets(path, max_packets=max_packets)
    protos: dict[str, int] = {"tcp": 0, "udp": 0, "other": 0}
    for frame in packets:
        parsed = _ipv4_payload(frame)
        if not parsed:
            protos["other"] += 1
            continue
        proto, _ = parsed
        if proto == 6:
            protos["tcp"] += 1
        elif proto == 17:
            protos["udp"] += 1
        else:
            protos["other"] += 1
    return {
        "source": str(path),
        "parser": "pcap-summary-minimal",
        "packet_count": len(packets),
        "protocol_counts": protos,
    }


def extract_conversations(path: Path, *, max_records: int = 200) -> dict[str, Any]:
    pairs: dict[str, int] = {}
    for frame in _read_pcap_packets(path):
        parsed = _ipv4_payload(frame)
        if not parsed:
            continue
        proto, payload = parsed
        if len(payload) < 4:
            continue
        if proto == 6 and len(payload) >= 20:
            src_port, dst_port = struct.unpack_from("!HH", payload, 0)
            ip_hdr = frame[14:34]
            src = ".".join(str(b) for b in ip_hdr[12:16])
            dst = ".".join(str(b) for b in ip_hdr[16:20])
            key = f"{src}:{src_port}->{dst}:{dst_port}/tcp"
            pairs[key] = pairs.get(key, 0) + 1
        elif proto == 17 and len(payload) >= 8:
            src_port, dst_port = struct.unpack_from("!HH", payload, 0)
            ip_hdr = frame[14:34]
            src = ".".join(str(b) for b in ip_hdr[12:16])
            dst = ".".join(str(b) for b in ip_hdr[16:20])
            key = f"{src}:{src_port}->{dst}:{dst_port}/udp"
            pairs[key] = pairs.get(key, 0) + 1
        if len(pairs) >= max_records:
            break
    ranked = sorted(pairs.items(), key=lambda item: -item[1])[:max_records]
    return {
        "source": str(path),
        "parser": "pcap-conversations-minimal",
        "conversations": [{"flow": k, "packets": v} for k, v in ranked],
        "conversation_count": len(ranked),
    }
