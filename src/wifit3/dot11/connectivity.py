"""Bounded packet helpers for the Fake-Connect connectivity probe."""
from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

from wifit3.dot11.mac import mac_header


LLC_IPV4 = bytes.fromhex("aaaa030000000800")
LLC_ARP = bytes.fromhex("aaaa030000000806")
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


@dataclass(frozen=True, slots=True)
class ArpReply:
    address: str
    mac: bytes


@dataclass(frozen=True, slots=True)
class TcpSegment:
    sequence: int
    acknowledgement: int
    flags: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class HttpProbeResponse:
    status: int
    location_origin: str | None


def build_arp_request(
    bssid: bytes,
    client_mac: bytes,
    client_ip: str,
    target_ip: str,
) -> bytes:
    body = (
        b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + client_mac
        + ipaddress.IPv4Address(client_ip).packed
        + b"\x00" * 6
        + ipaddress.IPv4Address(target_ip).packed
    )
    return (
        mac_header(b"\x08\x01", bssid, client_mac, b"\xff" * 6)
        + LLC_ARP
        + body
    )


def parse_arp_reply(
    frame: bytes,
    client_mac: bytes,
    client_ip: str,
    target_ip: str,
) -> ArpReply | None:
    body = _llc_payload(frame, LLC_ARP)
    if (
        body is None
        or len(body) < 28
        or body[:8] != b"\x00\x01\x08\x00\x06\x04\x00\x02"
        or body[18:24] != client_mac
        or body[24:28] != ipaddress.IPv4Address(client_ip).packed
        or body[14:18] != ipaddress.IPv4Address(target_ip).packed
    ):
        return None
    return ArpReply(target_ip, body[8:14])


def build_dns_query(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    client_ip: str,
    dns_ip: str,
    hostname: str,
    *,
    source_port: int,
    transaction_id: int,
) -> bytes:
    labels = hostname.rstrip(".").encode("ascii").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS hostname")
    question = b"".join(bytes((len(label),)) + label for label in labels)
    question += b"\x00\x00\x01\x00\x01"
    dns = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question
    return build_udp_frame(
        bssid, client_mac, next_hop_mac,
        client_ip, dns_ip, source_port, 53, dns,
        ident=transaction_id,
    )


def parse_dns_response(
    frame: bytes,
    client_ip: str,
    dns_ip: str,
    source_port: int,
    transaction_id: int,
) -> tuple[str, ...] | None:
    packet = _ipv4_packet(frame)
    if packet is None or packet[9] != 17:
        return None
    header_len = (packet[0] & 0x0F) * 4
    if (
        str(ipaddress.IPv4Address(packet[12:16])) != dns_ip
        or str(ipaddress.IPv4Address(packet[16:20])) != client_ip
        or len(packet) < header_len + 8
    ):
        return None
    udp = packet[header_len:]
    src, dst, length = struct.unpack("!HHH", udp[:6])
    if src != 53 or dst != source_port or length < 20:
        return None
    dns = udp[8:min(len(udp), length)]
    if len(dns) < 12:
        return None
    ident, flags, questions, answers = struct.unpack("!HHHH", dns[:8])
    if ident != transaction_id or not flags & 0x8000:
        return None
    offset = 12
    try:
        for _ in range(questions):
            offset = _skip_dns_name(dns, offset) + 4
        addresses = []
        for _ in range(min(answers, 32)):
            offset = _skip_dns_name(dns, offset)
            if offset + 10 > len(dns):
                return None
            kind, dns_class, _ttl, size = struct.unpack(
                "!HHIH", dns[offset:offset + 10],
            )
            offset += 10
            if offset + size > len(dns):
                return None
            if kind == 1 and dns_class == 1 and size == 4:
                addresses.append(str(ipaddress.IPv4Address(dns[offset:offset + 4])))
            offset += size
    except (ValueError, struct.error):
        return None
    return tuple(dict.fromkeys(addresses))


def build_udp_frame(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    source_ip: str,
    dest_ip: str,
    source_port: int,
    dest_port: int,
    body: bytes,
    *,
    ident: int,
) -> bytes:
    udp = struct.pack("!HHHH", source_port, dest_port, 8 + len(body), 0) + body
    return _data_frame(
        bssid, client_mac, next_hop_mac,
        source_ip, dest_ip, 17, udp, ident,
    )


def build_tcp_frame(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    source_ip: str,
    dest_ip: str,
    source_port: int,
    dest_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
    *,
    ident: int = 0,
) -> bytes:
    options = b"\x02\x04\x05\xb4" if flags & TCP_SYN else b""
    offset = 5 + len(options) // 4
    tcp = bytearray(
        struct.pack(
            "!HHIIHHHH",
            source_port, dest_port, sequence, acknowledgement,
            offset << 12 | flags, 64240, 0, 0,
        )
        + options
        + payload
    )
    pseudo = (
        ipaddress.IPv4Address(source_ip).packed
        + ipaddress.IPv4Address(dest_ip).packed
        + b"\x00\x06"
        + struct.pack("!H", len(tcp))
    )
    tcp[16:18] = struct.pack("!H", _checksum(pseudo + tcp))
    return _data_frame(
        bssid, client_mac, next_hop_mac,
        source_ip, dest_ip, 6, bytes(tcp), ident,
    )


def parse_tcp_segment(
    frame: bytes,
    client_ip: str,
    remote_ip: str,
    client_port: int,
    remote_port: int,
) -> TcpSegment | None:
    packet = _ipv4_packet(frame)
    if packet is None or packet[9] != 6:
        return None
    ip_len = (packet[0] & 0x0F) * 4
    if (
        str(ipaddress.IPv4Address(packet[12:16])) != remote_ip
        or str(ipaddress.IPv4Address(packet[16:20])) != client_ip
        or len(packet) < ip_len + 20
    ):
        return None
    tcp = packet[ip_len:]
    src, dst, seq, ack, offset_flags = struct.unpack("!HHIIH", tcp[:14])
    header_len = ((offset_flags >> 12) & 0x0F) * 4
    if src != remote_port or dst != client_port or header_len < 20 or header_len > len(tcp):
        return None
    return TcpSegment(seq, ack, offset_flags & 0x01FF, tcp[header_len:])


def parse_http_response(data: bytes) -> HttpProbeResponse | None:
    end = data.find(b"\r\n\r\n")
    if end < 0 or end > 8192:
        return None
    lines = data[:end].split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    location = None
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"location":
            location = _origin(value.strip())
            break
    return HttpProbeResponse(status, location)


def random_ephemeral_port() -> int:
    return 49152 + secrets.randbelow(16384)


def _data_frame(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    source_ip: str,
    dest_ip: str,
    protocol: int,
    payload: bytes,
    ident: int,
) -> bytes:
    ipv4 = bytearray(
        b"\x45\x00"
        + struct.pack("!H", 20 + len(payload))
        + struct.pack("!H", ident & 0xFFFF)
        + b"\x00\x00\x40"
        + bytes((protocol,))
        + b"\x00\x00"
        + ipaddress.IPv4Address(source_ip).packed
        + ipaddress.IPv4Address(dest_ip).packed
    )
    ipv4[10:12] = struct.pack("!H", _checksum(ipv4))
    return (
        mac_header(b"\x08\x01", bssid, client_mac, next_hop_mac)
        + LLC_IPV4
        + bytes(ipv4)
        + payload
    )


def _ipv4_packet(frame: bytes) -> bytes | None:
    payload = _llc_payload(frame, LLC_IPV4)
    if payload is None or len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    total = struct.unpack("!H", payload[2:4])[0]
    if total < 20:
        return None
    return payload[:min(total, len(payload))]


def _llc_payload(frame: bytes, marker: bytes) -> bytes | None:
    if len(frame) < 32 or ((frame[0] & 0x0C) >> 2) != 2 or frame[1] & 0x40:
        return None
    header_len = 30 if frame[1] & 0x03 == 0x03 else 24
    if (frame[0] >> 4) & 0x08:
        header_len += 2
    if frame[1] & 0x80:
        header_len += 4
    start = frame.find(marker, header_len, header_len + 16)
    return frame[start + len(marker):] if start >= 0 else None


def _skip_dns_name(data: bytes, offset: int) -> int:
    labels = 0
    while offset < len(data) and labels < 128:
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        offset += 1
        if size == 0:
            return offset
        if size > 63 or offset + size > len(data):
            raise ValueError("invalid DNS name")
        offset += size
        labels += 1
    raise ValueError("unterminated DNS name")


def _origin(raw: bytes) -> str | None:
    if len(raw) > 2048:
        return None
    try:
        parsed = urlsplit(raw.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError):
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{port}"


def _checksum(data: bytes | bytearray) -> int:
    raw = bytes(data)
    if len(raw) % 2:
        raw += b"\x00"
    total = sum(struct.unpack(f"!{len(raw) // 2}H", raw))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
