"""Minimal DHCP Discover/Offer support for an associated unencrypted station."""
from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

from wifit3.dot11.mac import mac_header


LLC_SNAP_IPV4 = bytes.fromhex("aaaa030000000800")
DHCP_COOKIE = bytes.fromhex("63825363")


@dataclass(frozen=True, slots=True)
class DhcpOffer:
    offered_ip: str
    server: str | None
    subnet_mask: str | None
    routers: tuple[str, ...]
    dns_servers: tuple[str, ...]
    domain: str | None
    portal: str | None
    lease_seconds: int | None

    def summary(self) -> str:
        parts = [f"offer {self.offered_ip}"]
        if self.routers:
            parts.append(f"gateway {self.routers[0]}")
        if self.dns_servers:
            parts.append(f"DNS {', '.join(self.dns_servers)}")
        if self.server:
            parts.append(f"server {self.server}")
        return " · ".join(parts)


def random_xid() -> int:
    return secrets.randbits(32)


def build_discover(bssid: bytes, client_mac: bytes, xid: int) -> bytes:
    """Build a broadcast DHCPDISCOVER in an 802.11 ToDS data frame."""
    bootp = bytearray(236)
    bootp[0:4] = b"\x01\x01\x06\x00"  # BOOTREQUEST, Ethernet, MAC length 6, hops 0
    bootp[4:8] = struct.pack("!I", xid)
    bootp[10:12] = b"\x80\x00"         # request broadcast reply
    bootp[28:34] = client_mac
    options = (
        b"\x35\x01\x01"                # DHCP message type: Discover
        + b"\x3d\x07\x01" + client_mac  # client identifier: Ethernet + MAC
        + b"\x39\x02\x05\xdc"          # maximum DHCP message size: 1500
        + b"\x37\x0c"                  # parameter request list
        + bytes((1, 3, 6, 15, 51, 54, 58, 59, 114, 119, 121, 249))
        + b"\xff"
    )
    # RFC 951's BOOTP packet is at least 300 octets. Some embedded DHCP
    # servers silently discard shorter, otherwise valid DHCP messages.
    dhcp = (bytes(bootp) + DHCP_COOKIE + options).ljust(300, b"\x00")
    return _ipv4_udp_frame(
        bssid, client_mac, b"\xff" * 6,
        "0.0.0.0", "255.255.255.255", 68, 67, dhcp, xid & 0xFFFF,
    )


def build_request(
    bssid: bytes,
    client_mac: bytes,
    xid: int,
    offered_ip: str,
    server: str,
) -> bytes:
    """Build the selecting-state DHCPREQUEST for one received Offer."""
    bootp = bytearray(236)
    bootp[0:4] = b"\x01\x01\x06\x00"
    bootp[4:8] = struct.pack("!I", xid)
    bootp[10:12] = b"\x80\x00"
    bootp[28:34] = client_mac
    options = (
        b"\x35\x01\x03"
        + b"\x32\x04" + ipaddress.IPv4Address(offered_ip).packed
        + b"\x36\x04" + ipaddress.IPv4Address(server).packed
        + b"\x3d\x07\x01" + client_mac
        + b"\x37\x0c"
        + bytes((1, 3, 6, 15, 51, 54, 58, 59, 114, 119, 121, 249))
        + b"\xff"
    )
    dhcp = (bytes(bootp) + DHCP_COOKIE + options).ljust(300, b"\x00")
    return _ipv4_udp_frame(
        bssid, client_mac, b"\xff" * 6,
        "0.0.0.0", "255.255.255.255", 68, 67, dhcp, xid & 0xFFFF,
    )


def build_release(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    xid: int,
    client_ip: str,
    server: str,
) -> bytes:
    """Build a best-effort DHCPRELEASE after a temporary connectivity probe."""
    bootp = bytearray(236)
    bootp[0:4] = b"\x01\x01\x06\x00"
    bootp[4:8] = struct.pack("!I", xid)
    bootp[12:16] = ipaddress.IPv4Address(client_ip).packed
    bootp[28:34] = client_mac
    options = (
        b"\x35\x01\x07"
        + b"\x36\x04" + ipaddress.IPv4Address(server).packed
        + b"\x3d\x07\x01" + client_mac
        + b"\xff"
    )
    dhcp = bytes(bootp) + DHCP_COOKIE + options
    return _ipv4_udp_frame(
        bssid, client_mac, next_hop_mac,
        client_ip, server, 68, 67, dhcp, xid & 0xFFFF,
    )


def parse_offer(frame: bytes, xid: int, client_mac: bytes) -> DhcpOffer | None:
    """Parse a matching DHCP Offer from a clear-text 802.11 data frame."""
    payload = _ipv4_payload(frame)
    if payload is None or len(payload) < 28 or payload[9] != 17:
        return None
    header_len = (payload[0] & 0x0F) * 4
    if header_len < 20 or len(payload) < header_len + 8:
        return None
    udp = payload[header_len:]
    source_port, dest_port, udp_len = struct.unpack("!HHH", udp[:6])
    if source_port != 67 or dest_port != 68 or udp_len < 8:
        return None
    body = udp[8:min(len(udp), udp_len)]
    if (
        len(body) < 240
        or body[0] != 2
        or body[2] != 6
        or struct.unpack("!I", body[4:8])[0] != xid
        or body[28:34] != client_mac
        or body[236:240] != DHCP_COOKIE
    ):
        return None
    options = _options(body[240:])
    if _first(options, 53) != b"\x02":
        return None
    return _lease_from_reply(body, options)


def parse_ack(
    frame: bytes,
    xid: int,
    client_mac: bytes,
) -> tuple[DhcpOffer | None, bool]:
    """Return ``(lease, nak)`` for a matching DHCP ACK/NAK."""
    payload = _ipv4_payload(frame)
    if payload is None or len(payload) < 28 or payload[9] != 17:
        return None, False
    header_len = (payload[0] & 0x0F) * 4
    if header_len < 20 or len(payload) < header_len + 8:
        return None, False
    udp = payload[header_len:]
    source_port, dest_port, udp_len = struct.unpack("!HHH", udp[:6])
    if source_port != 67 or dest_port != 68 or udp_len < 8:
        return None, False
    body = udp[8:min(len(udp), udp_len)]
    if (
        len(body) < 240
        or body[0] != 2
        or body[2] != 6
        or struct.unpack("!I", body[4:8])[0] != xid
        or body[28:34] != client_mac
        or body[236:240] != DHCP_COOKIE
    ):
        return None, False
    options = _options(body[240:])
    message_type = _first(options, 53)
    if message_type == b"\x06":
        return None, True
    if message_type != b"\x05":
        return None, False
    return _lease_from_reply(body, options), False


def parse_client_message(frame: bytes, client_mac: bytes) -> str | None:
    """Return ``discover`` or ``request`` for a matching client DHCP message."""
    if len(frame) < 24 or frame[1] & 0x03 != 0x01:  # station -> distribution system
        return None
    payload = _ipv4_payload(frame)
    if payload is None or len(payload) < 28 or payload[9] != 17:
        return None
    header_len = (payload[0] & 0x0F) * 4
    if header_len < 20 or len(payload) < header_len + 8:
        return None
    udp = payload[header_len:]
    source_port, dest_port, udp_len = struct.unpack("!HHH", udp[:6])
    if source_port != 68 or dest_port != 67 or udp_len < 8:
        return None
    body = udp[8:min(len(udp), udp_len)]
    if (
        len(body) < 240
        or body[0] != 1
        or body[2] != 6
        or body[28:34] != client_mac
        or body[236:240] != DHCP_COOKIE
    ):
        return None
    message_type = _first(_options(body[240:]), 53)
    return {b"\x01": "discover", b"\x03": "request"}.get(message_type)


def _lease_from_reply(
    body: bytes,
    options: dict[int, list[bytes]],
) -> DhcpOffer:
    offered_ip = str(ipaddress.IPv4Address(body[16:20]))
    server_raw = _first(options, 54)
    mask_raw = _first(options, 1)
    domain_raw = _first(options, 15)
    portal_raw = _first(options, 114)
    lease_raw = _first(options, 51)
    return DhcpOffer(
        offered_ip=offered_ip,
        server=_address(server_raw),
        subnet_mask=_address(mask_raw),
        routers=tuple(_addresses(options.get(3, ()))),
        dns_servers=tuple(_addresses(options.get(6, ()))),
        domain=_ascii(domain_raw),
        portal=_portal_origin(portal_raw),
        lease_seconds=(
            struct.unpack("!I", lease_raw)[0]
            if lease_raw is not None and len(lease_raw) == 4 else None
        ),
    )


def _ipv4_udp_frame(
    bssid: bytes,
    client_mac: bytes,
    next_hop_mac: bytes,
    source_ip: str,
    dest_ip: str,
    source_port: int,
    dest_port: int,
    body: bytes,
    ident: int,
) -> bytes:
    udp_len = 8 + len(body)
    udp = struct.pack("!HHHH", source_port, dest_port, udp_len, 0) + body
    total_len = 20 + len(udp)
    ipv4 = bytearray(
        b"\x45\x00"
        + struct.pack("!H", total_len)
        + struct.pack("!H", ident)
        + b"\x00\x00\x40\x11\x00\x00"
        + ipaddress.IPv4Address(source_ip).packed
        + ipaddress.IPv4Address(dest_ip).packed
    )
    ipv4[10:12] = struct.pack("!H", _checksum(ipv4))
    header = mac_header(b"\x08\x01", bssid, client_mac, next_hop_mac)
    return header + LLC_SNAP_IPV4 + bytes(ipv4) + udp


def _ipv4_payload(frame: bytes) -> bytes | None:
    if len(frame) < 32 or ((frame[0] & 0x0C) >> 2) != 2 or frame[1] & 0x40:
        return None
    subtype = frame[0] >> 4
    header_len = 30 if frame[1] & 0x03 == 0x03 else 24
    if subtype & 0x08:
        header_len += 2
    if frame[1] & 0x80:
        header_len += 4
    start = frame.find(LLC_SNAP_IPV4, header_len, header_len + 16)
    if start < 0:
        return None
    payload = frame[start + len(LLC_SNAP_IPV4):]
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    total = struct.unpack("!H", payload[2:4])[0]
    return payload[:min(total, len(payload))]


def _options(data: bytes) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = {}
    offset = 0
    while offset < len(data) and len(result) <= 128:
        code = data[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            break
        result.setdefault(code, []).append(data[offset:offset + length])
        offset += length
    return result


def _first(options: dict[int, list[bytes]], code: int) -> bytes | None:
    values = options.get(code)
    return values[0] if values else None


def _addresses(chunks) -> list[str]:
    raw = b"".join(chunks)
    if len(raw) % 4:
        return []
    return [
        str(ipaddress.IPv4Address(raw[index:index + 4]))
        for index in range(0, len(raw), 4)
    ]


def _address(value: bytes | None) -> str | None:
    return str(ipaddress.IPv4Address(value)) if value is not None and len(value) == 4 else None


def _ascii(value: bytes | None) -> str | None:
    if not value or len(value) > 253:
        return None
    try:
        text = value.decode("ascii").strip().strip(".")
    except UnicodeDecodeError:
        return None
    return text if text and all(32 < ord(char) < 127 for char in text) else None


def _portal_origin(value: bytes | None) -> str | None:
    text = _ascii(value)
    if not text:
        return None
    parsed = urlsplit(text)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{port}"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
