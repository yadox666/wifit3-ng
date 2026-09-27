"""Bounded passive network metadata extraction for unencrypted 802.11 captures.

Only infrastructure metadata is retained.  Packet payloads, DHCP client identifiers,
hostnames, DNS histories, HTTP bodies, cookies, and URL paths/query strings are never stored.
"""
from __future__ import annotations

import ipaddress
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from wifit3.dot11.dhcp import DhcpOffer


MAX_FACTS_PER_KIND = 32
MAX_CLIENTS = 256
MAX_URI_BYTES = 2048

_CONFIDENCE_RANK = {"inferred": 0, "advertised": 1, "observed": 2}


@dataclass(slots=True)
class NetworkFact:
    value: str
    first_seen: float
    last_seen: float
    source: str
    confidence: str
    expires_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "value": self.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "confidence": self.confidence,
        }
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at
        return result

    @classmethod
    def from_dict(cls, value: Any) -> NetworkFact | None:
        if not isinstance(value, dict):
            return None
        try:
            fact = cls(
                value=str(value["value"])[:MAX_URI_BYTES],
                first_seen=float(value["first_seen"]),
                last_seen=float(value["last_seen"]),
                source=str(value["source"])[:64],
                confidence=str(value["confidence"]),
                expires_at=(
                    float(value["expires_at"])
                    if value.get("expires_at") is not None else None
                ),
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        return fact if fact.value and fact.confidence in _CONFIDENCE_RANK else None


@dataclass(slots=True)
class ClientNetworkMetadata:
    mac: str
    first_seen: float
    last_seen: float
    facts: dict[str, list[NetworkFact]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "facts": {
                kind: [fact.to_dict() for fact in values]
                for kind, values in sorted(self.facts.items()) if values
            },
        }


@dataclass(slots=True)
class NetworkMetadata:
    bssid: str
    ssid: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    facts: dict[str, list[NetworkFact]] = field(default_factory=dict)
    clients: dict[str, ClientNetworkMetadata] = field(default_factory=dict)
    revision: int = field(default=0, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add(
        self,
        kind: str,
        value: str,
        *,
        source: str,
        confidence: str,
        now: float,
        client_mac: str | None = None,
        expires_at: float | None = None,
        include_ap: bool = True,
    ) -> bool:
        with self.lock:
            value = str(value).strip()[:MAX_URI_BYTES]
            if not value or confidence not in _CONFIDENCE_RANK:
                return False
            changed = False
            if include_ap:
                changed |= _merge_fact(
                    self.facts, kind, value, source, confidence, now, expires_at,
                )
            if client_mac:
                client_mac = client_mac.casefold()
                client = self.clients.get(client_mac)
                if client is None and len(self.clients) < MAX_CLIENTS:
                    client = ClientNetworkMetadata(client_mac, now, now)
                    self.clients[client_mac] = client
                    changed = True
                if client is not None:
                    client.last_seen = max(client.last_seen, now)
                    changed |= _merge_fact(
                        client.facts, kind, value, source, confidence, now, expires_at,
                    )
            if changed:
                self.last_seen = max(self.last_seen, now)
                self.revision += 1
            return changed

    def observe_dhcp_offer(
        self,
        offer: DhcpOffer,
        *,
        client_mac: str,
        now: float,
        source: str = "dhcp_offer_active",
    ) -> bool:
        """Record a parsed active-probe Offer using the passive metadata schema."""
        expires_at = (
            now + offer.lease_seconds
            if offer.lease_seconds is not None
            else None
        )
        changed = self.add(
            "ipv4_addresses",
            offer.offered_ip,
            source=source,
            confidence="advertised",
            now=now,
            client_mac=client_mac,
            expires_at=expires_at,
            include_ap=False,
        )
        if offer.subnet_mask:
            try:
                network = str(
                    ipaddress.IPv4Network(
                        (offer.offered_ip, offer.subnet_mask),
                        strict=False,
                    )
                )
                changed |= self.add(
                    "ipv4_networks",
                    network,
                    source=source,
                    confidence="inferred",
                    now=now,
                    client_mac=client_mac,
                    expires_at=expires_at,
                )
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass
        for kind, values in (
            ("gateways", offer.routers),
            ("dns_servers", offer.dns_servers),
            ("dhcp_servers", (offer.server,) if offer.server else ()),
            ("domains", (offer.domain,) if offer.domain else ()),
        ):
            for value in dict.fromkeys(values):
                changed |= self.add(
                    kind,
                    value,
                    source=source,
                    confidence="advertised",
                    now=now,
                    client_mac=client_mac,
                    expires_at=expires_at,
                )
        if offer.portal:
            changed |= self.add(
                "captive_portals",
                offer.portal,
                source="dhcp_option_114",
                confidence="advertised",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        return changed

    def observe_connectivity(
        self,
        result: Any,
        *,
        client_mac: str,
        now: float,
        expires_at: float | None = None,
    ) -> bool:
        """Store bounded connectivity outcomes without response bodies or DNS history."""
        changed = self.add(
            "connectivity",
            result.status,
            source="active_connectivity_probe",
            confidence="observed",
            now=now,
            client_mac=client_mac,
            expires_at=expires_at,
        )
        if result.gateway_reachable and result.gateway:
            changed |= self.add(
                "gateway_reachability",
                result.gateway,
                source="arp_probe",
                confidence="observed",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        if result.dns_reachable and result.dns_server:
            changed |= self.add(
                "dns_reachability",
                result.dns_server,
                source="dns_connectivity_probe",
                confidence="observed",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        if result.status == "internet_confirmed":
            changed |= self.add(
                "portal_status",
                "not_detected",
                source="http_204",
                confidence="observed",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        elif result.status == "portal_observed" and result.portal_origin:
            changed |= self.add(
                "captive_portals",
                result.portal_origin,
                source="http_connectivity_redirect",
                confidence="observed",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        elif result.status == "portal_suspected":
            changed |= self.add(
                "portal_status",
                "intercepted",
                source="http_connectivity_probe",
                confidence="inferred",
                now=now,
                client_mac=client_mac,
                expires_at=expires_at,
            )
        return changed

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            return {
                "version": 1,
                "bssid": self.bssid,
                "ssid": self.ssid,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "facts": {
                    kind: [fact.to_dict() for fact in values]
                    for kind, values in sorted(self.facts.items()) if values
                },
                "clients": {
                    mac: client.to_dict()
                    for mac, client in sorted(self.clients.items())
                },
            }

    def serialized_snapshot(self) -> tuple[dict[str, Any], int]:
        with self.lock:
            return (
                {
                    "version": 1,
                    "bssid": self.bssid,
                    "ssid": self.ssid,
                    "first_seen": self.first_seen,
                    "last_seen": self.last_seen,
                    "facts": {
                        kind: [fact.to_dict() for fact in values]
                        for kind, values in sorted(self.facts.items()) if values
                    },
                    "clients": {
                        mac: client.to_dict()
                        for mac, client in sorted(self.clients.items())
                    },
                },
                self.revision,
            )

    @classmethod
    def from_dict(
        cls, value: Any, *, expected_bssid: str, ssid: str,
    ) -> NetworkMetadata | None:
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or str(value.get("bssid", "")).casefold() != expected_bssid.casefold()
        ):
            return None
        try:
            result = cls(
                bssid=expected_bssid.casefold(),
                ssid=str(value.get("ssid") or ssid),
                first_seen=float(value["first_seen"]),
                last_seen=float(value["last_seen"]),
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        result.facts = _load_facts(value.get("facts"))
        raw_clients = value.get("clients")
        if isinstance(raw_clients, dict):
            for mac, raw in list(raw_clients.items())[:MAX_CLIENTS]:
                if not _valid_mac(mac) or not isinstance(raw, dict):
                    continue
                try:
                    client = ClientNetworkMetadata(
                        mac.casefold(),
                        float(raw["first_seen"]),
                        float(raw["last_seen"]),
                        _load_facts(raw.get("facts")),
                    )
                except (KeyError, TypeError, ValueError, OverflowError):
                    continue
                result.clients[client.mac] = client
        return result


def _merge_fact(
    facts: dict[str, list[NetworkFact]],
    kind: str,
    value: str,
    source: str,
    confidence: str,
    now: float,
    expires_at: float | None,
) -> bool:
    values = facts.setdefault(kind[:64], [])
    for fact in values:
        if fact.value != value:
            continue
        changed = (
            now > fact.last_seen
            or (expires_at is not None and expires_at != fact.expires_at)
            or _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[fact.confidence]
        )
        fact.last_seen = max(fact.last_seen, now)
        if expires_at is not None:
            fact.expires_at = expires_at
        if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[fact.confidence]:
            fact.confidence = confidence
            fact.source = source[:64]
        return changed
    if len(values) >= MAX_FACTS_PER_KIND:
        values.sort(key=lambda item: item.last_seen)
        values.pop(0)
    values.append(NetworkFact(value, now, now, source[:64], confidence, expires_at))
    return True


def _load_facts(value: Any) -> dict[str, list[NetworkFact]]:
    result: dict[str, list[NetworkFact]] = {}
    if not isinstance(value, dict):
        return result
    for kind, raw_values in value.items():
        if not isinstance(kind, str) or not isinstance(raw_values, list):
            continue
        parsed = [
            fact for fact in (
                NetworkFact.from_dict(raw)
                for raw in raw_values[:MAX_FACTS_PER_KIND]
            ) if fact is not None
        ]
        if parsed:
            result[kind[:64]] = parsed
    return result


def _valid_mac(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(":")
    try:
        return len(parts) == 6 and all(len(part) == 2 and int(part, 16) >= 0 for part in parts)
    except ValueError:
        return False


class PassiveNetworkAnalyzer:
    """Decode infrastructure metadata from clear-text data frames during capture."""

    def __init__(self, metadata: NetworkMetadata):
        self.metadata = metadata

    def observe(self, packet: Any, now: float | None = None) -> set[str]:
        """Observe one parsed packet; return client MACs whose metadata changed."""
        now = time.time() if now is None else now
        decoded = _data_payload(getattr(packet, "raw", b""))
        if decoded is None:
            return set()
        ethertype, payload = decoded
        before = self.metadata.revision
        touched: set[str] = set()
        client_mac = getattr(packet, "client_mac", None)
        if client_mac:
            client_mac = client_mac.casefold()
        try:
            if ethertype == 0x0806:
                touched |= self._arp(payload, client_mac, now)
            elif ethertype == 0x0800:
                touched |= self._ipv4(payload, packet, client_mac, now)
            elif ethertype == 0x86DD:
                touched |= self._ipv6(payload, packet, client_mac, now)
        except (ValueError, struct.error, ipaddress.AddressValueError):
            return set()
        if self.metadata.revision != before and client_mac:
            touched.add(client_mac)
        return touched

    def _arp(self, payload: bytes, client_mac: str | None, now: float) -> set[str]:
        if len(payload) < 28 or payload[:6] != b"\x00\x01\x08\x00\x06\x04":
            return set()
        sender_mac = _mac(payload[8:14])
        sender_ip = str(ipaddress.IPv4Address(payload[14:18]))
        target_mac = _mac(payload[18:24])
        target_ip = str(ipaddress.IPv4Address(payload[24:28]))
        touched = set()
        for mac, address in ((sender_mac, sender_ip), (target_mac, target_ip)):
            if mac == client_mac and _usable_host(address):
                if self.metadata.add(
                    "ipv4_addresses", address, source="arp", confidence="observed",
                    now=now, client_mac=mac, include_ap=False,
                ):
                    touched.add(mac)
        return touched

    def _ipv4(
        self, payload: bytes, packet: Any, client_mac: str | None, now: float,
    ) -> set[str]:
        if len(payload) < 20 or payload[0] >> 4 != 4:
            return set()
        header_len = (payload[0] & 0x0F) * 4
        total_len = min(struct.unpack("!H", payload[2:4])[0], len(payload))
        if header_len < 20 or total_len < header_len:
            return set()
        flags_offset = struct.unpack("!H", payload[6:8])[0]
        if flags_offset & 0x1FFF:
            return set()
        protocol = payload[9]
        source = str(ipaddress.IPv4Address(payload[12:16]))
        dest = str(ipaddress.IPv4Address(payload[16:20]))
        touched = set()
        if client_mac:
            candidate = source if getattr(packet, "to_ds", False) else dest
            if _usable_host(candidate) and self.metadata.add(
                "ipv4_addresses", candidate, source="ipv4", confidence="observed",
                now=now, client_mac=client_mac, include_ap=False,
            ):
                touched.add(client_mac)
        body = payload[header_len:total_len]
        if protocol == 17:
            touched |= self._udp(body, source, client_mac, now)
        elif protocol == 6:
            touched |= self._tcp(
                body, client_mac, now, to_ds=bool(getattr(packet, "to_ds", False)),
            )
        return touched

    def _udp(
        self, payload: bytes, source_ip: str, client_mac: str | None, now: float,
    ) -> set[str]:
        if len(payload) < 8:
            return set()
        source_port, dest_port, length = struct.unpack("!HHH", payload[:6])
        body = payload[8:min(max(length, 8), len(payload))]
        if {source_port, dest_port} == {67, 68}:
            return self._dhcp(body, source_ip, now)
        if client_mac and (source_port == 53 or dest_port == 53):
            host = _dns_question(body)
            if host and _looks_like_portal_host(host):
                changed = self.metadata.add(
                    "captive_portals", f"https://{host}", source="dns_portal_hint",
                    confidence="inferred", now=now, client_mac=client_mac,
                )
                return {client_mac} if changed else set()
        return set()

    def _dhcp(self, payload: bytes, source_ip: str, now: float) -> set[str]:
        if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
            return set()
        op, hlen = payload[0], payload[2]
        if op != 2 or hlen != 6:
            return set()
        client_mac = _mac(payload[28:34])
        if not _valid_mac(client_mac):
            return set()
        yiaddr = str(ipaddress.IPv4Address(payload[16:20]))
        options = _dhcp_options(payload[240:])
        message_type = _first(options, 53)
        if not message_type or message_type[0] not in (2, 5):
            return set()
        source = "dhcp_ack" if message_type[0] == 5 else "dhcp_offer"
        touched = set()
        lease = _u32(_first(options, 51))
        expires_at = now + lease if lease is not None else None
        if _usable_host(yiaddr) and self.metadata.add(
            "ipv4_addresses", yiaddr, source=source, confidence="advertised",
            now=now, client_mac=client_mac, expires_at=expires_at, include_ap=False,
        ):
            touched.add(client_mac)
        mask_raw = _first(options, 1)
        if mask_raw and len(mask_raw) == 4 and _usable_host(yiaddr):
            try:
                network = str(ipaddress.IPv4Network(
                    (yiaddr, str(ipaddress.IPv4Address(mask_raw))), strict=False,
                ))
                touched |= self._shared(
                    "ipv4_networks", [network], source, client_mac, now, expires_at,
                    confidence="inferred",
                )
            except ipaddress.NetmaskValueError:
                pass
        routers = _addresses(options.get(3, []), 4)
        classless = _classless_default_routers(options.get(121, []) + options.get(249, []))
        touched |= self._shared(
            "gateways", classless or routers, source, client_mac, now, expires_at,
        )
        touched |= self._shared(
            "dns_servers", _addresses(options.get(6, []), 4),
            source, client_mac, now, expires_at,
        )
        server = _first(options, 54)
        servers = (
            [str(ipaddress.IPv4Address(server))]
            if server and len(server) == 4 else ([source_ip] if _usable_host(source_ip) else [])
        )
        touched |= self._shared(
            "dhcp_servers", servers, source, client_mac, now, expires_at,
        )
        domains = []
        domain = _first(options, 15)
        if domain:
            text = _safe_text(domain, 253)
            if text:
                domains.append(text)
        search = b"".join(options.get(119, []))
        domains.extend(_dns_names(search))
        touched |= self._shared(
            "domains", domains, source, client_mac, now, expires_at,
        )
        portal = _first(options, 114)
        portal_origin = _uri_origin(portal)
        if portal_origin:
            touched |= self._shared(
                "captive_portals", [portal_origin], "dhcp_option_114",
                client_mac, now, expires_at,
            )
        return touched

    def _shared(
        self,
        kind: str,
        values: Iterable[str],
        source: str,
        client_mac: str,
        now: float,
        expires_at: float | None,
        confidence: str = "advertised",
    ) -> set[str]:
        changed = False
        for value in dict.fromkeys(values):
            changed |= self.metadata.add(
                kind, value, source=source, confidence=confidence, now=now,
                client_mac=client_mac, expires_at=expires_at,
            )
        return {client_mac} if changed else set()

    def _tcp(
        self, payload: bytes, client_mac: str | None, now: float, *, to_ds: bool,
    ) -> set[str]:
        if not client_mac or len(payload) < 20:
            return set()
        source_port, dest_port = struct.unpack("!HH", payload[:4])
        header_len = (payload[12] >> 4) * 4
        if header_len < 20 or len(payload) <= header_len:
            return set()
        body = payload[header_len:header_len + 8192]
        if to_ds and dest_port == 443:
            host = _tls_sni(body)
            if host and _looks_like_portal_host(host):
                changed = self.metadata.add(
                    "captive_portals", f"https://{host}", source="tls_sni_portal_hint",
                    confidence="inferred", now=now, client_mac=client_mac,
                )
                return {client_mac} if changed else set()
        if source_port not in (80, 8080):
            return set()
        if not body.startswith(b"HTTP/1."):
            return set()
        first_end = body.find(b"\r\n")
        if first_end < 0:
            return set()
        try:
            status = int(body[:first_end].split(b" ", 2)[1])
        except (IndexError, ValueError):
            return set()
        if not 300 <= status < 400:
            return set()
        headers_end = body.find(b"\r\n\r\n")
        headers = body[first_end + 2:headers_end if headers_end >= 0 else len(body)]
        location = None
        for line in headers.split(b"\r\n")[:64]:
            if line.lower().startswith(b"location:"):
                location = line.split(b":", 1)[1].strip()
                break
        origin = _uri_origin(location)
        if not origin:
            return set()
        changed = self.metadata.add(
            "captive_portals", origin, source="http_redirect", confidence="observed",
            now=now, client_mac=client_mac,
        )
        return {client_mac} if changed else set()

    def _ipv6(
        self, payload: bytes, packet: Any, client_mac: str | None, now: float,
    ) -> set[str]:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            return set()
        next_header = payload[6]
        source = str(ipaddress.IPv6Address(payload[8:24]))
        dest = str(ipaddress.IPv6Address(payload[24:40]))
        touched = set()
        if client_mac:
            candidate = source if getattr(packet, "to_ds", False) else dest
            address = ipaddress.IPv6Address(candidate)
            if not address.is_multicast and not address.is_unspecified:
                if self.metadata.add(
                    "ipv6_addresses", candidate, source="ipv6", confidence="observed",
                    now=now, client_mac=client_mac, include_ap=False,
                ):
                    touched.add(client_mac)
        if next_header != 58 or len(payload) < 56 or payload[40] != 134:
            return touched
        router_lifetime = struct.unpack("!H", payload[46:48])[0]
        expires_at = now + router_lifetime if router_lifetime else None
        if router_lifetime:
            self.metadata.add(
                "gateways", source, source="ipv6_ra", confidence="advertised",
                now=now, expires_at=expires_at,
            )
        offset = 56
        while offset + 2 <= len(payload):
            option_type, units = payload[offset], payload[offset + 1]
            length = units * 8
            if not length or offset + length > len(payload):
                break
            option = payload[offset:offset + length]
            if option_type == 3 and length >= 32:
                prefix_len = option[2]
                prefix = ipaddress.IPv6Address(option[16:32])
                if prefix_len <= 128:
                    self.metadata.add(
                        "ipv6_prefixes",
                        str(ipaddress.IPv6Network((prefix, prefix_len), strict=False)),
                        source="ipv6_ra", confidence="advertised", now=now,
                        expires_at=now + struct.unpack("!I", option[4:8])[0],
                    )
            elif option_type == 25 and length >= 24:
                lifetime = struct.unpack("!I", option[4:8])[0]
                for index in range(8, length, 16):
                    if index + 16 <= length:
                        self.metadata.add(
                            "dns_servers", str(ipaddress.IPv6Address(option[index:index + 16])),
                            source="ipv6_rdnss", confidence="advertised", now=now,
                            expires_at=now + lifetime,
                        )
            elif option_type == 31 and length >= 16:
                lifetime = struct.unpack("!I", option[4:8])[0]
                for name in _dns_names(option[8:].rstrip(b"\x00")):
                    self.metadata.add(
                        "domains", name, source="ipv6_dnssl", confidence="advertised",
                        now=now, expires_at=now + lifetime,
                    )
            elif option_type == 37 and length > 2:
                origin = _uri_origin(option[2:].rstrip(b"\x00"))
                if origin:
                    self.metadata.add(
                        "captive_portals", origin, source="ipv6_option_37",
                        confidence="advertised", now=now,
                    )
            offset += length
        return touched


def _data_payload(frame: bytes) -> tuple[int, bytes] | None:
    if len(frame) < 32 or ((frame[0] & 0x0C) >> 2) != 2 or frame[1] & 0x40:
        return None
    subtype = frame[0] >> 4
    header_len = 24
    if frame[1] & 0x03 == 0x03:
        header_len += 6
    if subtype & 0x08:
        if len(frame) < header_len + 2:
            return None
        if frame[header_len] & 0x80:  # A-MSDU needs subframe parsing; do not guess.
            return None
        header_len += 2
    if frame[1] & 0x80:
        header_len += 4
    start = frame.find(b"\xaa\xaa\x03\x00\x00\x00", header_len, header_len + 16)
    if start < 0 or len(frame) < start + 8:
        return None
    return struct.unpack("!H", frame[start + 6:start + 8])[0], frame[start + 8:]


def _dhcp_options(payload: bytes) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = {}
    offset = 0
    while offset < len(payload) and len(result) <= 128:
        code = payload[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(payload):
            break
        length = payload[offset]
        offset += 1
        if offset + length > len(payload):
            break
        result.setdefault(code, []).append(payload[offset:offset + length])
        offset += length
    return result


def _first(options: dict[int, list[bytes]], code: int) -> bytes | None:
    values = options.get(code)
    return values[0] if values else None


def _u32(value: bytes | None) -> int | None:
    return struct.unpack("!I", value)[0] if value is not None and len(value) == 4 else None


def _addresses(chunks: Iterable[bytes], size: int) -> list[str]:
    raw = b"".join(chunks)
    if len(raw) % size:
        return []
    cls = ipaddress.IPv4Address if size == 4 else ipaddress.IPv6Address
    return [str(cls(raw[index:index + size])) for index in range(0, len(raw), size)]


def _classless_default_routers(chunks: Iterable[bytes]) -> list[str]:
    data = b"".join(chunks)
    routers = []
    offset = 0
    while offset < len(data):
        width = data[offset]
        offset += 1
        prefix_bytes = (width + 7) // 8
        if width > 32 or offset + prefix_bytes + 4 > len(data):
            break
        offset += prefix_bytes
        router = str(ipaddress.IPv4Address(data[offset:offset + 4]))
        offset += 4
        if width == 0:
            routers.append(router)
    return routers


def _dns_names(data: bytes) -> list[str]:
    names = []
    offset = 0
    labels: list[str] = []
    while offset < len(data) and len(names) < 16:
        length = data[offset]
        offset += 1
        if length == 0:
            if labels:
                names.append(".".join(labels))
                labels = []
            continue
        if length & 0xC0 or length > 63 or offset + length > len(data):
            break
        label = _safe_text(data[offset:offset + length], 63)
        offset += length
        if not label:
            break
        labels.append(label)
    if labels:
        names.append(".".join(labels))
    return names


def _dns_question(data: bytes) -> str | None:
    if len(data) < 17 or struct.unpack("!H", data[4:6])[0] < 1:
        return None
    names = _dns_names(data[12:])
    return names[0].casefold() if names else None


def _tls_sni(data: bytes) -> str | None:
    """Return a bounded ClientHello SNI, without retaining any TLS payload."""
    if len(data) < 9 or data[0] != 22:
        return None
    record_len = struct.unpack("!H", data[3:5])[0]
    if record_len > len(data) - 5 or data[5] != 1:
        return None
    hello_len = int.from_bytes(data[6:9], "big")
    end = min(9 + hello_len, 5 + record_len)
    offset = 9 + 2 + 32
    if offset >= end:
        return None
    session_len = data[offset]
    offset += 1 + session_len
    if offset + 2 > end:
        return None
    cipher_len = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2 + cipher_len
    if offset >= end:
        return None
    compression_len = data[offset]
    offset += 1 + compression_len
    if offset + 2 > end:
        return None
    extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    extensions_end = min(offset + extensions_len, end)
    while offset + 4 <= extensions_end:
        kind, length = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        if offset + length > extensions_end:
            return None
        if kind == 0 and length >= 5:
            extension = data[offset:offset + length]
            name_type = extension[2]
            name_len = struct.unpack("!H", extension[3:5])[0]
            if name_type == 0 and 5 + name_len <= len(extension):
                return _safe_hostname(extension[5:5 + name_len])
        offset += length
    return None


def _safe_hostname(value: bytes) -> str | None:
    text = _safe_text(value, 253)
    if not text:
        return None
    host = text.casefold()
    try:
        encoded = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = encoded.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63
        or label.startswith("-") or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in labels
    ):
        return None
    return encoded


def _looks_like_portal_host(host: str) -> bool:
    labels = host.casefold().replace("-", "").split(".")
    return any(
        label in {"portal", "captive", "hotspot", "guestwifi", "wifilogin"}
        or label.startswith("captiveportal")
        for label in labels
    )


def _safe_text(value: bytes, maximum: int) -> str | None:
    try:
        text = value[:maximum].decode("ascii").strip().strip(".")
    except UnicodeDecodeError:
        return None
    return text if text and all(32 < ord(char) < 127 for char in text) else None


def _uri_origin(value: bytes | None) -> str | None:
    if not value or len(value) > MAX_URI_BYTES:
        return None
    text = _safe_text(value, MAX_URI_BYTES)
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


def _usable_host(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_unspecified or address.is_multicast
        or (isinstance(address, ipaddress.IPv4Address) and value == "255.255.255.255")
    )


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)
