import ipaddress
import struct
from types import SimpleNamespace

from wifit3.dot11.dhcp import DhcpOffer
from wifit3.wlan.network_metadata import NetworkMetadata, PassiveNetworkAnalyzer


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "02:11:22:33:44:55"


def _mac(value):
    return bytes.fromhex(value.replace(":", ""))


def _frame(payload, ethertype=0x0800, *, client=CLIENT, from_ds=True):
    if from_ds:
        header = (
            b"\x08\x02\x00\x00" + _mac(client) + _mac(BSSID)
            + b"\x00\x01\x02\x03\x04\x05" + b"\x00\x00"
        )
    else:
        header = (
            b"\x08\x01\x00\x00" + _mac(BSSID) + _mac(client)
            + b"\x00\x01\x02\x03\x04\x05" + b"\x00\x00"
        )
    raw = header + b"\xaa\xaa\x03\x00\x00\x00" + struct.pack("!H", ethertype) + payload
    return SimpleNamespace(
        raw=raw,
        bssid=BSSID,
        client_mac=client,
        to_ds=not from_ds,
        from_ds=from_ds,
    )


def _ipv4(payload, protocol, source, dest):
    total = 20 + len(payload)
    return (
        b"\x45\x00" + struct.pack("!H", total) + b"\x00\x01\x00\x00"
        + b"\x40" + bytes([protocol]) + b"\x00\x00"
        + ipaddress.IPv4Address(source).packed
        + ipaddress.IPv4Address(dest).packed
        + payload
    )


def _dhcp_ack():
    fixed = bytearray(240)
    fixed[0] = 2
    fixed[1] = 1
    fixed[2] = 6
    fixed[16:20] = ipaddress.IPv4Address("192.168.50.42").packed
    fixed[28:34] = _mac(CLIENT)
    fixed[236:240] = b"\x63\x82\x53\x63"
    options = (
        b"\x35\x01\x05"
        b"\x01\x04\xff\xff\xff\x00"
        b"\x03\x04\xc0\xa8\x32\x01"
        b"\x06\x08\x01\x01\x01\x01\x08\x08\x08\x08"
        b"\x36\x04\xc0\xa8\x32\x02"
        b"\x0f\x0bexample.net"
        b"\x33\x04\x00\x00\x0e\x10"
        b"\x72\x24https://login.example.test/path?secret=x"
        b"\xff"
    )
    body = bytes(fixed) + options
    udp = struct.pack("!HHHH", 67, 68, 8 + len(body), 0) + body
    return _frame(_ipv4(udp, 17, "192.168.50.2", "255.255.255.255"))


def test_dhcp_ack_populates_ap_and_broadcast_client_without_storing_url_path():
    metadata = NetworkMetadata(BSSID, "Cafe")
    touched = PassiveNetworkAnalyzer(metadata).observe(_dhcp_ack(), now=1000)

    assert touched == {CLIENT}
    assert [fact.value for fact in metadata.facts["ipv4_networks"]] == ["192.168.50.0/24"]
    assert [fact.value for fact in metadata.facts["gateways"]] == ["192.168.50.1"]
    assert {fact.value for fact in metadata.facts["dns_servers"]} == {
        "1.1.1.1", "8.8.8.8",
    }
    assert [fact.value for fact in metadata.facts["dhcp_servers"]] == ["192.168.50.2"]
    assert [fact.value for fact in metadata.facts["domains"]] == ["example.net"]
    assert [fact.value for fact in metadata.facts["captive_portals"]] == [
        "https://login.example.test",
    ]
    client = metadata.clients[CLIENT]
    assert [fact.value for fact in client.facts["ipv4_addresses"]] == ["192.168.50.42"]
    assert client.facts["ipv4_addresses"][0].expires_at == 4600


def test_active_dhcp_offer_populates_the_same_ap_and_client_metadata():
    metadata = NetworkMetadata(BSSID, "Cafe")
    offer = DhcpOffer(
        offered_ip="192.168.0.161",
        server="192.168.0.1",
        subnet_mask="255.255.255.0",
        routers=("192.168.0.1",),
        dns_servers=("192.168.0.1", "192.168.0.1"),
        domain="lan",
        portal="https://portal.example",
        lease_seconds=3600,
    )

    assert metadata.observe_dhcp_offer(offer, client_mac=CLIENT, now=1000)

    assert [fact.value for fact in metadata.facts["ipv4_networks"]] == [
        "192.168.0.0/24",
    ]
    assert [fact.value for fact in metadata.facts["gateways"]] == ["192.168.0.1"]
    assert [fact.value for fact in metadata.facts["dns_servers"]] == ["192.168.0.1"]
    assert [fact.value for fact in metadata.facts["dhcp_servers"]] == ["192.168.0.1"]
    assert metadata.facts["captive_portals"][0].source == "dhcp_option_114"
    client = metadata.clients[CLIENT]
    assert [fact.value for fact in client.facts["ipv4_addresses"]] == [
        "192.168.0.161",
    ]
    assert client.facts["ipv4_addresses"][0].expires_at == 4600


def test_connectivity_result_records_reachability_without_response_content():
    metadata = NetworkMetadata(BSSID, "Cafe")
    result = SimpleNamespace(
        status="internet_confirmed",
        gateway="192.168.1.1",
        gateway_reachable=True,
        dns_server="192.168.1.1",
        dns_reachable=True,
        portal_origin=None,
        detail="Expected HTTP 204 received",
    )

    assert metadata.observe_connectivity(
        result, client_mac=CLIENT, now=2000, expires_at=5600,
    )

    assert metadata.facts["connectivity"][0].value == "internet_confirmed"
    assert metadata.facts["gateway_reachability"][0].value == "192.168.1.1"
    assert metadata.facts["dns_reachability"][0].value == "192.168.1.1"
    assert metadata.facts["portal_status"][0].value == "not_detected"
    serialized = str(metadata.to_dict())
    assert "generate_204" not in serialized
    assert "response" not in serialized.casefold()


def test_plain_http_redirect_is_observed_and_strips_sensitive_path():
    response = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: https://portal.example/login?token=private\r\n"
        b"Set-Cookie: secret=value\r\n\r\nbody"
    )
    tcp = (
        struct.pack("!HHII", 80, 49152, 1, 1)
        + b"\x50\x18\x10\x00\x00\x00\x00\x00"
        + response
    )
    packet = _frame(_ipv4(tcp, 6, "192.168.50.1", "192.168.50.42"))
    metadata = NetworkMetadata(BSSID, "Cafe")

    PassiveNetworkAnalyzer(metadata).observe(packet, now=2000)

    fact = metadata.facts["captive_portals"][0]
    assert fact.value == "https://portal.example"
    assert fact.confidence == "observed"
    serialized = str(metadata.to_dict())
    assert "token" not in serialized
    assert "Cookie" not in serialized
    assert "body" not in serialized


def test_protected_and_malformed_frames_are_ignored():
    metadata = NetworkMetadata(BSSID, "Cafe")
    analyzer = PassiveNetworkAnalyzer(metadata)
    malformed = SimpleNamespace(raw=b"\x08", client_mac=CLIENT)
    protected = _dhcp_ack()
    protected.raw = protected.raw[:1] + bytes([protected.raw[1] | 0x40]) + protected.raw[2:]

    assert analyzer.observe(malformed, now=1) == set()
    assert analyzer.observe(protected, now=1) == set()
    assert metadata.facts == {}


def test_ipv6_router_advertisement_records_prefix_router_dns_and_portal():
    prefix = (
        b"\x03\x04\x40\xc0"
        + struct.pack("!II", 3600, 1800)
        + b"\x00\x00\x00\x00"
        + ipaddress.IPv6Address("2001:db8:abcd::").packed
    )
    rdnss = (
        b"\x19\x03\x00\x00" + struct.pack("!I", 1200)
        + ipaddress.IPv6Address("2001:4860:4860::8888").packed
    )
    uri = b"https://portal-v6.example/path"
    units = (2 + len(uri) + 7) // 8
    portal = bytes([37, units]) + uri + b"\x00" * (units * 8 - 2 - len(uri))
    ra = (
        b"\x86\x00\x00\x00\x40\x00" + struct.pack("!H", 1800)
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + prefix + rdnss + portal
    )
    ipv6 = (
        b"\x60\x00\x00\x00" + struct.pack("!H", len(ra)) + b"\x3a\xff"
        + ipaddress.IPv6Address("fe80::1").packed
        + ipaddress.IPv6Address("ff02::1").packed
        + ra
    )
    packet = _frame(ipv6, ethertype=0x86DD)
    packet.client_mac = None
    metadata = NetworkMetadata(BSSID, "Cafe")

    PassiveNetworkAnalyzer(metadata).observe(packet, now=3000)

    assert [fact.value for fact in metadata.facts["ipv6_prefixes"]] == [
        "2001:db8:abcd::/64",
    ]
    assert [fact.value for fact in metadata.facts["gateways"]] == ["fe80::1"]
    assert [fact.value for fact in metadata.facts["dns_servers"]] == [
        "2001:4860:4860::8888",
    ]
    assert [fact.value for fact in metadata.facts["captive_portals"]] == [
        "https://portal-v6.example",
    ]
