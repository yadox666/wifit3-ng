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


def _amsdu_frame(payloads, *, client=CLIENT, from_ds=False):
    if from_ds:
        header = (
            b"\x88\x02\x00\x00" + _mac(client) + _mac(BSSID)
            + b"\x00\x01\x02\x03\x04\x05" + b"\x00\x00"
        )
    else:
        header = (
            b"\x88\x01\x00\x00" + _mac(BSSID) + _mac(client)
            + b"\x00\x01\x02\x03\x04\x05" + b"\x00\x00"
        )
    aggregate = bytearray()
    for index, (ethertype, payload) in enumerate(payloads):
        msdu = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack("!H", ethertype) + payload
        aggregate += _mac("00:01:02:03:04:05") + _mac(client)
        aggregate += struct.pack("!H", len(msdu)) + msdu
        if index < len(payloads) - 1:
            aggregate += b"\x00" * (-len(aggregate) % 4)
    return SimpleNamespace(
        raw=header + b"\x80\x00" + aggregate,
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


def _tcp_packet(body, dest_port, *, from_ds=False):
    tcp = (
        struct.pack("!HHII", 49152, dest_port, 1, 1)
        + b"\x50\x18\x10\x00\x00\x00\x00\x00"
        + body
    )
    return _frame(
        _ipv4(tcp, 6, "192.168.50.42", "93.184.216.34"),
        from_ds=from_ds,
    )


def _dns_query(host):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in host.split(".")
    ) + b"\x00"
    dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 49152, 53, 8 + len(dns), 0) + dns
    return _frame(
        _ipv4(udp, 17, "192.168.50.42", "1.1.1.1"),
        from_ds=False,
    )


def _tls_client_hello(host):
    encoded = host.encode("ascii")
    server_name = struct.pack("!H", len(encoded) + 3) + b"\x00" + struct.pack(
        "!H", len(encoded),
    ) + encoded
    extension = b"\x00\x00" + struct.pack("!H", len(server_name)) + server_name
    hello = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + b"\x00\x02\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(extension)) + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


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


def test_websites_deduplicate_by_host_and_prefer_full_http_url_per_client():
    metadata = NetworkMetadata(BSSID, "Cafe")
    analyzer = PassiveNetworkAnalyzer(metadata)

    analyzer.observe(_dns_query("www.example.com"), now=100)
    analyzer.observe(_tcp_packet(_tls_client_hello("www.example.com"), 443), now=101)
    request = (
        b"GET /products/item?color=blue&token=private HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"Cookie: should-not-be-stored\r\n\r\n"
    )
    analyzer.observe(_tcp_packet(request, 80), now=102)

    expected = "http://www.example.com/products/item?color=blue&token=REDACTED"
    assert [fact.value for fact in metadata.facts["websites"]] == [expected]
    client_facts = metadata.clients[CLIENT].facts["websites"]
    assert [fact.value for fact in client_facts] == [expected]
    assert client_facts[0].source == "http_request"
    serialized = str(metadata.to_dict())
    assert "private" not in serialized
    assert "should-not-be-stored" not in serialized


def test_all_unique_full_urls_survive_while_later_dns_stays_deduplicated():
    metadata = NetworkMetadata(BSSID, "Cafe")
    analyzer = PassiveNetworkAnalyzer(metadata)

    first = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
    second = b"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
    analyzer.observe(_tcp_packet(first, 80), now=100)
    analyzer.observe(_tcp_packet(second, 80), now=101)
    analyzer.observe(_dns_query("example.com"), now=102)

    websites = metadata.clients[CLIENT].facts["websites"]
    assert len(websites) == 2
    assert {fact.value for fact in websites} == {
        "http://example.com/first",
        "http://example.com/second",
    }


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


def _quic_client_hello(host):
    encoded = host.encode("ascii")
    sni = b"\x00" + struct.pack("!H", len(encoded)) + encoded
    sni_list = struct.pack("!H", len(sni)) + sni
    ext = struct.pack("!HH", 0, len(sni_list)) + sni_list
    exts = struct.pack("!H", len(ext)) + ext
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + b"\x00\x02\x13\x01" + b"\x01\x00"
        + exts
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _quic_initial_frame(host):
    from wifit3.wlan import quic

    pkt = quic._seal_client_initial(
        bytes.fromhex("0001020304050607"), _quic_client_hello(host), pad_to=1200,
    )
    udp = struct.pack("!HHHH", 49152, 443, 8 + len(pkt), 0) + pkt
    return _frame(_ipv4(udp, 17, "192.168.50.42", "93.184.216.34"), from_ds=False)


def _tcp_segment(body, dest_port, seq, *, from_ds=False):
    tcp = (
        struct.pack("!HHII", 49152, dest_port, seq, 1)
        + b"\x50\x18\x10\x00\x00\x00\x00\x00"
        + body
    )
    return _frame(_ipv4(tcp, 6, "192.168.50.42", "93.184.216.34"), from_ds=from_ds)


def test_observe_arp_neighbors_records_ip_on_each_client():
    metadata = NetworkMetadata(BSSID, "Cafe")
    neighbor = "6a:a9:f9:87:7e:d1"
    assert metadata.observe_arp_neighbors(
        [("192.168.0.84", neighbor)], now=100,
    )
    assert metadata.clients[neighbor].facts["ipv4_addresses"][0].value == "192.168.0.84"
    assert metadata.clients[neighbor].facts["ipv4_addresses"][0].source == "arp_sweep_active"


def test_observe_bonjour_services_keeps_only_sanitized_service_types():
    metadata = NetworkMetadata(BSSID, "Cafe")
    neighbor = "6a:a9:f9:87:7e:d1"

    assert metadata.observe_bonjour_services(
        [
            ("192.168.0.84", neighbor, "_airplay._tcp.local"),
            ("192.168.0.84", neighbor, "Alice's iPhone._airplay._tcp.local"),
        ],
        now=100,
    )

    assert [
        fact.value for fact in metadata.facts["bonjour_services"]
    ] == ["_airplay._tcp.local"]
    assert metadata.clients[neighbor].facts["bonjour_services"][0].value == (
        "_airplay._tcp.local"
    )


def test_local_discovery_records_services_and_roles_without_names():
    metadata = NetworkMetadata(BSSID, "Cafe")
    neighbor = "6a:a9:f9:87:7e:d1"

    assert metadata.observe_local_discovery(
        [
            ("192.168.0.84", neighbor, "_airplay._tcp.local", "mdns"),
            (
                "192.168.0.84",
                neighbor,
                "ssdp:urn:schemas-upnp-org:device:mediarenderer:1",
                "ssdp",
            ),
            ("192.168.0.84", neighbor, "PRIVATE-NAME", "nbns"),
        ],
        [("192.168.0.84", neighbor, "apple_media")],
        now=100,
    )

    assert {
        fact.value for fact in metadata.facts["announced_services"]
    } == {
        "_airplay._tcp.local",
        "ssdp:urn:schemas-upnp-org:device:mediarenderer:1",
    }
    assert metadata.clients[neighbor].facts["device_roles"][0].value == "apple_media"
    assert "PRIVATE-NAME" not in str(metadata.to_dict())


def test_quic_initial_sni_recorded_as_website():
    metadata = NetworkMetadata(BSSID, "Cafe")
    touched = PassiveNetworkAnalyzer(metadata).observe(
        _quic_initial_frame("video.example.com"), now=500,
    )
    assert touched == {CLIENT}
    assert [fact.value for fact in metadata.facts["websites"]] == [
        "https://video.example.com",
    ]
    assert metadata.facts["websites"][0].source == "quic_sni"


def test_tls_client_hello_split_across_tcp_segments_is_reassembled():
    metadata = NetworkMetadata(BSSID, "Cafe")
    analyzer = PassiveNetworkAnalyzer(metadata)
    record = _tls_client_hello("split.example.com")
    part1, part2 = record[:20], record[20:]

    analyzer.observe(_tcp_segment(part1, 443, seq=1000), now=1)
    assert "websites" not in metadata.facts          # incomplete ClientHello: nothing yet
    touched = analyzer.observe(_tcp_segment(part2, 443, seq=1000 + len(part1)), now=2)

    assert CLIENT in touched
    assert [fact.value for fact in metadata.facts["websites"]] == [
        "https://split.example.com",
    ]
    assert metadata.facts["websites"][0].source == "tls_sni"


def test_qos_amsdu_subframes_are_analyzed_for_websites():
    dns_ip = _dns_query("dns-in-aggregate.example").raw[32:]
    tls_ip = _tcp_packet(
        _tls_client_hello("tls-in-aggregate.example"), 443,
    ).raw[32:]
    packet = _amsdu_frame([(0x0800, dns_ip), (0x0800, tls_ip)])
    metadata = NetworkMetadata(BSSID, "Cafe")

    touched = PassiveNetworkAnalyzer(metadata).observe(packet, now=600)

    assert touched == {CLIENT}
    assert {fact.value for fact in metadata.clients[CLIENT].facts["websites"]} == {
        "dns-in-aggregate.example",
        "https://tls-in-aggregate.example",
    }
