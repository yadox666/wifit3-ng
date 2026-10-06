import ipaddress
import struct

from wifit3.dot11.connectivity import (
    LLC_ARP,
    TCP_ACK,
    TCP_SYN,
    build_arp_request,
    build_mdns_service_query,
    build_nbns_node_status_query,
    build_ssdp_discovery_query,
    build_tcp_frame,
    build_udp_frame,
    build_wsd_probe,
    classify_announced_services,
    parse_arp_reply,
    parse_dns_response,
    parse_http_response,
    parse_mdns_services,
    parse_nbns_node_status,
    parse_ssdp_services,
    parse_tcp_segment,
    parse_wsd_services,
)
from wifit3.dot11.mac import mac_header


BSSID = bytes.fromhex("aabbccddeeff")
CLIENT = bytes.fromhex("021122334455")
GATEWAY = bytes.fromhex("102030405060")


def test_arp_request_and_matching_reply():
    request = build_arp_request(
        BSSID, CLIENT, "192.168.1.20", "192.168.1.1",
    )
    assert request[4:10] == BSSID
    assert request[10:16] == CLIENT
    assert request[16:22] == b"\xff" * 6

    body = (
        b"\x00\x01\x08\x00\x06\x04\x00\x02"
        + GATEWAY
        + ipaddress.IPv4Address("192.168.1.1").packed
        + CLIENT
        + ipaddress.IPv4Address("192.168.1.20").packed
    )
    reply = (
        mac_header(b"\x08\x02", CLIENT, BSSID, GATEWAY)
        + LLC_ARP
        + body
    )
    parsed = parse_arp_reply(
        reply, CLIENT, "192.168.1.20", "192.168.1.1",
    )
    assert parsed is not None
    assert parsed.mac == GATEWAY


def test_dns_response_extracts_only_ipv4_answers():
    question = (
        b"\x11connectivitycheck\x07gstatic\x03com\x00"
        b"\x00\x01\x00\x01"
    )
    answer = (
        b"\xc0\x0c"
        + b"\x00\x01\x00\x01"
        + struct.pack("!I", 60)
        + b"\x00\x04"
        + ipaddress.IPv4Address("142.250.74.131").packed
    )
    dns = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
    udp = struct.pack("!HHHH", 53, 53000, 8 + len(dns), 0) + dns
    ipv4 = (
        b"\x45\x00" + struct.pack("!H", 20 + len(udp))
        + b"\x00\x01\x00\x00\x40\x11\x00\x00"
        + ipaddress.IPv4Address("192.168.1.1").packed
        + ipaddress.IPv4Address("192.168.1.20").packed
        + udp
    )
    frame = mac_header(b"\x08\x02", CLIENT, BSSID, GATEWAY) + bytes.fromhex(
        "aaaa030000000800"
    ) + ipv4

    assert parse_dns_response(
        frame, "192.168.1.20", "192.168.1.1", 53000, 0x1234,
    ) == ("142.250.74.131",)


def test_mdns_service_enumeration_query_and_sanitized_response():
    query = build_mdns_service_query(
        BSSID,
        CLIENT,
        "192.168.1.20",
    )
    assert query[16:22] == bytes.fromhex("01005e0000fb")
    assert ipaddress.IPv4Address(query[48:52]) == ipaddress.IPv4Address("224.0.0.251")

    def dns_name(value: str) -> bytes:
        return b"".join(
            bytes((len(label),)) + label.encode("ascii")
            for label in value.split(".")
        ) + b"\x00"

    owner = dns_name("_services._dns-sd._udp.local")
    target = dns_name("_airplay._tcp.local")
    answer = owner + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
    dns = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + answer
    frame = build_udp_frame(
        BSSID,
        GATEWAY,
        bytes.fromhex("01005e0000fb"),
        "192.168.1.5",
        "224.0.0.251",
        5353,
        5353,
        dns,
        ident=1,
    )

    parsed = parse_mdns_services(frame)
    assert parsed is not None
    assert parsed.source_ip == "192.168.1.5"
    assert parsed.service_types == ("_airplay._tcp.local",)
    assert "instance" not in repr(parsed).casefold()


def test_ssdp_and_wsd_extract_only_sanitized_service_types():
    client_port = 51000
    ssdp_query = build_ssdp_discovery_query(
        BSSID, CLIENT, "192.168.1.20", source_port=client_port,
    )
    assert bytes.fromhex("01005e7ffffa") == ssdp_query[16:22]
    ssdp_body = (
        b"HTTP/1.1 200 OK\r\n"
        b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        b"USN: uuid:personal-serial::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        b"LOCATION: http://192.168.1.5/private.xml\r\n\r\n"
    )
    ssdp_frame = build_udp_frame(
        BSSID, GATEWAY, CLIENT,
        "192.168.1.5", "192.168.1.20",
        1900, client_port, ssdp_body, ident=1,
    )
    ssdp = parse_ssdp_services(ssdp_frame, client_port)
    assert ssdp is not None
    assert ssdp.service_types == (
        "ssdp:urn:schemas-upnp-org:device:mediarenderer:1",
    )
    assert "personal-serial" not in repr(ssdp)

    wsd_query = build_wsd_probe(
        BSSID, CLIENT, "192.168.1.20", source_port=client_port,
    )
    assert b"<d:Probe/>" in wsd_query
    wsd_body = (
        b'<s:Envelope><d:ProbeMatches><d:ProbeMatch><d:Types>'
        b'dn:NetworkVideoTransmitter wprt:PrintDevice'
        b'</d:Types><d:Scopes>onvif://personal/name</d:Scopes>'
        b'</d:ProbeMatch></d:ProbeMatches></s:Envelope>'
    )
    wsd_frame = build_udp_frame(
        BSSID, GATEWAY, CLIENT,
        "192.168.1.6", "192.168.1.20",
        3702, client_port, wsd_body, ident=2,
    )
    wsd = parse_wsd_services(wsd_frame, client_port)
    assert wsd is not None
    assert wsd.service_types == (
        "wsd:networkvideotransmitter",
        "wsd:printdevice",
    )
    assert "personal" not in repr(wsd)


def test_nbns_node_status_returns_roles_without_host_names():
    client_port = 52000
    transaction_id = 0x1234
    query = build_nbns_node_status_query(
        BSSID,
        CLIENT,
        GATEWAY,
        "192.168.1.20",
        "192.168.1.7",
        source_port=client_port,
        transaction_id=transaction_id,
    )
    assert b"WORKSTATION" not in query

    entries = (
        b"PRIVATE-NAME   " + b"\x00\x04\x00"
        + b"PRIVATE-NAME   " + b"\x20\x04\x00"
    )
    rdata = bytes((2,)) + entries + GATEWAY
    answer = b"\x00" + struct.pack("!HHIH", 0x21, 1, 120, len(rdata)) + rdata
    body = struct.pack("!HHHHHH", transaction_id, 0x8500, 0, 1, 0, 0) + answer
    frame = build_udp_frame(
        BSSID, GATEWAY, CLIENT,
        "192.168.1.7", "192.168.1.20",
        137, client_port, body, ident=transaction_id,
    )
    parsed = parse_nbns_node_status(frame, client_port)

    assert parsed is not None
    assert parsed.roles == ("file_sharing", "workstation")
    assert "PRIVATE-NAME" not in repr(parsed)


def test_announced_service_roles_cover_common_device_families():
    assert classify_announced_services((
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_matter._tcp.local",
        "_ipp._tcp.local",
        "_smb._tcp.local",
        "wsd:networkvideotransmitter",
    )) == (
        "apple_media",
        "camera",
        "file_sharing",
        "media_cast",
        "printer",
        "smart_home",
    )


def test_tcp_segment_and_http_redirect_are_bounded_to_origin():
    frame = build_tcp_frame(
        BSSID, BSSID, CLIENT,
        "142.250.74.131", "192.168.1.20",
        80, 53001, 100, 200, TCP_SYN | TCP_ACK,
    )
    segment = parse_tcp_segment(
        frame, "192.168.1.20", "142.250.74.131", 53001, 80,
    )
    assert segment is not None
    assert segment.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK

    response = parse_http_response(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: https://portal.example/login?token=secret\r\n"
        b"Set-Cookie: secret=value\r\n\r\nprivate body"
    )
    assert response is not None
    assert response.status == 302
    assert response.location_origin == "https://portal.example"


def test_expected_connectivity_response_is_204():
    response = parse_http_response(b"HTTP/1.1 204 No Content\r\n\r\n")
    assert response is not None
    assert response.status == 204
    assert response.location_origin is None
