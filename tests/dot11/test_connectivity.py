import ipaddress
import struct

from wifit3.dot11.connectivity import (
    LLC_ARP,
    TCP_ACK,
    TCP_SYN,
    build_arp_request,
    build_tcp_frame,
    parse_arp_reply,
    parse_dns_response,
    parse_http_response,
    parse_tcp_segment,
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
