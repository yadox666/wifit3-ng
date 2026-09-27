import ipaddress
import struct

from wifit3.dot11.dhcp import (
    DHCP_COOKIE,
    LLC_SNAP_IPV4,
    build_discover,
    build_release,
    build_request,
    parse_ack,
    parse_offer,
)
from wifit3.dot11.mac import mac_header


BSSID = bytes.fromhex("aabbccddeeff")
CLIENT = bytes.fromhex("021122334455")
XID = 0x12345678


def _offer_frame():
    bootp = bytearray(236)
    bootp[0:4] = b"\x02\x01\x06\x00"
    bootp[4:8] = struct.pack("!I", XID)
    bootp[16:20] = ipaddress.IPv4Address("192.168.40.25").packed
    bootp[28:34] = CLIENT
    portal = b"https://portal.example/login?token=private"
    options = (
        b"\x35\x01\x02"
        b"\x01\x04\xff\xff\xff\x00"
        b"\x03\x04\xc0\xa8\x28\x01"
        b"\x06\x08\x01\x01\x01\x01\x08\x08\x08\x08"
        b"\x36\x04\xc0\xa8\x28\x02"
        b"\x0f\x0bexample.net"
        b"\x33\x04\x00\x00\x0e\x10"
        + bytes((114, len(portal))) + portal
        + b"\xff"
    )
    dhcp = bytes(bootp) + DHCP_COOKIE + options
    udp = struct.pack("!HHHH", 67, 68, 8 + len(dhcp), 0) + dhcp
    ipv4 = (
        b"\x45\x00" + struct.pack("!H", 20 + len(udp))
        + b"\x00\x01\x00\x00\x40\x11\x00\x00"
        + ipaddress.IPv4Address("192.168.40.2").packed
        + ipaddress.IPv4Address("255.255.255.255").packed
        + udp
    )
    return (
        mac_header(b"\x08\x02", b"\xff" * 6, BSSID, bytes.fromhex("000102030405"))
        + LLC_SNAP_IPV4 + ipv4
    )


def test_build_discover_contains_randomized_client_and_requested_options():
    frame = build_discover(BSSID, CLIENT, XID)
    start = frame.index(DHCP_COOKIE) - 236
    body = frame[start:]

    assert frame[4:10] == BSSID
    assert frame[10:16] == CLIENT
    assert struct.unpack("!I", body[4:8])[0] == XID
    assert body[28:34] == CLIENT
    assert b"\x35\x01\x01" in body
    assert b"\x72" in body  # captive-portal option requested
    assert len(body) >= 300  # BOOTP minimum for embedded-server compatibility


def test_parse_offer_extracts_network_data_and_discards_portal_path():
    offer = parse_offer(_offer_frame(), XID, CLIENT)

    assert offer is not None
    assert offer.offered_ip == "192.168.40.25"
    assert offer.subnet_mask == "255.255.255.0"
    assert offer.routers == ("192.168.40.1",)
    assert offer.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert offer.server == "192.168.40.2"
    assert offer.domain == "example.net"
    assert offer.portal == "https://portal.example"
    assert offer.lease_seconds == 3600


def test_parse_offer_rejects_wrong_transaction_or_client():
    frame = _offer_frame()

    assert parse_offer(frame, XID + 1, CLIENT) is None
    assert parse_offer(frame, XID, bytes.fromhex("021122334466")) is None


def test_request_ack_and_release_complete_temporary_lease_flow():
    request = build_request(
        BSSID, CLIENT, XID, "192.168.40.25", "192.168.40.2",
    )
    request_body = request[request.index(DHCP_COOKIE) - 236:]
    assert b"\x35\x01\x03" in request_body
    assert b"\x32\x04\xc0\xa8\x28\x19" in request_body
    assert b"\x36\x04\xc0\xa8\x28\x02" in request_body

    ack_frame = _offer_frame().replace(b"\x35\x01\x02", b"\x35\x01\x05", 1)
    lease, nak = parse_ack(ack_frame, XID, CLIENT)
    assert nak is False
    assert lease is not None
    assert lease.offered_ip == "192.168.40.25"

    release = build_release(
        BSSID,
        CLIENT,
        bytes.fromhex("102030405060"),
        XID,
        "192.168.40.25",
        "192.168.40.2",
    )
    release_body = release[release.index(DHCP_COOKIE) - 236:]
    assert release[16:22] == bytes.fromhex("102030405060")
    assert b"\x35\x01\x07" in release_body
