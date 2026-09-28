import struct

import pytest

from wifit3.bluetooth.classic_sdp import (
    SdpProtocolError,
    parse_service_records,
    parse_data_element,
    parse_service_search_attribute_response,
    service_search_attribute_request,
)


def _sequence(payload: bytes) -> bytes:
    return b"\x35" + bytes((len(payload),)) + payload


def test_service_search_request_browses_public_records_and_all_attributes():
    packet = service_search_attribute_request(0x1234, b"\xaa\xbb")

    assert packet[0] == 0x06
    assert packet[1:3] == b"\x12\x34"
    assert bytes.fromhex("3503191002") in packet
    assert bytes.fromhex("35050a0000ffff") in packet
    assert packet.endswith(b"\x02\xaa\xbb")


def test_response_continuation_and_service_record_parsing():
    attributes = (
        b"\x09\x00\x01" + _sequence(b"\x19\x11\x0b")
        + b"\x09\x01\x00" + b"\x25\x07Headset"
    )
    encoded = _sequence(_sequence(attributes))
    parameters = struct.pack(">H", len(encoded)) + encoded + b"\x02\xaa\xbb"
    response = b"\x07\x00\x01" + struct.pack(">H", len(parameters)) + parameters

    fragment, continuation = parse_service_search_attribute_response(response, 1)
    services = parse_service_records(fragment)

    assert continuation == b"\xaa\xbb"
    assert services[0].uuid == "110b"
    assert services[0].name == "Headset"


def test_response_rejects_transaction_mismatch():
    response = b"\x07\x00\x02\x00\x03\x00\x00\x00"

    with pytest.raises(SdpProtocolError, match="transaction"):
        parse_service_search_attribute_response(response, 1)


def test_response_rejects_oversized_continuation_state():
    parameters = b"\x00\x00\x11" + b"x" * 17
    response = b"\x07\x00\x01" + struct.pack(">H", len(parameters)) + parameters

    with pytest.raises(SdpProtocolError, match="continuation"):
        parse_service_search_attribute_response(response, 1)


def test_data_element_parser_bounds_nesting_depth():
    encoded = b"\x00"
    for _ in range(18):
        encoded = _sequence(encoded)

    with pytest.raises(SdpProtocolError, match="nested"):
        parse_data_element(encoded)
