from wifit3.bluetooth.hci_protocol import (
    EVENT_EXTENDED_INQUIRY_RESULT,
    EVENT_LE_META,
    LE_ADVERTISING_REPORT,
    command_packet,
    parse_discovery_event,
)


def _ad(*fields: bytes) -> bytes:
    return b"".join(bytes([len(field)]) + field for field in fields)


def test_command_packet_uses_usb_hci_command_layout():
    assert command_packet(0x200C, b"\x01\x00") == b"\x0c\x20\x02\x01\x00"


def test_extended_inquiry_result_is_marked_classic():
    advertising = _ad(
        b"\x09Blue",
        b"\x03\x0f\x18",
        b"\xff\x4c\x00\xaa\xbb",
    ).ljust(240, b"\x00")
    parameters = (
        b"\x01"
        + bytes.fromhex("FFEEDDCCBBAA")
        + b"\x01\x00"
        + bytes.fromhex("0C0204")
        + b"\x00\x00"
        + bytes([0xD6])
        + advertising
    )

    observed = parse_discovery_event(EVENT_EXTENDED_INQUIRY_RESULT, parameters)

    assert len(observed) == 1
    assert observed[0].identifier == "AA:BB:CC:DD:EE:FF"
    assert observed[0].radio_type == "BT"
    assert observed[0].name == "Blue"
    assert observed[0].rssi == -42
    assert observed[0].class_of_device == 0x04020C
    assert observed[0].service_uuids == ("180f",)
    assert observed[0].manufacturer_ids == (0x004C,)


def test_le_advertising_report_is_marked_ble():
    advertising = _ad(b"\x09Sensor", b"\x03\x0f\x18")
    parameters = (
        bytes([LE_ADVERTISING_REPORT, 1, 0, 1])
        + bytes.fromhex("665544332211")
        + bytes([len(advertising)])
        + advertising
        + bytes([0xC4])
    )

    observed = parse_discovery_event(EVENT_LE_META, parameters)

    assert len(observed) == 1
    assert observed[0].identifier == "11:22:33:44:55:66"
    assert observed[0].radio_type == "BLE"
    assert observed[0].name == "Sensor"
    assert observed[0].rssi == -60
