from wifit3.bluetooth.hci_protocol import (
    EVENT_EXTENDED_INQUIRY_RESULT,
    EVENT_INQUIRY_RESULT_WITH_RSSI,
    EVENT_LE_META,
    LE_ADVERTISING_REPORT,
    command_packet,
    parse_discovery_event,
    parse_remote_name_event,
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
    assert observed[0].page_scan_repetition_mode == 1
    assert observed[0].clock_offset == 0
    assert observed[0].class_of_device == 0x04020C
    assert observed[0].service_uuids == ("180f",)
    assert observed[0].manufacturer_ids == (0x004C,)


def test_remote_name_complete_decodes_address_and_utf8_name():
    parameters = (
        b"\x00"
        + bytes.fromhex("FFEEDDCCBBAA")
        + "Living Room Speaker".encode()
        + b"\x00"
    )

    assert parse_remote_name_event(parameters) == (
        "AA:BB:CC:DD:EE:FF",
        "Living Room Speaker",
    )


def test_multiple_inquiry_results_are_parsed_as_packed_records():
    parameters = (
        b"\x02"
        + bytes.fromhex("FFEEDDCCBBAA01000C02043412D6")
        + bytes.fromhex("66554433221102000425027856C4")
    )

    observed = parse_discovery_event(EVENT_INQUIRY_RESULT_WITH_RSSI, parameters)

    assert [item.identifier for item in observed] == [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
    ]
    assert [item.page_scan_repetition_mode for item in observed] == [1, 2]
    assert [item.class_of_device for item in observed] == [0x04020C, 0x022504]
    assert [item.clock_offset for item in observed] == [0x1234, 0x5678]
    assert [item.rssi for item in observed] == [-42, -60]


def test_le_advertising_report_is_marked_ble():
    advertising = _ad(
        b"\x09Sensor",
        b"\x03\x0f\x18",
        b"\x19\x43\x09",
    )
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
    assert observed[0].address_type == "non-resolvable-private"
    assert observed[0].appearance == 0x0943


def test_le_report_classifies_resolvable_private_address():
    parameters = (
        bytes([LE_ADVERTISING_REPORT, 1, 0, 1])
        + bytes.fromhex("665544332240")
        + b"\x00"
        + bytes([0xC4])
    )

    observed = parse_discovery_event(EVENT_LE_META, parameters)

    assert observed[0].identifier == "40:22:33:44:55:66"
    assert observed[0].address_type == "resolvable-private"


def test_le_report_recognizes_apple_proximity_pairing_protocol():
    advertising = _ad(b"\xff\x4c\x00\x07\x19\x01\x0e\x20")
    parameters = (
        bytes([LE_ADVERTISING_REPORT, 1, 0, 1])
        + bytes.fromhex("665544332240")
        + bytes([len(advertising)])
        + advertising
        + bytes([0xC4])
    )

    observed = parse_discovery_event(EVENT_LE_META, parameters)[0]

    assert observed.protocol_category == "Audio"
    assert observed.protocol_type == "Apple Proximity Pairing audio"
    assert observed.protocol_confidence == "high"
