import pytest

from wifit3.bluetooth.analytics import (
    ble_advertisement_matches_target,
    device_lacks_usb_hci_bd_addr,
    discovery_names_match,
    hci_bd_addr_bytes,
    is_bluetooth_bd_addr,
    le_hci_peer_address_type,
    protocol_type_hint,
)


@pytest.mark.parametrize(
    ("service_uuid", "category", "device_type", "confidence"),
    [
        ("feaa", "Beacon", "Google Eddystone beacon", "high"),
        ("fcd2", "Sensor", "BTHome sensor", "high"),
        ("feed", "Beacon", "Tile tracker", "high"),
        ("fe9a", "Beacon", "Estimote beacon", "high"),
        ("fe59", "Other", "Nordic Secure DFU mode", "medium"),
        ("fd6f", "Other", "Exposure Notification broadcaster", "medium"),
        ("3100", "Sensor", "Raven acoustic sensor", "medium"),
        (
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
            "Other",
            "Nordic UART device",
            "medium",
        ),
        (
            "cba20d00-224d-11e6-9fb8-0002a5d5c51b",
            "Appliance",
            "SwitchBot device",
            "high",
        ),
        (
            "b42e4a8e-ade7-11e4-89d3-123b93f75cba",
            "Sensor",
            "Airthings air-quality sensor",
            "high",
        ),
        (
            "f0cd1400-95da-4f4b-9ac8-aa55d312af0c",
            "Sensor",
            "Aranet environmental sensor",
            "high",
        ),
        (
            "0000fe95-0000-1000-8000-00805f9b34fb",
            "Other",
            "Xiaomi MiBeacon device",
            "medium",
        ),
    ],
)
def test_service_protocols_provide_bounded_device_evidence(
    service_uuid, category, device_type, confidence,
):
    hint = protocol_type_hint({}, {}, (service_uuid,))

    assert hint["protocol_category"] == category
    assert hint["protocol_type"] == device_type
    assert hint["protocol_confidence"] == confidence


def test_altbeacon_signature_is_not_tied_to_one_company_identifier():
    hint = protocol_type_hint({0x1234: b"\xbe\xac" + b"\x00" * 20}, {})

    assert hint["protocol_category"] == "Beacon"
    assert hint["protocol_type"] == "AltBeacon"
    assert hint["protocol_confidence"] == "high"


@pytest.mark.parametrize("data_format", [0x03, 0x05])
def test_ruuvi_data_formats_identify_sensor_protocol(data_format):
    hint = protocol_type_hint({0x0499: bytes([data_format]) + b"\x00" * 10}, {})

    assert hint["protocol_category"] == "Sensor"
    assert hint["protocol_type"] == "Ruuvi sensor"
    assert hint["protocol_confidence"] == "high"


def test_apple_homekit_signature_does_not_claim_a_physical_subtype():
    hint = protocol_type_hint({0x004C: b"\x06\x01\x02"}, {})

    assert hint["protocol_category"] == "Other"
    assert hint["protocol_type"] == "Apple HomeKit accessory"
    assert hint["protocol_confidence"] == "medium"


@pytest.mark.parametrize(
    ("frame_type", "category", "device_type", "confidence"),
    [
        (0x03, "Other", "Apple AirPrint broadcaster", "medium"),
        (0x05, "Other", "Apple AirDrop broadcaster", "medium"),
        (0x09, "Audio", "Apple AirPlay device", "medium"),
        (0x0B, "Wearable", "Apple Watch Magic Switch", "high"),
        (0x0D, "Network", "Apple tethering target", "medium"),
        (0x10, "Other", "Apple Nearby Info device", "medium"),
    ],
)
def test_reelyactive_apple_continuity_frames(
    frame_type, category, device_type, confidence,
):
    hint = protocol_type_hint({0x004C: bytes((frame_type, 1))}, {})

    assert hint["protocol_category"] == category
    assert hint["protocol_type"] == device_type
    assert hint["protocol_confidence"] == confidence


def test_strongest_known_service_signature_wins():
    hint = protocol_type_hint({}, {"fd6f": b"", "fcd2": b""})

    assert hint["protocol_type"] == "BTHome sensor"
    assert hint["protocol_confidence"] == "high"


@pytest.mark.parametrize(
    ("company_id", "payload", "device_type"),
    [
        (0x0077, b"\x01\x00" + b"\x00" * 22, "Laird Connectivity sensor"),
        (0x026C, b"\x02" + b"\x00" * 23, "Efento environmental sensor"),
        (0x03DA, b"\x00" * 9, "EnOcean BLE sensor protocol"),
        (0x0500, b"\x00" * 27, "Wiliot IoT Pixel"),
        (0x0583, b"\x01", "Code Blue DirAct proximity device"),
        (0x0639, b"\x51\x01" + b"\x00" * 5, "Minew MSE01 sensor"),
        (0x0639, b"\xa3\x03" + b"\x00" * 14, "Minew S3 environmental sensor"),
        (0x0757, b"\x32\x00\x00", "ELA magnetic contact sensor"),
        (0x075B, b"\x05" + b"\x00" * 23, "HibouAir air-quality sensor"),
        (0x0A62, b"\x02\x10" + b"\x00" * 16, "MOKO proximity sensor"),
        (
            0x0059,
            b"\x07\x6c" + b"\x00" * 9 + b"\x01" + b"\x00" * 3,
            "MOKOSmart time-of-flight sensor",
        ),
        (0x0590, b'{"temp":21}', "Espruino telemetry device"),
    ],
)
def test_permissively_licensed_manufacturer_signatures_are_exact(
    company_id, payload, device_type,
):
    hint = protocol_type_hint({company_id: payload}, {})

    assert hint["protocol_type"] == device_type
    assert "reelyActive" in hint["protocol_source"]


def test_manufacturer_signature_rejects_wrong_frame_length():
    assert protocol_type_hint({0x0639: b"\xa3\x03" + b"\x00" * 13}, {}) == {}


def test_airhound_find_my_signature_stays_bounded():
    hint = protocol_type_hint({0x004C: b"\x12\x19" + b"\x00" * 23}, {})

    assert hint["protocol_category"] == "Tracker"
    assert hint["protocol_type"] == "Apple Find My-compatible tracker"
    assert hint["protocol_confidence"] == "medium"


def test_airhound_flock_rule_requires_name_and_company():
    hint = protocol_type_hint(
        {0x09C8: b"\x00"}, {}, name="Flock Camera",
    )

    assert hint["protocol_type"] == "Flock Safety camera/accessory"
    assert hint["protocol_confidence"] == "high"
    assert protocol_type_hint({0x09C8: b"\x00"}, {}, name="Other") == {}


def test_le_hci_peer_address_type_random_static():
    assert le_hci_peer_address_type(
        "random-static",
        "C0:5A:82:D9:F0:96",
    ) == 0x01


def test_le_hci_peer_address_type_public():
    assert le_hci_peer_address_type("public", "00:12:6F:FF:2A:F2") == 0x00


def test_is_bluetooth_bd_addr_rejects_corebluetooth_uuid():
    uuid = "6804E0C3-0714-E78A-A9E1-96898F237D05"
    assert not is_bluetooth_bd_addr(uuid)
    with pytest.raises(ValueError, match="not a Bluetooth address"):
        hci_bd_addr_bytes(uuid)


def test_hci_bd_addr_bytes_endianness():
    assert hci_bd_addr_bytes("00:12:6F:FF:2A:F2") == bytes.fromhex("f22aff6f1200")


def test_device_lacks_usb_hci_bd_addr_for_corebluetooth_uuid():
    uuid = "6804E0C3-0714-E78A-A9E1-96898F237D05"
    assert device_lacks_usb_hci_bd_addr(uuid, ())
    assert not device_lacks_usb_hci_bd_addr(
        uuid,
        ("AA:BB:CC:DD:EE:FF",),
    )


def test_discovery_names_match_desktop_hostname():
    assert discovery_names_match("DESKTOP-JOI2SAP", "Desktop-JOI2SAP")


def test_ble_advertisement_matches_by_device_name():
    assert ble_advertisement_matches_target(
        "AA:BB:CC:DD:EE:FF",
        "TVVictor",
        "6804E0C3-0714-E78A-A9E1-96898F237D05",
        target_name="TVVictor",
    )
