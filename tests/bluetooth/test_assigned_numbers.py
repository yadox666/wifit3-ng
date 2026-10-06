from wifit3.bluetooth.assigned_numbers import (
    assigned_uuid_name,
    characteristic_property_detail,
    characteristic_name,
    descriptor_name,
    manufacturer_label,
    resolved_service_name,
    service_label,
    service_name,
    service_uuid_owner,
    uuid_metadata_source,
)


def test_manufacturer_label_prefers_company_identifier():
    assert manufacturer_label((0x004C,), "AA:BB:CC:DD:EE:FF") == "Apple, Inc. (004C)"


def test_manufacturer_label_falls_back_to_public_address_oui():
    assert manufacturer_label((), "28:6F:B9:00:00:00") == "Nokia Shanghai Bell Co., Ltd."


def test_service_label_resolves_classic_sdp_service_classes():
    assert service_name("110a") == "A2DP Audio Source"
    assert service_label("110c") == "A/V Remote Control Target (110c)"
    assert service_name("111f") == "Hands-Free Audio Gateway"
    assert service_label("1200") == "PnP Information (1200)"


def test_complete_sig_database_resolves_all_gatt_assignment_kinds():
    assert service_name("1800") == "Generic Access"
    assert characteristic_name("2a00") == "Device Name"
    assert descriptor_name("2902") == "Client Characteristic Configuration"
    assert assigned_uuid_name("2800") == "Primary Service"
    assert assigned_uuid_name("2701") == "length (metre)"
    assert assigned_uuid_name("0003") == "RFCOMM"
    assert assigned_uuid_name("1600") == "Ambient Light Sensor NLC Profile 1.0"
    assert assigned_uuid_name("0709") is None


def test_service_label_resolves_standard_and_vendor_uuids():
    assert service_label("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service (180f)"
    assert service_label("6e400001-b5a3-f393-e0a9-e50e24dcca9e") == (
        "Nordic UART Service (6e400001-b5a3-f393-e0a9-e50e24dcca9e)"
    )
    assert service_label("00001523-1212-efde-1523-785feabcd123") == (
        "Nordic LED and Button Service (00001523-1212-efde-1523-785feabcd123)"
    )
    assert characteristic_name("00001524-1212-efde-1523-785feabcd123") == (
        "Blinky Button State"
    )
    assert uuid_metadata_source(
        "00001523-1212-efde-1523-785feabcd123",
        kind="service",
    ) == "Nordic Bluetooth Numbers Database (nordic)"


def test_service_label_keeps_unknown_uuid():
    uuid = "12345678-1234-5678-1234-56789abcdef0"
    assert service_label(uuid) == uuid
    assert service_name(uuid) == "Custom (12345678…)"


def test_current_assigned_number_updates_override_dependency_database():
    assert service_name("1860") == "Tire Pressure Monitoring System"
    assert service_name("183d") == "Authorization Control"
    assert service_name("1827") == "Mesh Provisioning Service"
    assert service_name("fcb2") == "Location Enabled Advertisement Service"
    assert characteristic_name("2c3b") == "Tire Pressure"


def test_member_uuid_resolves_to_registered_owner():
    assert service_name("0000fe03-0000-1000-8000-00805f9b34fb") == (
        "Amazon.com Services, Inc. (fe03)"
    )
    assert service_label("fe03") == "Amazon.com Services, Inc. (fe03)"
    assert service_uuid_owner("fe03") == "Amazon.com Services, Inc."
    assert service_uuid_owner("180f") is None
    assert service_uuid_owner("fcb2") is None


def test_exact_service_name_takes_priority_over_member_owner():
    assert service_name("fe2c") == "Fast Pair Service"


def test_unassigned_short_uuid_stays_custom():
    assert service_name("00000709-0000-1000-8000-00805f9b34fb") == "Custom (0709)"


def test_custom_service_name_is_inferred_from_apple_characteristics():
    custom_uuid = "12345678-1234-5678-1234-56789abcdef0"

    assert resolved_service_name(
        custom_uuid,
        ["9FBF120D-6301-42D9-8C58-25E699A21DBD"],
    ) == "Apple Notification Center Service (inferred)"
    assert resolved_service_name(
        custom_uuid,
        ["2F7CABCE-808D-411F-9A0C-BB92BA96C102"],
    ) == "Apple Media Service (inferred)"


def test_custom_service_name_is_inferred_from_fast_pair_characteristics():
    custom_uuid = "12345678-1234-5678-1234-56789abcdef0"

    assert resolved_service_name(
        custom_uuid,
        ["FE2C1236-8366-4814-8EB0-01DE32100BEA"],
    ) == "Fast Pair Service (inferred)"


def test_unknown_service_without_recognized_characteristics_stays_custom():
    uuid = "12345678-1234-5678-1234-56789abcdef0"
    assert resolved_service_name(uuid, ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]) == (
        "Custom (12345678…)"
    )


def test_descriptor_properties_and_metadata_provenance_are_resolved():
    assert descriptor_name("2902") == "Client Characteristic Configuration"
    assert "ATT Read Request" in characteristic_property_detail("read")
    assert uuid_metadata_source("2a19", kind="characteristic") == (
        "Bluetooth SIG Assigned Numbers"
    )
    assert "Vendor-specific" in uuid_metadata_source(
        "12345678-1234-5678-1234-56789abcdef0",
        kind="characteristic",
    )

