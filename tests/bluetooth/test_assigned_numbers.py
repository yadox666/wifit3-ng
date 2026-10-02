from wifit3.bluetooth.assigned_numbers import (
    characteristic_property_detail,
    characteristic_name,
    descriptor_name,
    manufacturer_label,
    resolved_service_name,
    service_label,
    service_name,
    uuid_metadata_source,
)


def test_manufacturer_label_prefers_company_identifier():
    assert manufacturer_label((0x004C,), "AA:BB:CC:DD:EE:FF") == "Apple, Inc. (004C)"


def test_manufacturer_label_falls_back_to_public_address_oui():
    assert manufacturer_label((), "28:6F:B9:00:00:00") == "Nokia Shanghai Bell Co., Ltd."


def test_service_label_resolves_standard_and_vendor_uuids():
    assert service_label("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service (180f)"
    assert service_label("6e400001-b5a3-f393-e0a9-e50e24dcca9e") == (
        "Nordic UART Service (6e400001-b5a3-f393-e0a9-e50e24dcca9e)"
    )


def test_service_label_keeps_unknown_uuid():
    uuid = "12345678-1234-5678-1234-56789abcdef0"
    assert service_label(uuid) == uuid
    assert service_name(uuid) == "Custom (12345678…)"


def test_current_assigned_number_updates_override_dependency_database():
    assert service_name("1860") == "Tire Pressure Monitoring System Service"
    assert service_name("1855") == "Telephony and Media Audio"
    assert characteristic_name("2c3b") == "Tire Pressure"


def test_member_uuid_resolves_to_registered_owner():
    assert service_name("0000fe03-0000-1000-8000-00805f9b34fb") == (
        "Amazon.com Services, Inc. (fe03)"
    )
    assert service_label("fe03") == "Amazon.com Services, Inc. (fe03)"


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

