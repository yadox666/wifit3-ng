import struct

from wifit3.bluetooth.gatt_metadata import (
    decode_pnp_id,
    display_model_label,
    gatt_identity_fields,
    gatt_identity_parts,
    merge_gatt_identity_fields,
)
from wifit3.bluetooth.apple_identifiers import format_device_model_number
from wifit3.models import BluetoothCharacteristic, BluetoothDevice, BluetoothService


def test_decode_pnp_id_bluetooth_sig_company():
    raw = struct.pack("<BHHH", 0x01, 0x0075, 0xABCD, 0x0100)
    decoded = decode_pnp_id(raw)
    assert "Samsung" in decoded or "0075" in decoded
    assert "0xabcd" in decoded.casefold()


def test_unknown_apple_pnp_product_populates_generic_model_without_guessing():
    raw = struct.pack("<BHHH", 0x01, 0x004C, 0x2018, 0x0100)
    decoded = decode_pnp_id(raw)
    assert "Apple" in decoded
    assert "product 0x2018" in decoded

    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="<Unknown>",
        rssi=-50,
        service_uuids=("180a",),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0,
        last_seen=1,
        pnp_id=decoded,
    )
    assert display_model_label(device) == "Apple Bluetooth device (PID 0x2018)"
    assert "product 0x2018" in display_model_label(device, include_identifier=True)


def test_gatt_identity_fields_collects_dis_gap_and_pnp():
    pnp = struct.pack("<BHHH", 0x01, 0x004C, 0x1234, 0x0001)
    service_dis = BluetoothService(
        uuid="0000180a-0000-1000-8000-00805f9b34fb",
        name="Device Information",
        characteristics=[
            BluetoothCharacteristic(
                handle=1,
                uuid="00002a24-0000-1000-8000-00805f9b34fb",
                name="Model Number String",
                properties=("read",),
                value="SM-G998B",
            ),
            BluetoothCharacteristic(
                handle=2,
                uuid="00002a29-0000-1000-8000-00805f9b34fb",
                name="Manufacturer Name String",
                properties=("read",),
                value="samsung",
            ),
            BluetoothCharacteristic(
                handle=3,
                uuid="00002a50-0000-1000-8000-00805f9b34fb",
                name="PnP ID",
                properties=("read",),
                value_hex=pnp.hex(" "),
            ),
        ],
    )
    service_gap = BluetoothService(
        uuid="00001800-0000-1000-8000-00805f9b34fb",
        name="Generic Access",
        characteristics=[
            BluetoothCharacteristic(
                handle=4,
                uuid="00002a00-0000-1000-8000-00805f9b34fb",
                name="Device Name",
                properties=("read",),
                value="Galaxy S21",
            ),
        ],
    )
    inspection = type("Inspection", (), {"services": [service_dis, service_gap]})()

    fields = gatt_identity_fields(inspection)
    assert fields["model_number"] == "SM-G998B"
    assert fields["manufacturer_name"] == "samsung"
    assert fields["gatt_device_name"] == "Galaxy S21"
    assert "pnp_id" in fields


def test_merge_gatt_identity_fields_fills_empty_device_fields():
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="adv",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=1.0,
    )
    merged = merge_gatt_identity_fields(
        device,
        {"model_number": "iPhone13,4", "manufacturer_name": "Apple Inc."},
    )
    assert merged.model_number == "iPhone13,4"
    assert merged.manufacturer_name == "Apple Inc."


def test_gatt_identity_parts_brand_model_submodel():
    parts = gatt_identity_parts({
        "manufacturer_name": "Apple Inc.",
        "model_number": "iPhone13,4",
    })
    assert parts.brand == "Apple Inc."
    assert parts.model == "iPhone 12 Pro Max"
    assert parts.submodel == "iPhone13,4"


def test_display_model_label_prefers_model_then_gatt_name():
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="adv",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=1.0,
        gatt_device_name="Galaxy Tab",
    )
    assert display_model_label(device) == "Galaxy Tab"


def test_display_model_label_omits_internal_identifier_by_default():
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="iPhone",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=1.0,
        model_number="iPhone13,4",
    )
    assert display_model_label(device) == "iPhone 12 Pro Max"
    assert display_model_label(device, include_identifier=True) == (
        format_device_model_number("iPhone13,4", detail=True)
    )
