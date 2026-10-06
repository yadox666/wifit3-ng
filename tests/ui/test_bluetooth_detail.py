import time

import pytest
from textual.widgets import Static

from wifit3.bluetooth.manager import BluetoothManager
from wifit3.models import BluetoothDevice
from wifit3.ui.app import WifiteApp
from wifit3.ui.bluetooth_detail import (
    advertised_services_tooltip,
    bluetooth_manufacturer_label,
    device_detail_lines,
)


def _rich_device() -> BluetoothDevice:
    now = time.time()
    return BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Apple Watch",
        rssi=-55,
        service_uuids=("0000180f-0000-1000-8000-00805f9b34fb",),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=8,
        service_data_bytes=0,
        tx_power=-8,
        advertisement_count=12,
        advertisement_interval=0.25,
        first_seen=now - 5,
        last_seen=now,
        model_number="Watch7,15",
        firmware_revision="11.0",
        software_revision="11.0.1",
        serial_number="ABC123",
    )


def test_device_detail_lines_cover_scan_log_information():
    lines = device_detail_lines(_rich_device())
    text = "\n".join(lines)

    # Identity and radio
    assert "Apple Watch" in text
    assert "AA:BB:CC:DD:EE:FF" in text
    assert "Radio:" in text and "Discovery:" in text
    assert "Manufacturer:" in text
    # GATT identity block
    assert "GATT identity" in text
    assert "Watch7,15" in text
    assert "11.0.1" in text
    assert "ABC123" in text
    # Observation + privacy
    assert "Signal:" in text
    assert "Address type:" in text and "MAC kind:" in text
    assert "Advertised services:" in text


def test_device_detail_lines_handles_bare_classic_row():
    now = time.time()
    classic = BluetoothDevice(
        identifier="11:22:33:44:55:66",
        name="Vieta Pro",
        rssi=-60,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        radio_types=("BT",),
        class_of_device=0x240404,
    )
    lines = device_detail_lines(classic)
    text = "\n".join(lines)

    assert "Vieta Pro" in text
    assert "Classic class of device: [bold]0x240404[/bold]" in text
    # Classic-only rows get the no-GATT-endpoint hint.
    assert "no BLE GATT endpoint" in text


def test_device_detail_lines_are_deterministic():
    # The scanner log and the USB lab panel render identical content.
    assert device_detail_lines(_rich_device()) == device_detail_lines(_rich_device())


def test_service_tooltip_and_detail_show_every_translated_service():
    device = _rich_device()
    device.service_uuids = ("110a", "110c", "111f", "1200", "1801")

    tooltip = advertised_services_tooltip(device)
    detail = "\n".join(device_detail_lines(device))
    for translation in (
        "A2DP Audio Source (110a)",
        "A/V Remote Control Target (110c)",
        "Hands-Free Audio Gateway (111f)",
        "PnP Information (1200)",
        "Generic Attribute (1801)",
    ):
        assert translation in tooltip
        assert translation in detail


def test_member_service_owner_fills_missing_manufacturer_and_is_hidden_from_services():
    device = _rich_device()
    device.identifier = "11111111-1111-1111-1111-111111111111"
    device.manufacturer_ids = ()
    device.service_uuids = ("fe03", "180f")

    assert bluetooth_manufacturer_label(device) == "Amazon.com Services, Inc."
    tooltip = advertised_services_tooltip(device)
    detail = "\n".join(device_detail_lines(device))
    assert "Manufacturer: [bold]Amazon.com Services, Inc.[/bold]" in detail
    assert "Battery Service (180f)" in tooltip
    assert "fe03" not in tooltip
    assert "Amazon.com Services" not in tooltip
    assert "fe03" not in detail


def test_member_owner_replaces_unknown_company_id_and_is_still_hidden():
    device = _rich_device()
    device.manufacturer_ids = (0x81DF,)
    device.service_uuids = ("fe03", "180f")

    assert bluetooth_manufacturer_label(device) == "Amazon.com Services, Inc."
    tooltip = advertised_services_tooltip(device)
    assert "Battery Service (180f)" in tooltip
    assert "Amazon" not in tooltip
    assert "fe03" not in tooltip


def test_member_owner_service_is_hidden_when_manufacturer_is_already_known():
    device = _rich_device()
    device.service_uuids = ("fe03", "180f")

    assert bluetooth_manufacturer_label(device) == "Apple, Inc."
    tooltip = advertised_services_tooltip(device)
    assert "Battery Service (180f)" in tooltip
    assert "Amazon" not in tooltip
    assert "fe03" not in tooltip


def test_tooltip_shortens_unknown_vendor_uuid():
    device = _rich_device()
    device.service_uuids = ("12345678-1234-5678-1234-56789abcdef0",)

    tooltip = advertised_services_tooltip(device)
    assert "Custom (12345678…)" in tooltip
    assert "12345678-1234-5678-1234-56789abcdef0" not in tooltip


