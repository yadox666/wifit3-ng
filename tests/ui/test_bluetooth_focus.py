from types import SimpleNamespace

import pytest
from textual.widgets import DataTable

from wifit3.models import (
    BluetoothCharacteristic,
    BluetoothDescriptor,
    BluetoothDevice,
    BluetoothInspection,
    BluetoothService,
)
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.bluetooth_focus import (
    BluetoothFocusView,
    _read_error_cell,
    gatt_ascii,
    gatt_payload_hex,
    gatt_payload_text,
    gatt_value_detail_markup,
    gatt_display_value,
)


def _inspection():
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Test Sensor",
        rssi=-41,
        service_uuids=("180a",),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=4,
        service_data_bytes=0,
        tx_power=-8,
        advertisement_count=10,
        advertisement_interval=0.2,
        first_seen=1,
        last_seen=2,
    )
    characteristic = BluetoothCharacteristic(
        handle=1,
        uuid="00002a29-0000-1000-8000-00805f9b34fb",
        name="Manufacturer Name String",
        properties=("read",),
        value="Acme",
        value_bytes=4,
    )
    return BluetoothInspection(
        device=device,
        connected=True,
        connected_at=1,
        services=[
            BluetoothService(
                uuid="0000180a-0000-1000-8000-00805f9b34fb",
                name="Device Information",
                characteristics=[characteristic],
            )
        ],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_renders_identity_traffic_and_gatt_table():
    app = WifiteApp()
    app.bluetooth_manager.connection = SimpleNamespace(inspection=_inspection())

    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen
        assert isinstance(screen, BluetoothFocusView)

        table = screen.query_one("#gatt-table", DataTable)
        assert table.row_count == 2
        row = table.get_row("1")
        assert row[0] == "Device Information"
        assert row[1] == "Manufacturer Name String"
        assert row[3].plain == "Acme"
        assert row[4].plain == "LOW"
        assert screen.query_one("#gatt-detail").border_title == "DEVICE / BLE"
        assert "L1" in str(screen.query_one("#bt-connection").render())

        local = screen.query_one("#bt-local").region
        center = screen.query_one("#bt-center").region
        device = screen.query_one("#bt-device").region
        traffic = screen.query_one("#bt-traffic").region
        connection = screen.query_one("#bt-connection").region
        assert local.right == center.x
        assert center.right == device.x
        assert local.x == 120 - device.right
        assert connection.x == traffic.x == center.x
        assert connection.bottom == traffic.y

        local_art = screen.query_one("#bt-local").render()
        device_art = screen.query_one("#bt-device").render()
        assert "THIS LAPTOP" in local_art.plain
        assert "Wifit3-ng" in local_art.plain
        assert "Test Sensor" in device_art.plain
        assert any("rgb(0,120,255)" in str(span.style) for span in device_art.spans)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_shows_property_meanings_and_live_descriptors():
    inspection = _inspection()
    characteristic = inspection.services[0].characteristics[0]
    characteristic.descriptors.append(BluetoothDescriptor(
        handle=7,
        uuid="00002904-0000-1000-8000-00805f9b34fb",
        name="Characteristic Presentation Format",
        value=(
            "uint16; exponent -1; unit 0x272f; "
            "namespace 0x01; description 0x0000"
        ),
        value_hex="06 ff 2f 27 01 00 00",
    ))
    characteristic.descriptors.append(BluetoothDescriptor(
        handle=8,
        uuid="00002902-0000-1000-8000-00805f9b34fb",
        name="Client Characteristic Configuration",
        read_error=(
            "BleakGATTProtocolError: Read Not Permitted "
            "(ATT 0x02, native code=2)"
        ),
    ))
    app = WifiteApp()
    app.bluetooth_manager.connection = SimpleNamespace(inspection=inspection)

    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen
        table = screen.query_one("#gatt-table", DataTable)

        assert table.row_count == 4
        assert table.get_row("descriptor:1:7")[1] == (
            "Characteristic Presentation Format"
        )
        assert table.get_row("descriptor:1:8")[3].plain == "READ DENIED"
        await pilot.press("down")
        characteristic_detail = str(screen.query_one("#gatt-detail").render())
        assert "Permits an ATT Read Request" in characteristic_detail
        assert "Bluetooth SIG Assigned Numbers" in characteristic_detail
        await pilot.press("down")
        descriptor_detail = str(screen.query_one("#gatt-detail").render())
        assert "unit 0x272f" in descriptor_detail
        assert "Live ATT/GATT descriptor discovery" in descriptor_detail
        await pilot.press("down")
        error_detail = str(screen.query_one("#gatt-detail").render())
        assert "BleakGATTProtocolError: Read Not Permitted" in error_detail


def test_read_errors_are_compact_in_table_cells():
    assert _read_error_cell("TimeoutError").plain == "TIMEOUT"
    assert _read_error_cell("Insufficient Authentication (ATT 0x05)").plain == (
        "AUTH REQUIRED"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_keeps_remote_art_visible_while_disconnected():
    app = WifiteApp()
    app.bluetooth_manager.connection = None

    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen

        device_art = screen.query_one("#bt-device").render()
        link = screen.query_one("#bt-connection").render()
        assert "BLUETOOTH DEVICE" in device_art.plain
        assert "Waiting for connection" in device_art.plain
        assert "██" in device_art.plain
        assert "DISCONNECTED" in str(link)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_opens_with_observation_data_after_gatt_timeout():
    app = WifiteApp()
    device = _inspection().device
    app.bluetooth_manager._devices[device.identifier] = device
    app.bluetooth_manager.select_focus(
        device.identifier,
        error="BLE GATT connection timed out",
    )

    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen

        assert "Test Sensor" in screen.query_one("#bt-device").render().plain
        assert "DISCONNECTED" in str(screen.query_one("#bt-connection").render())
        assert "BLE GATT connection timed out" in str(
            screen.query_one("#gatt-detail").render(),
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_renders_classic_identity_sdp_and_hci_in_same_design():
    app = WifiteApp()
    device = BluetoothDevice(
        identifier="38:8C:EF:CA:7F:FF",
        name="Classic Speaker",
        rssi=-64,
        service_uuids=("110b", "110e"),
        service_data_uuids=(),
        manufacturer_ids=(0x0075,),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=16,
        advertisement_interval=0.9,
        first_seen=1,
        last_seen=12,
        radio_types=("BT",),
        discovery_source="usb-hci",
        class_of_device=0x0C0404,
        page_scan_repetition_mode=1,
        clock_offset=0x1234,
        address_type="public",
    )
    app.bluetooth_manager._devices[device.identifier] = device
    app.bluetooth_manager.select_classic_focus(device.identifier)
    app.bluetooth_manager.connection = None

    async with app.run_test(size=(140, 45)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen

        assert "CLASSIC" in screen.query_one("#bt-local").render().plain
        assert "Classic Speaker" in screen.query_one("#bt-device").render().plain
        assert "CLASSIC / BR-EDR" in str(screen.query_one("#bt-connection").render())
        packet_flow = screen.query_one("#bt-traffic").render().plain
        assert "CLASSIC PACKET FLOW" in packet_flow
        assert "▁" in packet_flow
        assert screen.query_one("#bt-sdp").display
        table = screen.query_one("#gatt-table", DataTable)
        assert table.row_count == 4
        assert table.get_row("classic:trace")[1] == "PDU 0x06 → 0x07"
        assert table.get_row("classic:110b")[1] == "110b"
        detail = screen.query_one("#gatt-detail")
        assert detail.border_title == "DEVICE / CLASSIC"
        assert "Address & privacy" in str(detail.render())


def test_gatt_payload_hex_decodes_ascii_hex_strings():
    wire = "45 30 41 38 38 42 38 39"
    payload = "e0 a8 8b 89"
    assert gatt_payload_hex(wire) == payload
    assert gatt_payload_text(payload) == "...."
    assert "Payload (hex)" in gatt_value_detail_markup(wire, wire)
    assert payload in gatt_value_detail_markup(wire, wire)
    assert "ASCII (from payload)" in gatt_value_detail_markup(wire, wire)
    assert "...." in gatt_value_detail_markup(wire, wire)
    assert "Text (hex string)" not in gatt_value_detail_markup(wire, wire)
    assert "E0A88B89" not in gatt_value_detail_markup(wire, wire)
    hello_on_wire = " ".join(f"{b:02x}" for b in b"48454C4C4F")
    hello_payload = gatt_payload_hex(hello_on_wire)
    assert hello_payload == "48 45 4c 4c 4f"
    assert gatt_payload_text(hello_payload) == "HELLO"
    assert gatt_payload_hex("45 50 41 38") is None  # "EPA8" is not valid fromhex length/content


def test_gatt_ascii_converts_only_printable_hex_dumps():
    assert gatt_ascii("45 50 41 38") == "EPA8"
    assert gatt_ascii("45 50 00") == "EP"
    assert gatt_ascii("00 00 00 00") is None
    assert gatt_ascii("45 00 50") is None
    assert gatt_ascii("Acme") is None
    assert gatt_display_value("87%", "57", ascii_mode=True) == "87%"
    assert gatt_display_value("45 50", "45 50", ascii_mode=False) == "45 50"
    assert gatt_display_value("45 50", "45 50", ascii_mode=True) == "EP"


def _ascii_inspection():
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Orange TV",
        rssi=-68,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1,
        last_seen=2,
    )
    text = b"EPA8XB89"
    zeros = bytes(8)
    return BluetoothInspection(
        device=device,
        connected=True,
        connected_at=1,
        services=[
            BluetoothService(
                uuid="3c1d08cd-0000-0000-0000-000000000001",
                name="Custom",
                characteristics=[
                    BluetoothCharacteristic(
                        handle=1,
                        uuid="1a00137e-0000-0000-0000-000000000001",
                        name="Custom",
                        properties=("read",),
                        value=text.hex(" "),
                        value_hex=text.hex(" "),
                        value_bytes=len(text),
                    ),
                    BluetoothCharacteristic(
                        handle=2,
                        uuid="ac4f797f-0000-0000-0000-000000000002",
                        name="Custom",
                        properties=("read",),
                        value=zeros.hex(" "),
                        value_hex=zeros.hex(" "),
                        value_bytes=len(zeros),
                    ),
                    BluetoothCharacteristic(
                        handle=3,
                        uuid="00002a19-0000-1000-8000-00805f9b34fb",
                        name="Battery Level",
                        properties=("read",),
                        value="87%",
                        value_hex="57",
                        value_bytes=1,
                    ),
                ],
            )
        ],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_focus_toggles_ascii_for_printable_values():
    app = WifiteApp()
    app.bluetooth_manager.connection = SimpleNamespace(inspection=_ascii_inspection())

    async with app.run_test(size=(140, 40)) as pilot:
        app.push_screen("bluetooth-focus")
        await pilot.pause(0)
        screen = app.screen
        table = screen.query_one("#gatt-table", DataTable)
        assert table.get_row("1")[3].plain == "45 50 41 38 58 42 38 39"
        assert table.get_row("2")[3].plain == "00 00 00 00 00 00 00 00"
        assert table.get_row("3")[3].plain == "87%"
        table.move_cursor(row=1, animate=False)
        await pilot.pause(0)
        detail = screen.query_one("#gatt-detail")
        assert "ASCII" in str(detail.render())
        assert "EPA8XB89" in str(detail.render())
        assert "Raw bytes" in str(detail.render())

        await pilot.press("a")
        await pilot.pause(0)
        assert table.get_row("1")[3].plain == "EPA8XB89"
        assert table.get_row("2")[3].plain == "00 00 00 00 00 00 00 00"
        assert table.get_row("3")[3].plain == "87%"
        rendered = str(detail.render())
        assert "EPA8XB89" in rendered
        assert "45 50 41 38 58 42 38 39" in rendered
        assert detail.border_title == "CHARACTERISTIC"

        await pilot.press("a")
        await pilot.pause(0)
        assert table.get_row("1")[3].plain == "45 50 41 38 58 42 38 39"
        assert "EPA8XB89" in str(detail.render())
        assert "45 50 41 38 58 42 38 39" in str(detail.render())
        assert detail.border_title == "CHARACTERISTIC"

