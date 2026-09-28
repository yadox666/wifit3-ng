from types import SimpleNamespace

import pytest
from textual.widgets import DataTable

from wifit3.models import (
    BluetoothCharacteristic,
    BluetoothDevice,
    BluetoothInspection,
    BluetoothService,
)
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.bluetooth_focus import (
    BluetoothFocusView,
    gatt_ascii,
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
        assert table.row_count == 1
        row = table.get_row("1")
        assert row[0] == "Device Information"
        assert row[1] == "Manufacturer Name String"
        assert row[3].plain == "Acme"
        assert row[4].plain == "LOW"
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
        detail = screen.query_one("#gatt-detail")
        assert "ASCII" in str(detail.render())
        assert "EPA8XB89" in str(detail.render())
        assert "Hex" in str(detail.render())

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

