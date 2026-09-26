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
from wifit3.ui.screens.bluetooth_focus import BluetoothFocusView


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

        device = screen.query_one("#bt-device").region
        traffic = screen.query_one("#bt-traffic").region
        connection = screen.query_one("#bt-connection").region
        assert device.right == traffic.x
        assert traffic.right == connection.x
        assert connection.right == 120

