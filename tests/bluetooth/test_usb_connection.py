from types import SimpleNamespace

import pytest

from wifit3.bluetooth import gatt_att as att
from wifit3.bluetooth.usb_connection import (
    UsbBluetoothConnection,
    UsbBluetoothConnectionError,
)
from wifit3.models import BluetoothCharacteristic, BluetoothDevice, BluetoothService


@pytest.mark.asyncio
async def test_usb_gatt_read_reports_full_att_error_response():
    characteristic = BluetoothCharacteristic(
        handle=0x002A,
        uuid="00002a00-0000-1000-8000-00805f9b34fb",
        name="Device Name",
        properties=("read",),
    )
    scanner = SimpleNamespace(
        gatt=SimpleNamespace(
            att_exchange=lambda _handle, _request: bytes((
                att.ATT_ERROR_RESPONSE,
                att.ATT_READ_REQUEST,
                0x2A,
                0x00,
                att.ATT_ERR_READ_NOT_PERMITTED,
            )),
        ),
    )
    connection = UsbBluetoothConnection(
        BluetoothDevice(
            identifier="AA:BB:CC:DD:EE:FF",
            name="Test device",
            rssi=-50,
            service_uuids=(),
            service_data_uuids=(),
            manufacturer_ids=(),
            manufacturer_data_bytes=0,
            service_data_bytes=0,
            tx_power=None,
            advertisement_count=1,
            advertisement_interval=None,
            first_seen=1,
            last_seen=1,
        ),
        scanner,
    )
    connection._le_handle = 0x0040
    connection.inspection.connected = True
    connection.inspection.services = [
        BluetoothService(
            uuid="00001800-0000-1000-8000-00805f9b34fb",
            name="Generic Access",
            characteristics=[characteristic],
        ),
    ]

    with pytest.raises(
        UsbBluetoothConnectionError,
        match=r"Read Not Permitted \(ATT 0x02\).*opcode 0x0a.*handle 0x002a",
    ):
        await connection.read_characteristic(characteristic.handle)

    assert "ATT 0x02" in characteristic.read_error
