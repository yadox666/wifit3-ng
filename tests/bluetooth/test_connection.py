from types import SimpleNamespace

import pytest

from wifit3.bluetooth.connection import BluetoothConnection, BluetoothConnectionError
from wifit3.models import BluetoothDevice


def _device():
    return BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Sensor",
        rssi=-45,
        service_uuids=("180a", "180f"),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=4,
        service_data_bytes=0,
        tx_power=-8,
        advertisement_count=4,
        advertisement_interval=0.2,
        first_seen=1.0,
        last_seen=2.0,
    )


class _Client:
    def __init__(self, _device, disconnected_callback, **_kwargs):
        self.disconnected_callback = disconnected_callback
        self.connected = False
        self.notify = {}
        info = SimpleNamespace(
            handle=1,
            uuid="00002a29-0000-1000-8000-00805f9b34fb",
            properties=["read"],
        )
        battery = SimpleNamespace(
            handle=2,
            uuid="00002a19-0000-1000-8000-00805f9b34fb",
            properties=["read", "notify"],
        )
        self.services = [
            SimpleNamespace(
                uuid="0000180a-0000-1000-8000-00805f9b34fb",
                characteristics=[info],
            ),
            SimpleNamespace(
                uuid="0000180f-0000-1000-8000-00805f9b34fb",
                characteristics=[battery],
            ),
        ]

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def read_gatt_char(self, handle):
        return bytearray(b"Acme") if handle == 1 else bytearray([87])

    async def start_notify(self, handle, callback):
        self.notify[handle] = callback


@pytest.mark.asyncio
async def test_connection_discovers_reads_and_counts_notifications():
    connection = BluetoothConnection(_device(), object(), client_factory=_Client)

    inspection = await connection.connect()

    assert inspection.connected
    assert len(inspection.services) == 2
    assert inspection.services[0].name == "Device Information"
    assert inspection.services[0].characteristics[0].value == "Acme"
    assert inspection.services[1].characteristics[0].value == "87%"
    assert inspection.traffic.gatt_reads == 2
    assert inspection.traffic.read_bytes == 5

    connection._client.notify[2](None, bytearray([82]))
    assert inspection.services[1].characteristics[0].value == "82%"
    assert inspection.traffic.notifications == 1
    assert inspection.traffic.notification_bytes == 1

    await connection.disconnect()
    assert not inspection.connected


@pytest.mark.asyncio
async def test_explicit_read_rejects_non_readable_characteristic():
    class NotifyOnlyClient(_Client):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.services[0].characteristics[0].properties = ["notify"]

    connection = BluetoothConnection(_device(), object(), client_factory=NotifyOnlyClient)
    await connection.connect()

    with pytest.raises(BluetoothConnectionError, match="not readable"):
        await connection.read_characteristic(1)


@pytest.mark.asyncio
async def test_explicit_read_updates_value_and_traffic():
    connection = BluetoothConnection(_device(), object(), client_factory=_Client)
    inspection = await connection.connect()
    before_reads = inspection.traffic.gatt_reads

    characteristic = await connection.read_characteristic(1)

    assert characteristic.value == "Acme"
    assert inspection.traffic.gatt_reads == before_reads + 1


@pytest.mark.asyncio
async def test_connection_infers_custom_service_from_characteristics():
    class AppleClient(_Client):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            notification_source = SimpleNamespace(
                handle=3,
                uuid="9fbf120d-6301-42d9-8c58-25e699a21dbd",
                properties=["notify"],
            )
            self.services.append(
                SimpleNamespace(
                    uuid="12345678-1234-5678-1234-56789abcdef0",
                    characteristics=[notification_source],
                )
            )

    connection = BluetoothConnection(_device(), object(), client_factory=AppleClient)

    inspection = await connection.connect()

    assert inspection.services[2].name == "Apple Notification Center Service (inferred)"
    await connection.disconnect()


@pytest.mark.asyncio
async def test_connection_wraps_connect_failure():
    class FailingClient(_Client):
        async def connect(self):
            raise TimeoutError("device did not respond")

    connection = BluetoothConnection(_device(), object(), client_factory=FailingClient)

    with pytest.raises(BluetoothConnectionError, match="device did not respond"):
        await connection.connect()

    assert not connection.inspection.connected
    assert connection.inspection.traffic.errors == 1

