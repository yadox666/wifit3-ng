import asyncio
from types import SimpleNamespace

import pytest

from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.bluetooth.manager import BluetoothManager, BluetoothScanError
from wifit3.bluetooth.usb_hci import UsbBluetoothController


class _Scanner:
    def __init__(self, detection_callback, *, start_error=None):
        self.callback = detection_callback
        self.start_error = start_error
        self.started = False
        self.stopped = False

    async def start(self):
        if self.start_error is not None:
            raise self.start_error
        self.started = True

    async def stop(self):
        self.stopped = True


@pytest.mark.asyncio
async def test_manager_collects_and_updates_advertisements():
    scanner = None

    def factory(**kwargs):
        nonlocal scanner
        scanner = _Scanner(**kwargs)
        return scanner

    manager = BluetoothManager(scanner_factory=factory)
    await manager.start()
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="fallback")
    advertisement = SimpleNamespace(
        local_name="Beacon",
        rssi=-47,
        service_uuids=["180f"],
        service_data={"180f": b"\x64"},
        manufacturer_data={0x004C: b"data"},
        tx_power=-8,
    )
    scanner.callback(device, advertisement)

    discovered = manager.devices()
    assert len(discovered) == 1
    assert discovered[0].name == "Beacon"
    assert discovered[0].rssi == -47
    assert discovered[0].manufacturer_ids == (0x004C,)
    assert discovered[0].manufacturer_data_bytes == 4
    assert discovered[0].service_data_bytes == 1
    assert discovered[0].advertisement_count == 1

    advertisement.local_name = None
    advertisement.rssi = -52
    advertisement.service_uuids = ["180a"]
    scanner.callback(device, advertisement)
    updated = manager.devices()[0]
    assert updated.name == "Beacon"
    assert updated.rssi == -52
    assert updated.service_uuids == ("180a", "180f")
    assert updated.advertisement_count == 2
    assert updated.advertisement_interval is not None
    assert updated.first_seen <= updated.last_seen

    await manager.stop()
    assert scanner.stopped
    assert not manager.is_scanning


@pytest.mark.asyncio
async def test_restarting_scan_keeps_previously_seen_devices():
    scanners = []

    def factory(**kwargs):
        scanner = _Scanner(**kwargs)
        scanners.append(scanner)
        return scanner

    manager = BluetoothManager(scanner_factory=factory)
    await manager.start()
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="fallback")
    advertisement = SimpleNamespace(
        local_name="Beacon",
        rssi=-47,
        service_uuids=[],
        service_data={},
        manufacturer_data={},
        tx_power=None,
    )
    scanners[0].callback(device, advertisement)
    await manager.stop()

    await manager.start()

    assert [d.identifier for d in manager.devices()] == ["AA:BB:CC:DD:EE:FF"]


@pytest.mark.asyncio
async def test_manager_counts_similar_private_identifiers_without_merging_them():
    scanner = None

    def factory(**kwargs):
        nonlocal scanner
        scanner = _Scanner(**kwargs)
        return scanner

    manager = BluetoothManager(scanner_factory=factory)
    await manager.start()
    advertisement = SimpleNamespace(
        local_name="Headphones",
        rssi=-47,
        service_uuids=["184e"],
        service_data={},
        manufacturer_data={0x004C: b"data"},
        tx_power=None,
    )
    scanner.callback(SimpleNamespace(address="AA:00:00:00:00:01", name=None), advertisement)
    scanner.callback(SimpleNamespace(address="AE:00:00:00:00:02", name=None), advertisement)

    devices = {device.identifier: device for device in manager.devices()}
    assert len(devices) == 2
    assert devices["AA:00:00:00:00:01"].similar_identifier_count == 2
    assert devices["AE:00:00:00:00:02"].similar_identifier_count == 2


@pytest.mark.asyncio
async def test_manager_wraps_backend_start_failure():
    scanner = _Scanner(lambda *_: None, start_error=PermissionError("Bluetooth denied"))
    manager = BluetoothManager(scanner_factory=lambda **_kwargs: scanner)

    with pytest.raises(BluetoothScanError, match="Bluetooth denied"):
        await manager.start()

    assert scanner.stopped
    assert not manager.is_scanning


@pytest.mark.asyncio
async def test_cancelled_connection_disconnects_partial_client():
    client = None

    class HangingClient:
        def __init__(self, *_args, **_kwargs):
            self.disconnected = False

        async def connect(self):
            await asyncio.Event().wait()

        async def disconnect(self):
            self.disconnected = True

    def client_factory(*args, **kwargs):
        nonlocal client
        client = HangingClient(*args, **kwargs)
        return client

    manager = BluetoothManager(client_factory=client_factory)
    device = SimpleNamespace(identifier="AA:BB:CC:DD:EE:FF")
    task = asyncio.create_task(manager.connect(device))
    await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert client.disconnected
    assert manager.connection is None


@pytest.mark.asyncio
async def test_usb_scanner_is_separate_and_marks_classic_observations():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = None

    class UsbScanner:
        def __init__(self, selected, callback):
            nonlocal scanner
            scanner = self
            self.controller = selected
            self.callback = callback
            self.started = False
            self.stopped = False

        async def start(self):
            self.started = True

        async def stop(self):
            self.stopped = True

    manager = BluetoothManager(usb_scanner_factory=UsbScanner)
    await manager.start_usb(controller)
    scanner.callback(DiscoveryObservation(
        identifier="AA:BB:CC:DD:EE:FF",
        radio_type="BT",
        rssi=-50,
        class_of_device=0x240404,
    ))

    observed = manager.devices()[0]
    assert manager.is_usb_scanning
    assert manager.backend_name == "RTL8761BU"
    assert observed.radio_label == "BT"
    assert observed.discovery_source == "usb-hci"
    assert observed.class_of_device == 0x240404
    assert not observed.is_connectable_with_bleak

    await manager.stop()
    assert scanner.stopped


def test_usb_and_ble_observations_merge_as_dual_mode():
    manager = BluetoothManager()
    platform_device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None)
    advertisement = SimpleNamespace(
        local_name="Headset",
        rssi=-45,
        service_uuids=[],
        service_data={},
        manufacturer_data={},
        tx_power=None,
    )
    manager._on_advertisement(platform_device, advertisement)
    manager._on_usb_observation(DiscoveryObservation(
        identifier="AA:BB:CC:DD:EE:FF",
        radio_type="BT",
        rssi=-48,
    ))

    observed = manager.devices()[0]
    assert observed.radio_label == "BT+BLE"
    assert observed.name == "Headset"

