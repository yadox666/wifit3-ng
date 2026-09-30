import asyncio
import inspect
from types import SimpleNamespace

import pytest

from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.bluetooth.manager import BluetoothManager, BluetoothScanError
from wifit3.bluetooth.usb_hci import UsbBluetoothController
from wifit3.persist.bluetooth_history import BluetoothHistoryStore


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
    assert manager.observations_by_radio["BLE"] == 2
    assert manager.last_observation_by_radio["BLE"] is not None

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


def test_manager_enriches_a_live_device_from_bluetooth_history(tmp_path):
    path = tmp_path / "bluetooth.sqlite3"
    history = BluetoothHistoryStore(path)
    first = BluetoothManager(history=history)
    platform_device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None)
    first._on_advertisement(platform_device, SimpleNamespace(
        local_name="Remembered name",
        rssi=-45,
        service_uuids=["180f"],
        service_data={},
        manufacturer_data={0x004C: b"data"},
        tx_power=-8,
    ))
    history.close()

    reopened = BluetoothHistoryStore(path)
    second = BluetoothManager(history=reopened)
    second._on_advertisement(platform_device, SimpleNamespace(
        local_name=None,
        rssi=-55,
        service_uuids=[],
        service_data={},
        manufacturer_data={},
        tx_power=None,
    ))

    observed = second.devices()[0]
    assert observed.name == "Remembered name"
    assert observed.service_uuids == ("180f",)
    assert observed.manufacturer_ids == (0x004C,)


def test_manager_collects_bluez_class_appearance_and_address_type():
    manager = BluetoothManager()
    identifier = "40:22:33:44:55:66"
    manager._on_advertisement(
        SimpleNamespace(address=identifier, name=None),
        SimpleNamespace(
            local_name="Headphones",
            rssi=-50,
            service_uuids=[],
            service_data={},
            manufacturer_data={0x004C: b"\x07\x19\x01\x0e\x20"},
            tx_power=None,
            platform_data=(
                "/org/bluez/hci0/dev_40_22_33_44_55_66",
                {
                    "Appearance": 0x0943,
                    "Class": 0x240418,
                    "AddressType": "random",
                },
            ),
        ),
    )

    observed = manager.devices()[0]
    assert observed.appearance == 0x0943
    assert observed.class_of_device == 0x240418
    assert observed.address_type == "resolvable-private"
    assert observed.protocol_type == "Apple Proximity Pairing audio"


def test_manager_keeps_private_devices_live_without_persisting_them(tmp_path):
    history = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    location_store = SimpleNamespace(
        observe=lambda *_args, **_kwargs: pytest.fail(
            "private identifiers must not create location history",
        ),
    )
    manager = BluetoothManager(
        history=history,
        location_store=location_store,
        fix_provider=lambda: None,
    )
    advertisement = SimpleNamespace(
        local_name="Headphones",
        rssi=-50,
        service_uuids=["180f"],
        service_data={},
        manufacturer_data={0x004C: b"data"},
        tx_power=None,
        platform_data=(
            "/org/bluez/hci0/dev_40_22_33_44_55_66",
            {"AddressType": "random"},
        ),
    )

    manager._on_advertisement(
        SimpleNamespace(address="40:22:33:44:55:66", name=None),
        advertisement,
    )

    assert [device.identifier for device in manager.devices()] == [
        "40:22:33:44:55:66",
    ]
    assert history.count() == 0


def test_manager_collects_bluez_modalias_hardware_identity(monkeypatch):
    monkeypatch.setattr(
        "wifit3.bluetooth.analytics.resolve_bluez_modalias",
        lambda modalias: {
            "modalias": modalias,
            "hardware_vendor": "Acme Audio",
            "hardware_product": "Studio Headphones",
            "hardware_source": "BlueZ Device ID / systemd hwdb",
        },
    )
    manager = BluetoothManager()
    manager._on_advertisement(
        SimpleNamespace(address="00:11:22:33:44:55", name=None),
        SimpleNamespace(
            local_name="Studio",
            rssi=-50,
            service_uuids=[],
            service_data={},
            manufacturer_data={},
            tx_power=None,
            platform_data=(
                "/org/bluez/hci0/dev_00_11_22_33_44_55",
                {
                    "AddressType": "public",
                    "Modalias": "bluetooth:v1234p5678d0001",
                },
            ),
        ),
    )

    observed = manager.devices()[0]
    assert observed.modalias == "bluetooth:v1234p5678d0001"
    assert observed.hardware_vendor == "Acme Audio"
    assert observed.hardware_product == "Studio Headphones"
    assert observed.hardware_source == "BlueZ Device ID / systemd hwdb"


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
    first = "11111111-1111-1111-1111-111111111111"
    second = "22222222-2222-2222-2222-222222222222"
    scanner.callback(SimpleNamespace(address=first, name=None), advertisement)
    scanner.callback(SimpleNamespace(address=second, name=None), advertisement)

    devices = {device.identifier: device for device in manager.devices()}
    assert len(devices) == 2
    assert devices[first].similar_identifier_count == 2
    assert devices[second].similar_identifier_count == 2


@pytest.mark.asyncio
async def test_manager_tracks_rolling_signal_summary_and_trend():
    scanner = None

    def factory(**kwargs):
        nonlocal scanner
        scanner = _Scanner(**kwargs)
        return scanner

    manager = BluetoothManager(scanner_factory=factory)
    await manager.start()
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None)
    advertisement = SimpleNamespace(
        local_name="Tracker",
        rssi=-80,
        service_uuids=[],
        service_data={},
        manufacturer_data={},
        tx_power=None,
    )
    for rssi in (-80, -78, -68, -66):
        advertisement.rssi = rssi
        scanner.callback(device, advertisement)

    observed = manager.devices()[0]
    assert observed.rssi_average == -73.0
    assert observed.rssi_min == -80
    assert observed.rssi_max == -66
    assert observed.rssi_samples == 4
    assert observed.rssi_trend == "approaching"


@pytest.mark.asyncio
async def test_manager_wraps_backend_start_failure():
    scanner = _Scanner(lambda *_: None, start_error=PermissionError("Bluetooth denied"))
    manager = BluetoothManager(scanner_factory=lambda **_kwargs: scanner)

    with pytest.raises(BluetoothScanError, match="Bluetooth denied"):
        await manager.start()

    assert scanner.stopped
    assert not manager.is_scanning


@pytest.mark.asyncio
async def test_os_ble_probe_reports_ready_and_releases_probe_scanner():
    scanner = _Scanner(lambda *_: None)

    def factory(**kwargs):
        assert len(inspect.signature(kwargs["detection_callback"]).parameters) == 2
        return scanner

    manager = BluetoothManager(scanner_factory=factory)

    status = await manager.probe_os_ble()

    assert status.available is True
    assert status.state == "OS-READY"
    assert scanner.started is True
    assert scanner.stopped is True
    assert not manager.is_scanning


@pytest.mark.asyncio
async def test_os_ble_probe_reports_os_disabled_instead_of_raising():
    scanner = _Scanner(lambda *_: None, start_error=PermissionError("Bluetooth is off"))
    manager = BluetoothManager(scanner_factory=lambda **_kwargs: scanner)

    status = await manager.probe_os_ble()

    assert status.available is False
    assert status.state == "OS-DISABLED"
    assert status.detail == "Bluetooth is off"


@pytest.mark.asyncio
async def test_user_can_disable_os_ble_without_changing_os_settings():
    manager = BluetoothManager(os_ble_enabled=False)

    assert manager.os_ble_status.state == "APP-DISABLED"
    with pytest.raises(BluetoothScanError, match="disabled on the startup screen"):
        await manager.start()


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
        page_scan_repetition_mode=1,
        clock_offset=0x1234,
    ))

    observed = manager.devices()[0]
    assert manager.is_usb_scanning
    assert manager.backend_name == "RTL8761BU"
    assert observed.radio_label == "BT"
    assert observed.discovery_source == "usb-hci"
    assert observed.class_of_device == 0x240404
    assert observed.page_scan_repetition_mode == 1
    assert observed.clock_offset == 0x1234
    assert not observed.is_connectable_with_bleak
    assert manager.observations_by_radio["BT"] == 1
    assert manager.last_observation_by_radio["BT"] is not None

    await manager.stop()
    assert scanner.stopped


@pytest.mark.asyncio
async def test_classic_only_usb_scanner_runs_with_system_ble():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 2,
        supports_classic=True, supports_le=False,
    )
    system_scanner = None
    usb_scanner = None

    def system_factory(**kwargs):
        nonlocal system_scanner
        system_scanner = _Scanner(**kwargs)
        return system_scanner

    class UsbScanner:
        def __init__(self, selected, callback):
            nonlocal usb_scanner
            usb_scanner = self
            self.controller = selected
            self.callback = callback
            self.started = False
            self.stopped = False

        async def start(self):
            self.started = True

        async def stop(self):
            self.stopped = True

    manager = BluetoothManager(
        scanner_factory=system_factory,
        usb_scanner_factory=UsbScanner,
    )
    await manager.start_usb(controller)

    first_system_scanner = system_scanner
    first_usb_scanner = usb_scanner
    assert first_system_scanner.started
    assert first_usb_scanner.started
    assert manager.backend_name == "BlueCore4-ROM + OS BLE"

    await manager.stop()
    assert first_system_scanner.stopped
    assert first_usb_scanner.stopped

    await manager.resume_scan()
    assert system_scanner is not first_system_scanner
    assert usb_scanner is not first_usb_scanner
    assert system_scanner.started
    assert usb_scanner.started
    await manager.stop()


def test_macos_reserves_classic_controller_during_discovery(monkeypatch):
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 2,
        supports_classic=True, supports_le=False,
    )
    present = [controller]
    scanners = []

    class ReservableScanner:
        def __init__(self, selected, callback):
            self.controller = selected
            self.callback = callback
            self.reserved = False
            self.released = False
            scanners.append(self)

        def reserve(self):
            self.reserved = True

        def release(self):
            self.released = True

    monkeypatch.setattr("wifit3.bluetooth.manager.sys.platform", "darwin")
    manager = BluetoothManager(
        usb_controller_finder=lambda: list(present),
        usb_scanner_factory=ReservableScanner,
    )

    assert manager.available_usb_controllers() == [controller]
    assert scanners[0].reserved
    manager.available_usb_controllers()
    assert len(scanners) == 1

    present.clear()
    manager.available_usb_controllers()
    assert scanners[0].released


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
    assert observed.discovery_source == "system+usb-hci"
    assert observed.is_connectable_with_bleak


def test_usb_then_ble_observations_keep_both_radios_and_sources():
    manager = BluetoothManager()
    manager._on_usb_observation(DiscoveryObservation(
        identifier="AA:BB:CC:DD:EE:FF",
        radio_type="BT",
        rssi=-48,
    ))
    manager._on_advertisement(
        SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None),
        SimpleNamespace(
            local_name="Headset",
            rssi=-45,
            service_uuids=[],
            service_data={},
            manufacturer_data={},
            tx_power=None,
        ),
    )

    observed = manager.devices()[0]
    assert observed.radio_label == "BT+BLE"
    assert observed.discovery_source == "system+usb-hci"
    assert observed.is_connectable_with_bleak


def test_separate_classic_and_ble_addresses_are_probabilistically_linked():
    manager = BluetoothManager()
    manager._on_usb_observation(DiscoveryObservation(
        identifier="AA:BB:CC:DD:EE:FF",
        radio_type="BT",
        rssi=-48,
        name="Living Room Speaker",
        service_uuids=("110b",),
    ))
    manager._on_advertisement(
        SimpleNamespace(address="11:22:33:44:55:66", name=None),
        SimpleNamespace(
            local_name="Living Room Speaker",
            rssi=-45,
            service_uuids=["110b"],
            service_data={},
            manufacturer_data={},
            tx_power=None,
        ),
    )

    classic = next(
        device for device in manager.devices() if device.identifier.startswith("AA:")
    )
    ble = next(
        device for device in manager.devices() if device.identifier.startswith("11:")
    )
    assert classic.related_identifiers == (ble.identifier,)
    assert ble.related_identifiers == (classic.identifier,)
    assert classic.correlation_confidence == "high"
    assert "exact normalized name" in classic.correlation_evidence

