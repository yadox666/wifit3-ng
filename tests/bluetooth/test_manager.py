import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.bluetooth.manager import (
    BluetoothManager,
    BluetoothScanError,
    _advertised_connectable,
    _ble_mac_privacy_pattern,
    _platform_ble_identity,
)
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


def test_corebluetooth_metadata_exposes_connectable_and_mac_when_available():
    peripheral = object()

    class _Central:
        def retrieveAddressForPeripheral_(self, candidate):
            assert candidate is peripheral
            return bytes.fromhex("AABBCCDDEEFF")

    platform_device = SimpleNamespace(
        address="356CF960-45E2-5E8F-DE3B-EDA564085A97",
        details=(peripheral, SimpleNamespace(central_manager=_Central())),
    )
    identity, mac = _platform_ble_identity(platform_device)

    assert mac == "AA:BB:CC:DD:EE:FF"
    assert "CoreBluetooth UUID=356CF960-45E2-5E8F-DE3B-EDA564085A97" in identity
    assert "MAC=AA:BB:CC:DD:EE:FF" in identity
    assert "reserved random-address bit pattern" in identity
    assert _advertised_connectable(
        (peripheral, {"kCBAdvDataIsConnectable": False}, -66),
    ) is False


def test_ble_mac_privacy_pattern_marks_rpa_as_private_rotating():
    assert _ble_mac_privacy_pattern(
        "66:E9:13:C3:FC:3C",
    ) == "RPA/private-rotating bit pattern"


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

    manager = BluetoothManager(usb_scanner_factory=UsbScanner, os_ble_enabled=False)
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
async def test_dual_mode_usb_pairs_os_ble_and_defers_usb_le_scan():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
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
            self._usb_le_scan_enabled = True

        def use_os_ble_for_le_discovery(self):
            self._usb_le_scan_enabled = False

        async def start(self):
            self.started = True

        async def stop(self):
            self.stopped = True

    manager = BluetoothManager(
        scanner_factory=system_factory,
        usb_scanner_factory=UsbScanner,
    )
    await manager.start_usb(controller)

    assert system_scanner.started
    assert usb_scanner.started
    assert usb_scanner._usb_le_scan_enabled is False
    assert manager.backend_name == "RTL8761BU + OS BLE"
    await manager.stop()


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


@pytest.mark.asyncio
async def test_classic_sdp_auto_starts_the_only_usb_controller_beside_os_ble():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    usb_scanner = None

    class UsbScanner:
        def __init__(self, selected, callback):
            nonlocal usb_scanner
            usb_scanner = self
            self.controller = selected
            self.callback = callback
            self.started = False
            self._device = object()

        @property
        def is_scanning(self):
            return self.started

        async def start(self):
            self.started = True

    manager = BluetoothManager(
        scanner_factory=lambda **kwargs: _Scanner(**kwargs),
        usb_scanner_factory=UsbScanner,
        usb_controller_finder=lambda: [controller],
    )
    await manager.start()

    await manager._ensure_usb_scanner_ready()

    assert manager._scanner is not None
    assert manager._usb_scanner is usb_scanner
    assert usb_scanner.started


@pytest.mark.asyncio
async def test_classic_sdp_missing_usb_controller_has_actionable_error():
    manager = BluetoothManager(
        usb_controller_finder=lambda: [],
        os_ble_enabled=False,
    )

    with pytest.raises(BluetoothScanError, match="Connect or select"):
        await manager._ensure_usb_scanner_ready()


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


def test_macos_reserves_dual_mode_controller_during_discovery(monkeypatch):
    """A dual-mode dongle must be held at plug-in. Waiting until scan time loses the race to macOS."""
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanners = []

    class ReservableScanner:
        def __init__(self, selected, callback):
            self.controller = selected
            self.callback = callback
            self.reserved = False
            scanners.append(self)

        def reserve(self):
            self.reserved = True

        def release(self):
            self.released = True

    monkeypatch.setattr("wifit3.bluetooth.manager.sys.platform", "darwin")
    manager = BluetoothManager(
        usb_controller_finder=lambda: [controller],
        usb_scanner_factory=ReservableScanner,
    )

    assert manager.available_usb_controllers() == [controller]
    assert scanners[0].reserved
    assert manager.usb_reservation_held(controller)
    manager.available_usb_controllers()
    assert len(scanners) == 1


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


@pytest.mark.asyncio
async def test_start_parallel_runs_os_ble_beside_an_le_usb_controller():
    """A dual-mode USB dongle used to skip OS BLE. Background mode runs both."""
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    system = None
    usb = None

    def system_factory(**kwargs):
        nonlocal system
        system = _Scanner(**kwargs)
        return system

    class UsbScanner:
        def __init__(self, selected, callback):
            nonlocal usb
            usb = self
            self.controller = selected
            self.callback = callback

        async def start(self):
            self.started = True

        async def stop(self):
            self.stopped = True

    manager = BluetoothManager(
        scanner_factory=system_factory,
        usb_scanner_factory=UsbScanner,
    )
    failures = await manager.start_parallel(os_ble=True, controller=controller)

    assert failures == []
    assert system.started
    assert usb.started
    assert manager.is_usb_scanning
    assert manager.os_ble_status.state == "OS-ACTIVE"
    await manager.stop()
    assert system.stopped
    assert usb.stopped


class _FakeDebug:
    """Minimal UsbLabDebugSession stand-in: records steps, supports phase()."""

    def __init__(self):
        self.steps: list[str] = []

    def step(self, message):
        self.steps.append(message)

    def phase(self, _name):
        from contextlib import nullcontext

        return nullcontext()


def _os_uuid_device():
    from wifit3.models import BluetoothDevice
    from wifit3.models.bluetooth_device import BLE_RADIO

    return BluetoothDevice(
        identifier="41C28AFD-7223-CCD1-6681-2C4127D8F06E",
        name="[TV] Samsung Q60AA 85 TV",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=0.0,
        first_seen=0.0,
        last_seen=1.0,
        address_type="platform-opaque",
        radio_types=(BLE_RADIO,),
    )


@pytest.mark.asyncio
def _device_information_inspection(device):
    from wifit3.models import (
        BluetoothCharacteristic,
        BluetoothInspection,
        BluetoothService,
    )

    service = BluetoothService(
        uuid="0000180a-0000-1000-8000-00805f9b34fb",
        name="Device Information",
    )
    fields = {
        "00002a24-0000-1000-8000-00805f9b34fb": ("Model Number String", "Watch7,15"),
        "00002a26-0000-1000-8000-00805f9b34fb": ("Firmware Revision String", "11.0"),
        "00002a27-0000-1000-8000-00805f9b34fb": ("Hardware Revision String", "1.0"),
        "00002a28-0000-1000-8000-00805f9b34fb": ("Software Revision String", "11.0.1"),
    }
    for handle, (uuid_value, (name, value)) in enumerate(fields.items(), start=3):
        service.characteristics.append(
            BluetoothCharacteristic(
                handle=handle,
                uuid=uuid_value,
                name=name,
                properties=("read",),
                value=value,
            ),
        )
    inspection = BluetoothInspection(device=device, connected=True)
    inspection.services = [service]
    return inspection


def test_connection_update_caches_device_information_onto_scan_row():
    manager = BluetoothManager()
    device = _os_uuid_device()
    manager._devices[device.identifier] = device

    inspection = _device_information_inspection(device)
    manager._connection_updated(inspection, None)

    cached = manager._devices[device.identifier]
    assert cached.model_number == "Watch7,15"
    assert cached.firmware_revision == "11.0"
    assert cached.hardware_revision == "1.0"
    assert cached.software_revision == "11.0.1"
    assert manager._device_information[device.identifier]["model_number"] == "Watch7,15"


class _FakeDisChar:
    def __init__(self, uuid, handle, value, properties=("read",)):
        self.uuid = uuid
        self.handle = handle
        self.properties = properties
        self.descriptors = ()
        self._value = value


class _FakeDisService:
    def __init__(self, uuid, characteristics):
        self.uuid = uuid
        self.characteristics = characteristics


class _FakeDisClient:
    """Minimal Bleak-like client exposing a Device Information Service."""

    def __init__(self, *args, **kwargs):
        self.services = [
            _FakeDisService(
                "0000180a-0000-1000-8000-00805f9b34fb",
                [
                    _FakeDisChar(
                        "00002a24-0000-1000-8000-00805f9b34fb", 10, b"Watch7,15",
                    ),
                    _FakeDisChar(
                        "00002a26-0000-1000-8000-00805f9b34fb", 12, b"11.0",
                    ),
                ],
            ),
        ]
        self.connected = False

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def read_gatt_char(self, handle):
        for service in self.services:
            for char in service.characteristics:
                if char.handle == handle:
                    return char._value
        raise KeyError(handle)


@pytest.mark.asyncio
async def test_device_information_sweep_enriches_connectable_device():
    manager = BluetoothManager(client_factory=_FakeDisClient)
    manager._scanner = object()  # OS BLE path active
    manager._enrichment_screen_active = True  # scanner screen is live
    manager._enrichment_gap_s = 0.0
    device = _os_uuid_device()
    manager._devices[device.identifier] = device

    await manager._run_device_information_sweep()

    enriched = manager._devices[device.identifier]
    assert enriched.model_number == "Watch7,15"
    assert enriched.firmware_revision == "11.0"
    assert manager._device_information[device.identifier]["model_number"] == "Watch7,15"
    assert manager.connection is None  # the sweep never clobbers the user connection


@pytest.mark.asyncio
async def test_device_information_sweep_enriches_over_usb_transport():
    from wifit3.bluetooth import gatt_att as att
    from wifit3.models import BluetoothCharacteristic, BluetoothService

    model_char = BluetoothCharacteristic(
        handle=0x0010,
        uuid="00002a24-0000-1000-8000-00805f9b34fb",
        name="Model Number String",
        properties=("read",),
    )
    dis = BluetoothService(
        uuid="0000180a-0000-1000-8000-00805f9b34fb",
        name="Device Information",
        characteristics=[model_char],
    )
    gatt = SimpleNamespace(
        le_gatt_session_start=lambda device: (0x0040, [dis]),
        le_gatt_session_stop=lambda handle: None,
        att_exchange=lambda handle, request: (
            bytes((att.ATT_READ_RESPONSE,)) + b"Watch7,15"
        ),
    )
    scanner = SimpleNamespace(
        gatt=gatt,
        controller=SimpleNamespace(supports_le=True),
        suspend_background_scan=AsyncMock(return_value=True),
        resume_background_scan=AsyncMock(),
    )

    manager = BluetoothManager()
    manager._usb_scanner = scanner  # USB HCI dongle owns LE; no OS BLE scanner
    manager._enrichment_screen_active = True
    manager._enrichment_gap_s = 0.0
    from wifit3.models import BluetoothDevice

    now = 1_700_000_000.0
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="BLE Speaker",
        rssi=-50,
        service_uuids=("180a",),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        radio_types=("BLE",),
        discovery_source="usb-hci+system",
    )
    manager._devices[device.identifier] = device

    # The sweep is available over USB even without an OS BLE scanner.
    assert manager._enrichment_unavailable_reason() == ""
    await manager._run_device_information_sweep()

    assert manager._devices[device.identifier].model_number == "Watch7,15"
    assert manager.enrichment_successes == 1
    scanner.suspend_background_scan.assert_awaited()
    scanner.resume_background_scan.assert_awaited_with(True)


def test_device_information_sweep_skips_os_uuid_without_os_ble():
    manager = BluetoothManager()
    manager._usb_scanner = SimpleNamespace(
        controller=SimpleNamespace(supports_le=True),
    )
    manager._enrichment_screen_active = True
    device = _os_uuid_device()
    manager._devices[device.identifier] = device

    assert manager._enrichment_transport_for(device) == "none"
    assert manager._device_information_candidates() == []


@pytest.mark.asyncio
async def test_device_information_sweep_only_runs_while_scanner_screen_active(tmp_path):
    manager = BluetoothManager(client_factory=_FakeDisClient)
    manager._scanner = object()
    manager._enrichment_gap_s = 0.0
    device = _os_uuid_device()
    manager._devices[device.identifier] = device

    # Screen not active (e.g. in Focus/Lab): the sweep must not connect.
    await manager._run_device_information_sweep()
    assert device.identifier not in manager._device_information

    manager.resume_device_information_sweep()
    await manager._run_device_information_sweep()
    assert manager._devices[device.identifier].model_number == "Watch7,15"

    await manager.pause_device_information_sweep()
    assert manager._enrichment_screen_active is False
    assert manager._enrichment_task is None


@pytest.mark.asyncio
async def test_device_information_sweep_persists_to_history(tmp_path):
    from wifit3.persist.bluetooth_history import BluetoothHistoryStore

    history = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    manager = BluetoothManager(client_factory=_FakeDisClient, history=history)
    manager._scanner = object()
    manager._enrichment_screen_active = True
    manager._enrichment_gap_s = 0.0

    from dataclasses import replace

    from wifit3.models import BluetoothDevice

    now = 1_700_000_000.0
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Apple Watch",
        rssi=-50,
        service_uuids=("180a",),
        service_data_uuids=(),
        manufacturer_ids=(76,),
        manufacturer_data_bytes=4,
        service_data_bytes=0,
        tx_power=-8,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        radio_types=("BLE",),
        address_type="public",
    )
    manager._devices[device.identifier] = device

    await manager._run_device_information_sweep()
    assert manager._devices[device.identifier].model_number == "Watch7,15"

    # A fresh observation of the same device restores the model from the DB.
    returning = replace(device, model_number="", firmware_revision="")
    assert history.enrich(returning)
    assert returning.model_number == "Watch7,15"
    assert returning.firmware_revision == "11.0"
    history.close()


@pytest.mark.asyncio
async def test_device_information_sweep_skips_during_active_connection():
    manager = BluetoothManager(client_factory=_FakeDisClient)
    manager._scanner = object()
    manager._enrichment_screen_active = True
    manager._enrichment_gap_s = 0.0
    manager.connection = object()  # user is inspecting a device
    device = _os_uuid_device()
    manager._devices[device.identifier] = device

    await manager._run_device_information_sweep()

    assert device.identifier not in manager._device_information


@pytest.mark.asyncio
async def test_device_information_sweep_skips_and_counts_nonconnectable():
    manager = BluetoothManager(client_factory=_FakeDisClient)
    manager._scanner = object()
    manager._enrichment_screen_active = True
    manager._enrichment_gap_s = 0.0
    device = _os_uuid_device()
    manager._devices[device.identifier] = device
    # CoreBluetooth reported this advertiser as non-connectable.
    manager._platform_connectable[device.identifier] = False

    await manager._run_device_information_sweep()

    assert manager.enrichment_nonconnectable == 1
    assert manager.enrichment_attempts == 1
    assert "model sweep ON" in manager.device_information_status()


def test_device_information_hint_explains_per_device_state():
    from dataclasses import replace

    manager = BluetoothManager()
    manager._enrichment_screen_active = True
    manager._scanner = object()  # sweep available

    connectable = _os_uuid_device()
    manager._platform_connectable[connectable.identifier] = False
    assert "non-connectable" in manager.device_information_hint(connectable)
    assert "still trying" in manager.device_information_hint(connectable)

    classic = replace(
        _os_uuid_device(),
        identifier="33:33:33:33:33:33",
        discovery_source="usb-hci",
        radio_types=("BT",),
    )
    assert "Classic only" in manager.device_information_hint(classic)

    known = replace(_os_uuid_device(), identifier="44:44:44:44:44:44",
                    model_number="Watch7,15")
    assert manager.device_information_hint(known) == "cached Watch7,15"

    pending = replace(_os_uuid_device(), identifier="55:55:55:55:55:55")
    assert "pending" in manager.device_information_hint(pending)


def test_device_information_status_reports_disabled_reason():
    manager = BluetoothManager()
    manager._enrichment_screen_active = True
    manager._scanner = None  # OS BLE not active
    status = manager.device_information_status()
    assert "model sweep OFF" in status
    assert "no BLE scanner active" in status


def test_device_information_candidates_exclude_noncandidates():
    from dataclasses import replace

    manager = BluetoothManager()
    manager._scanner = object()

    connectable = _os_uuid_device()
    cached = replace(_os_uuid_device(), identifier="22:22:22:22:22:22")
    classic = replace(
        _os_uuid_device(),
        identifier="33:33:33:33:33:33",
        discovery_source="usb-hci",
        radio_types=("BT",),
    )
    for device in (connectable, cached, classic):
        manager._devices[device.identifier] = device
    manager._device_information[cached.identifier] = {"model_number": "known"}

    candidate_ids = {d.identifier for d in manager._device_information_candidates()}
    assert connectable.identifier in candidate_ids
    assert cached.identifier not in candidate_ids  # already enriched
    assert classic.identifier not in candidate_ids  # not Bleak-connectable


def test_cached_device_information_survives_new_advertisement():
    from types import SimpleNamespace

    manager = BluetoothManager()
    device = _os_uuid_device()
    manager._devices[device.identifier] = device
    manager._connection_updated(_device_information_inspection(device), None)

    advertisement = SimpleNamespace(
        local_name=device.name,
        service_uuids=(),
        manufacturer_data={},
        service_data={},
        tx_power=None,
        rssi=-55,
        platform_data=(),
    )
    manager._on_advertisement(
        SimpleNamespace(address=device.identifier, name=device.name),
        advertisement,
    )

    refreshed = manager._devices[device.identifier]
    assert refreshed.model_number == "Watch7,15"
    assert refreshed.software_revision == "11.0.1"

