"""OS-backed Bluetooth Low Energy discovery."""
from __future__ import annotations

import asyncio
import logging
import platform
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from collections import deque
from dataclasses import dataclass, replace
from typing import Any, Callable


from bleak import BleakClient, BleakScanner

from wifit3.bluetooth.analytics import (
    bluez_platform_metadata,
    payload_fingerprint,
    is_bluetooth_bd_addr,
    platform_address_type,
    profile_fingerprint,
    protocol_type_hint,
    signal_summary,
)
from wifit3.bluetooth.connection import BluetoothConnection, BluetoothConnectionError
from wifit3.bluetooth.gatt_metadata import (
    ENRICHMENT_IDENTITY_BY_SERVICE,
    compact_uuid,
    device_information_fields,
)
from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.bluetooth.usb_hci import (
    UsbBluetoothController,
    UsbBluetoothError,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)
from wifit3.models import BluetoothDevice, BluetoothInspection, LocationFix
from wifit3.models.bluetooth_device import (
    BLE_RADIO,
    CLASSIC_RADIO,
    has_coherent_persistent_identity,
    has_stable_persistent_identifier,
)
from wifit3.persist.bluetooth_history import BluetoothHistoryStore
from wifit3.persist.locations import LocationStore

logger = logging.getLogger(__name__)


class BluetoothScanError(RuntimeError):
    """The platform Bluetooth backend could not start scanning."""


@dataclass(frozen=True, slots=True)
class OsBleSourceStatus:
    enabled: bool
    available: bool | None
    state: str
    backend: str
    operating_system: str
    manufacturer: str
    adapter: str
    detail: str

    @property
    def instance_key(self) -> tuple:
        return (
            self.enabled,
            self.available,
            self.state,
            self.backend,
            self.adapter,
            self.detail,
        )


def _os_ble_backend_info(scanner) -> tuple[str, str, str]:
    backend = getattr(scanner, "_backend", scanner)
    backend_type = type(backend)
    identity = f"{backend_type.__module__}.{backend_type.__name__}".casefold()
    if "corebluetooth" in identity:
        return "CoreBluetooth", "Apple", "System adapter"
    if "bluez" in identity:
        adapter = str(getattr(backend, "_adapter", "") or "System adapter")
        return "BlueZ", "", adapter
    if "winrt" in identity:
        return "WinRT", "Microsoft", "System adapter"
    return backend_type.__name__, "", "System adapter"


def _advertised_connectable(platform_data: tuple) -> bool | None:
    """Return CoreBluetooth's connectable flag when the advertisement includes it."""
    if len(platform_data) != 3 or not isinstance(platform_data[1], Mapping):
        return None
    value = platform_data[1].get("kCBAdvDataIsConnectable")
    return None if value is None else bool(value)


def _ble_mac_privacy_pattern(mac: str) -> str:
    """Classify random-address privacy bits without claiming an OS-hidden type."""
    if not is_bluetooth_bd_addr(mac):
        return "unknown address pattern"
    most_significant = int(mac.split(":", 1)[0], 16)
    kind = most_significant >> 6
    return {
        0b00: "NRPA/private-random bit pattern",
        0b01: "RPA/private-rotating bit pattern",
        0b11: "random-static bit pattern",
    }.get(kind, "reserved random-address bit pattern")


def _platform_ble_identity(platform_device: Any) -> tuple[str, str | None]:
    """Describe the OS BLE endpoint and return a BD_ADDR if the OS exposes one.

    CoreBluetooth's public identifier is normally a per-host UUID. Bleak also
    knows an optional, undocumented macOS selector that can return a BD_ADDR on
    some systems/controllers; probe it defensively without making it required.
    """
    address = str(getattr(platform_device, "address", "") or "")
    if is_bluetooth_bd_addr(address):
        return f"system address={address}", address
    uuid_label = address or "unavailable"
    details = getattr(platform_device, "details", None)
    if not isinstance(details, tuple) or len(details) < 2:
        return f"CoreBluetooth UUID={uuid_label}; MAC unavailable", None
    peripheral, manager = details[:2]
    central = getattr(manager, "central_manager", None)
    retrieve = getattr(central, "retrieveAddressForPeripheral_", None)
    if not callable(retrieve):
        return f"CoreBluetooth UUID={uuid_label}; MAC unavailable", None
    try:
        raw = retrieve(peripheral)
        address_bytes = bytes(raw) if raw is not None else b""
    except Exception:
        address_bytes = b""
    if len(address_bytes) != 6:
        return f"CoreBluetooth UUID={uuid_label}; MAC unavailable", None
    mac = address_bytes.hex(":").upper()
    pattern = _ble_mac_privacy_pattern(mac)
    return (
        f"CoreBluetooth UUID={uuid_label}; MAC={mac} "
        f"({pattern}; address type hidden by macOS)",
        mac,
    )


class BluetoothManager:
    """Owns either system BLE or dedicated USB discovery and its latest observations."""

    def __init__(
        self,
        scanner_factory: Callable[..., Any] = BleakScanner,
        client_factory: Callable[..., Any] = BleakClient,
        usb_scanner_factory: Callable[..., Any] = UsbHciScanner,
        usb_controller_finder: Callable[[], list[UsbBluetoothController]] = (
            find_usb_bluetooth_controllers
        ),
        history: BluetoothHistoryStore | None = None,
        location_store: LocationStore | None = None,
        fix_provider: Callable[[], LocationFix | None] | None = None,
        movement_provider: Callable[[], float] | None = None,
        accuracy_provider: Callable[[], float] | None = None,
        os_ble_enabled: bool = True,
    ) -> None:
        self._scanner_factory = scanner_factory
        self._client_factory = client_factory
        self._usb_scanner_factory = usb_scanner_factory
        self._usb_controller_finder = usb_controller_finder
        self.history = history
        self.location_store = location_store
        self.fix_provider = fix_provider
        self.movement_provider = movement_provider
        self.accuracy_provider = accuracy_provider
        self.os_ble_enabled = os_ble_enabled
        self.os_ble_status = self._disabled_os_ble_status() if not os_ble_enabled else (
            OsBleSourceStatus(
                True,
                None,
                "CHECKING",
                "Bleak",
                platform.system(),
                "",
                "System adapter",
                "Checking operating-system BLE availability",
            )
        )
        self._scanner = None
        self._usb_scanner = None
        self._usb_reservations: dict[tuple, Any] = {}
        self._usb_not_claimed: set[tuple] = set()
        self._usb_claim_verified: set[tuple] = set()
        self._usb_reservation_lock = threading.Lock()
        self._resume_usb_controller: UsbBluetoothController | None = None
        self._devices: dict[str, BluetoothDevice] = {}
        self._device_information: dict[str, dict[str, str]] = {}
        self._enrichment_enabled = True
        self._enrichment_screen_active = False
        self._enrichment_task: asyncio.Task | None = None
        self._enrichment_connection: Any = None
        self._enrichment_attempts: dict[str, float] = {}
        self._enrichment_interval_s = 12.0
        self._enrichment_gap_s = 1.5
        self._enrichment_retry_s = 180.0
        # Observability for the passive model-enrichment sweep (debuggable in UI).
        self.enrichment_status_reason = "not started"
        self.enrichment_candidates = 0
        self.enrichment_nonconnectable = 0
        self.enrichment_attempts = 0
        self.enrichment_successes = 0
        self.enrichment_failures = 0
        self.enrichment_last_target = ""
        self.enrichment_last_error = ""
        self._platform_devices: dict[str, Any] = {}
        self._platform_connectable: dict[str, bool] = {}
        self._platform_observed_macs: dict[str, str] = {}
        self._similar_identifiers: dict[tuple, set[str]] = {}
        self._rssi_history: dict[str, deque[int]] = {}
        self._classic_focus_identifier: str | None = None
        self._focus_identifier: str | None = None
        self.focus_connection_error: str = ""
        self._classic_sdp_trace: tuple[str, ...] = ()
        self.connection: BluetoothConnection | None = None
        self._advertisement_callbacks: list[Callable[[BluetoothDevice], None]] = []
        self._inspection_callbacks: list[Callable[[Any], None]] = []
        self.scan_started_at: float | None = None
        self.last_advertisement_at: float | None = None
        self.received_advertisements = 0
        self.observations_by_radio = {BLE_RADIO: 0, CLASSIC_RADIO: 0}
        self.last_observation_by_radio: dict[str, float] = {}
        self.scan_failures = 0

    @property
    def is_scanning(self) -> bool:
        return self._scanner is not None or (
            self._usb_scanner is not None
            and getattr(self._usb_scanner, "is_scanning", True)
        )

    @property
    def hci_capture_records(self) -> tuple:
        if self._usb_scanner is None:
            return ()
        return tuple(getattr(self._usb_scanner, "capture_records", ()))

    @property
    def hci_health(self):
        if self._usb_scanner is None:
            return None
        return getattr(self._usb_scanner, "health", None)

    @property
    def classic_focus_device(self) -> BluetoothDevice | None:
        if self._classic_focus_identifier is None:
            return None
        return self._devices.get(self._classic_focus_identifier)

    @property
    def focus_device(self) -> BluetoothDevice | None:
        if self._focus_identifier is None:
            return None
        return self._devices.get(self._focus_identifier)

    def select_focus(self, identifier: str, *, error: str = "") -> None:
        self._focus_identifier = identifier
        self.focus_connection_error = error

    def select_classic_focus(self, identifier: str) -> None:
        self._classic_focus_identifier = identifier
        self.select_focus(identifier)

    @property
    def classic_sdp_trace(self) -> tuple[str, ...]:
        return self._classic_sdp_trace

    def classic_focus_fallback(
        self,
        device: BluetoothDevice,
    ) -> BluetoothDevice | None:
        if CLASSIC_RADIO in device.radio_types:
            return device
        for identifier in device.related_identifiers:
            related = self._devices.get(identifier)
            if related is not None and CLASSIC_RADIO in related.radio_types:
                return related
        return None

    def _resolve_platform_device(self, identifier: str) -> Any:
        platform_device = self._platform_devices.get(identifier)
        if platform_device is not None:
            return platform_device
        folded = identifier.casefold()
        for key, candidate in self._platform_devices.items():
            if key.casefold() == folded:
                return candidate
        return identifier

    def _resolve_bluetooth_device(self, identifier: str) -> BluetoothDevice | None:
        device = self._devices.get(identifier)
        if device is not None:
            return device
        folded = identifier.casefold()
        for key, candidate in self._devices.items():
            if key.casefold() == folded:
                return candidate
        focus = self.classic_focus_device
        if focus is not None and focus.identifier.casefold() == folded:
            return focus
        return None

    async def _ensure_usb_scanner_ready(self) -> None:
        if self._usb_scanner is None:
            controller = self._resume_usb_controller
            if controller is None:
                controllers = await asyncio.to_thread(self.available_usb_controllers)
                classic_controllers = [
                    candidate
                    for candidate in controllers
                    if candidate.supports_classic
                ]
                if len(classic_controllers) == 1:
                    controller = classic_controllers[0]
                elif len(classic_controllers) > 1:
                    raise BluetoothScanError(
                        "Multiple USB Bluetooth controllers are available. "
                        "Select one on the startup screen before browsing Classic SDP",
                    )
            if controller is None:
                raise BluetoothScanError(
                    "No dedicated USB HCI controller is active. Connect or select a "
                    "Classic-capable USB Bluetooth dongle on the startup screen, "
                    "then rescan",
                )
            await self._activate_usb(controller, pair_os_ble=False)
            return
        scanner = self._usb_scanner
        if scanner._device is not None:
            if not scanner.is_scanning:
                await scanner.start()
            return
        await scanner.start()

    async def browse_classic_sdp(self, identifier: str):
        await self._ensure_usb_scanner_ready()
        device = self._resolve_bluetooth_device(identifier)
        if device is not None:
            identifier = device.identifier
        try:
            services = await self._usb_scanner.browse_sdp(
                identifier, fallback_device=device,
            )
        finally:
            self._classic_sdp_trace = tuple(
                getattr(self._usb_scanner, "sdp_trace", ()),
            )
        if device is not None:
            device.service_uuids = tuple(sorted({
                *device.service_uuids,
                *(service.uuid for service in services),
            }))
            device.profile_fingerprint = _profile_fingerprint(device)
            self._correlate_radios(device)
            if self.history is not None:
                self.history.remember(device)
            for callback in list(self._advertisement_callbacks):
                try:
                    callback(device)
                except Exception:
                    logger.debug("Bluetooth SDP callback failed", exc_info=True)
        return services

    @property
    def is_usb_scanning(self) -> bool:
        return (
            self._usb_scanner is not None
            and getattr(self._usb_scanner, "is_scanning", True)
        )

    @property
    def is_os_ble_scanning(self) -> bool:
        return self._scanner is not None

    @property
    def usb_lab_available(self) -> bool:
        return False

    @property
    def usb_scanner(self):
        return self._usb_scanner

    def usb_capabilities(self):
        if self._usb_scanner is None:
            return None
        from wifit3.bluetooth.usb_capabilities import UsbBluetoothCapabilities

        return UsbBluetoothCapabilities.for_controller(self._usb_scanner.controller)

    @property
    def backend_name(self) -> str:
        if self._usb_scanner is not None:
            chipset = self._usb_scanner.controller.chipset
            return (
                f"{chipset} + OS BLE"
                if self._scanner is not None else chipset
            )
        scanner = self._scanner
        return scanner.__class__.__name__ if scanner is not None else "Bleak"

    def devices(self) -> list[BluetoothDevice]:
        return list(self._devices.values())

    def active_radio_types(self) -> tuple[str, ...]:
        radios = set()
        if self._scanner is not None or self.connection is not None:
            radios.add(BLE_RADIO)
        if self._usb_scanner is not None:
            controller = self._usb_scanner.controller
            if controller.supports_le:
                radios.add(BLE_RADIO)
            if controller.supports_classic:
                radios.add(CLASSIC_RADIO)
        return tuple(radio for radio in (BLE_RADIO, CLASSIC_RADIO) if radio in radios)

    def backend_name_for_radio(self, radio_type: str) -> str:
        usb_scanner = self._usb_scanner
        if usb_scanner is not None:
            controller = usb_scanner.controller
            if (
                radio_type == CLASSIC_RADIO and controller.supports_classic
                or radio_type == BLE_RADIO and controller.supports_le
            ):
                return controller.chipset
        scanner = self._scanner
        return scanner.__class__.__name__ if scanner is not None else "Bleak"

    def is_usb_radio(self, radio_type: str) -> bool:
        usb_scanner = self._usb_scanner
        if usb_scanner is None:
            return False
        controller = usb_scanner.controller
        return (
            radio_type == CLASSIC_RADIO and controller.supports_classic
            or radio_type == BLE_RADIO and controller.supports_le
        )

    def forget_devices(self) -> None:
        """Drop the in-memory discovery picture after confirmed history deletion."""
        if self.is_scanning:
            raise BluetoothScanError(
                "Stop Bluetooth discovery before clearing its history",
            )
        self._devices.clear()
        self._platform_devices.clear()
        self._platform_connectable.clear()
        self._platform_observed_macs.clear()
        self._similar_identifiers.clear()
        self._rssi_history.clear()

    def available_usb_controllers(self) -> list[UsbBluetoothController]:
        try:
            controllers = self._usb_controller_finder()
        except Exception:
            logger.debug("Bluetooth USB controller scan failed", exc_info=True)
            return []
        if sys.platform == "darwin":
            self._reserve_macos_controllers(controllers)
        else:
            self._probe_usb_claim_status(controllers)
        return controllers

    def usb_not_claimed_keys(self) -> frozenset[tuple]:
        return frozenset(self._usb_not_claimed)

    def mark_usb_claim_failed(self, controller: UsbBluetoothController) -> None:
        self._usb_not_claimed.add(controller.instance_key)

    def mark_usb_claimed(self, controller: UsbBluetoothController) -> None:
        self._usb_not_claimed.discard(controller.instance_key)

    def reclaim_usb_controller(
        self, controller: UsbBluetoothController,
    ) -> tuple[bool, str]:
        """Try to take the dongle from the OS without a physical replug."""
        key = controller.instance_key
        active = (
            self._usb_scanner.controller.instance_key
            if self._usb_scanner is not None else None
        )
        with self._usb_reservation_lock:
            if key in self._usb_reservations or key == active:
                self._usb_not_claimed.discard(key)
                return True, "USB Bluetooth adapter is already held by wifit3"
        scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
        try:
            if hasattr(scanner, "reclaim_from_os"):
                scanner.reclaim_from_os()
            elif hasattr(scanner, "reserve"):
                scanner.reserve(recover=True)
            else:
                return False, "This adapter cannot be reclaimed in software"
        except Exception as exc:
            logger.debug("USB Bluetooth reclaim failed", exc_info=True)
            self._usb_not_claimed.add(key)
            self._usb_claim_verified.discard(key)
            return False, str(exc) or type(exc).__name__
        with self._usb_reservation_lock:
            self._usb_not_claimed.discard(key)
            self._usb_claim_verified.add(key)
            self._usb_reservations[key] = scanner
        return True, "USB Bluetooth adapter claimed for wifit3"

    def _disabled_os_ble_status(self) -> OsBleSourceStatus:
        return OsBleSourceStatus(
            False,
            None,
            "APP-DISABLED",
            "Bleak",
            platform.system(),
            "",
            "System adapter",
            "Disabled for wifit3 on the startup screen",
        )

    def set_os_ble_enabled(self, enabled: bool) -> None:
        self.os_ble_enabled = enabled
        if not enabled:
            self.os_ble_status = self._disabled_os_ble_status()
        elif self.os_ble_status.state == "APP-DISABLED":
            self.os_ble_status = replace(
                self.os_ble_status,
                enabled=True,
                available=None,
                state="CHECKING",
                detail="Checking operating-system BLE availability",
            )

    async def probe_os_ble(self) -> OsBleSourceStatus:
        if not self.os_ble_enabled:
            self.os_ble_status = self._disabled_os_ble_status()
            return self.os_ble_status
        if self._scanner is not None:
            self.os_ble_status = replace(
                self.os_ble_status,
                enabled=True,
                available=True,
                state="OS-ACTIVE",
                detail="Operating-system BLE discovery is active",
            )
            return self.os_ble_status
        scanner = self._scanner_factory(
            detection_callback=lambda _device, _advertisement: None,
        )
        backend, manufacturer, adapter = _os_ble_backend_info(scanner)
        started = False
        try:
            await asyncio.wait_for(scanner.start(), timeout=3.0)
            started = True
        except Exception as exc:
            detail = str(exc).strip() or type(exc).__name__
            self.os_ble_status = OsBleSourceStatus(
                True,
                False,
                "OS-DISABLED",
                backend,
                platform.system(),
                manufacturer,
                adapter,
                detail,
            )
        else:
            self.os_ble_status = OsBleSourceStatus(
                True,
                True,
                "OS-READY",
                backend,
                platform.system(),
                manufacturer,
                adapter,
                "Operating-system BLE scanning is available",
            )
        finally:
            if started:
                try:
                    await scanner.stop()
                except Exception:
                    pass
        return self.os_ble_status

    def register_advertisement_callback(
        self, callback: Callable[[BluetoothDevice], None],
    ) -> None:
        if callback not in self._advertisement_callbacks:
            self._advertisement_callbacks.append(callback)

    def unregister_advertisement_callback(
        self, callback: Callable[[BluetoothDevice], None],
    ) -> None:
        if callback in self._advertisement_callbacks:
            self._advertisement_callbacks.remove(callback)

    def register_inspection_callback(self, callback: Callable[[Any], None]) -> None:
        if callback not in self._inspection_callbacks:
            self._inspection_callbacks.append(callback)

    def unregister_inspection_callback(self, callback: Callable[[Any], None]) -> None:
        if callback in self._inspection_callbacks:
            self._inspection_callbacks.remove(callback)

    async def start(self) -> None:
        if self.is_scanning:
            return
        await self._activate_os_ble()

    async def _activate_os_ble(self) -> None:
        if not self.os_ble_enabled:
            raise BluetoothScanError("OS BLE source is disabled on the startup screen")
        if self._scanner is not None:
            return
        scanner = self._scanner_factory(detection_callback=self._on_advertisement)
        try:
            await scanner.start()
        except Exception as exc:
            self.scan_failures += 1
            self.os_ble_status = replace(
                self.os_ble_status,
                enabled=True,
                available=False,
                state="OS-DISABLED",
                detail=str(exc).strip() or type(exc).__name__,
            )
            try:
                await scanner.stop()
            except Exception:
                pass
            raise BluetoothScanError(str(exc) or type(exc).__name__) from exc
        self._scanner = scanner
        backend, manufacturer, adapter = _os_ble_backend_info(scanner)
        self.os_ble_status = OsBleSourceStatus(
            True,
            True,
            "OS-ACTIVE",
            backend,
            platform.system(),
            manufacturer,
            adapter,
            "Operating-system BLE discovery is active",
        )
        if self._usb_scanner is None:
            self._resume_usb_controller = None
        self.scan_started_at = time.time()
        self._start_device_information_sweep()

    async def start_usb(self, controller: UsbBluetoothController) -> None:
        if self.is_scanning:
            return
        await self._activate_usb(controller, pair_os_ble=True)

    async def start_parallel(
        self,
        *,
        os_ble: bool,
        controller: UsbBluetoothController | None,
    ) -> list[str]:
        """Start OS BLE and a USB controller together. One radio failing leaves the other running."""
        failures: list[str] = []
        if controller is not None and not self.is_usb_scanning:
            try:
                await self._activate_usb(controller, pair_os_ble=False)
            except BluetoothScanError as exc:
                failures.append(str(exc))
        if os_ble and self._scanner is None:
            try:
                await self._activate_os_ble()
            except BluetoothScanError as exc:
                failures.append(str(exc))
        return failures

    async def _activate_usb(
        self,
        controller: UsbBluetoothController,
        *,
        pair_os_ble: bool,
    ) -> None:
        system_scanner = None
        if pair_os_ble and self.os_ble_enabled and self._scanner is None:
            system_scanner = self._scanner_factory(
                detection_callback=self._on_advertisement,
            )
        with self._usb_reservation_lock:
            usb_scanner = self._usb_reservations.pop(controller.instance_key, None)
        if usb_scanner is None:
            usb_scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
        if system_scanner is not None and controller.supports_le:
            usb_scanner.use_os_ble_for_le_discovery()
        try:
            await usb_scanner.start()
            if system_scanner is not None:
                await system_scanner.start()
        except Exception as exc:
            self.scan_failures += 1
            self.mark_usb_claim_failed(controller)
            for scanner in (usb_scanner, system_scanner):
                if scanner is None:
                    continue
                try:
                    await scanner.stop()
                except Exception:
                    pass
            if isinstance(exc, BluetoothScanError):
                raise
            if isinstance(exc, UsbBluetoothError):
                raise BluetoothScanError(str(exc)) from exc
            raise BluetoothScanError(str(exc) or type(exc).__name__) from exc
        if system_scanner is not None:
            self._scanner = system_scanner
        self._usb_scanner = usb_scanner
        if system_scanner is not None:
            backend, manufacturer, adapter = _os_ble_backend_info(system_scanner)
            self.os_ble_status = OsBleSourceStatus(
                True,
                True,
                "OS-ACTIVE",
                backend,
                platform.system(),
                manufacturer,
                adapter,
                "Operating-system BLE discovery is active",
            )
        self._resume_usb_controller = controller
        self.mark_usb_claimed(controller)
        self.scan_started_at = time.time()
        self._start_device_information_sweep()

    async def resume_scan(self) -> None:
        if self._resume_usb_controller is not None:
            await self.start_usb(self._resume_usb_controller)
        else:
            await self.start()

    async def stop(self) -> None:
        await self._stop_device_information_sweep()
        scanner, self._scanner = self._scanner, None
        usb_scanner, self._usb_scanner = self._usb_scanner, None
        if scanner is not None:
            try:
                await scanner.stop()
            except Exception:
                logger.debug("Bluetooth scanner stop failed", exc_info=True)
            if self.os_ble_enabled:
                self.os_ble_status = replace(
                    self.os_ble_status,
                    available=True,
                    state="OS-READY",
                    detail="Operating-system BLE scanning is available",
                )
        if usb_scanner is None:
            return
        keep_reserved = (
            sys.platform == "darwin"
            and hasattr(usb_scanner, "pause")
        )
        try:
            if keep_reserved:
                await usb_scanner.pause()
                with self._usb_reservation_lock:
                    self._usb_reservations[usb_scanner.controller.instance_key] = usb_scanner
            else:
                await usb_scanner.stop()
        except Exception:
            logger.debug("Bluetooth USB scanner stop failed", exc_info=True)

    async def connect(self, device: BluetoothDevice, update_callback=None):
        if not getattr(device, "is_connectable_with_bleak", True):
            raise BluetoothConnectionError(
                "This Classic-only observation has no BLE GATT endpoint; open Classic Focus "
                "or use USB lab Classic checks",
            )
        if self._usb_scanner is not None and self._usb_scanner.controller.supports_le:
            return await self._connect_usb(device, update_callback)
        await self._abort_enrichment()
        await self.disconnect()
        platform_device = self._platform_devices.get(device.identifier, device.identifier)
        connection = BluetoothConnection(
            device,
            platform_device,
            client_factory=self._client_factory,
            update_callback=lambda inspection: self._connection_updated(
                inspection, update_callback,
            ),
        )
        self.connection = connection
        try:
            await connection.connect()
        except asyncio.CancelledError:
            self.connection = None
            await connection.disconnect()
            raise
        except Exception:
            self.connection = None
            raise
        return connection

    async def _connect_usb(self, device: BluetoothDevice, update_callback=None):
        from wifit3.bluetooth.usb_connection import (
            UsbBluetoothConnection,
            UsbBluetoothConnectionError,
        )

        await self._ensure_usb_scanner_ready()
        await self._abort_enrichment()
        await self.disconnect()
        connection = UsbBluetoothConnection(
            device,
            self._usb_scanner,
            update_callback=lambda inspection: self._connection_updated(
                inspection, update_callback,
            ),
        )
        self.connection = connection
        try:
            await connection.connect()
        except asyncio.CancelledError:
            self.connection = None
            await connection.disconnect()
            raise
        except UsbBluetoothConnectionError:
            self.connection = None
            raise BluetoothConnectionError(connection.inspection.disconnected_reason)
        except Exception:
            self.connection = None
            raise
        return connection

    def _connection_updated(self, inspection, update_callback) -> None:
        self._cache_device_information(inspection)
        if update_callback is not None:
            update_callback(inspection)
        for callback in list(self._inspection_callbacks):
            try:
                callback(inspection)
            except Exception:
                logger.debug("Bluetooth inspection callback failed", exc_info=True)

    def _cache_device_information(self, inspection) -> None:
        """Cache Device Information strings from a live inspection for the scanner.

        The exact model string is only available from the Device Information
        Service (0x180A) after a GATT connection, so it is stored per identifier
        and surfaced on the scanner row the next time the table repaints.
        """
        identifier = getattr(getattr(inspection, "device", None), "identifier", None)
        if not identifier:
            return
        info = device_information_fields(inspection)
        if not info:
            return
        previous_info = self._device_information.get(identifier, {})
        merged = {**previous_info, **info}
        learned_new = merged != previous_info
        self._device_information[identifier] = merged
        existing = self._devices.get(identifier)
        if existing is not None:
            updated = replace(existing, **info)
            self._devices[identifier] = updated
            if learned_new and self.history is not None:
                try:
                    self.history.remember(updated, force=True)
                except Exception:
                    logger.debug(
                        "Persisting Device Information failed", exc_info=True,
                    )

    def _apply_cached_device_information(self, device):
        """Overlay cached Device Information onto a freshly observed device."""
        cached = self._device_information.get(device.identifier)
        if not cached:
            return device
        return replace(device, **cached)

    def resume_device_information_sweep(self) -> None:
        """Enable passive enrichment; only the scanner screen should call this."""
        self._enrichment_screen_active = True
        self._start_device_information_sweep()

    async def pause_device_information_sweep(self) -> None:
        """Disable passive enrichment when leaving the scanner (Focus/Lab/exit)."""
        self._enrichment_screen_active = False
        await self._stop_device_information_sweep()

    def _start_device_information_sweep(self) -> None:
        """Start the passive background enrichment loop if the Bleak radio is active."""
        if not self._enrichment_enabled or not self._enrichment_screen_active:
            return
        if self._enrichment_unavailable_reason() != "":
            return
        if self._enrichment_task is not None and not self._enrichment_task.done():
            return
        try:
            self._enrichment_task = asyncio.ensure_future(
                self._device_information_sweep_loop(),
            )
        except RuntimeError:
            self._enrichment_task = None

    async def _stop_device_information_sweep(self) -> None:
        task, self._enrichment_task = self._enrichment_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._abort_enrichment()

    async def _abort_enrichment(self) -> None:
        """Release any in-flight enrichment connection so a user action can proceed."""
        connection, self._enrichment_connection = self._enrichment_connection, None
        if connection is not None:
            try:
                await connection.disconnect()
            except Exception:
                logger.debug("Enrichment disconnect failed", exc_info=True)

    def _enrichment_unavailable_reason(self) -> str:
        """Explain why passive enrichment cannot run (empty string = available)."""
        if not self._enrichment_enabled:
            return "disabled"
        if not self._enrichment_screen_active:
            return "off scanner screen"
        # Enrichment mirrors the manual-connect routing: it reads the Device
        # Information Service over whichever LE transport is active (USB HCI
        # dongle when it owns LE, otherwise the OS BLE/Bleak path).
        if not self._enrichment_usb_le_active() and self._scanner is None:
            return "no BLE scanner active"
        return ""

    def _enrichment_usb_le_active(self) -> bool:
        return (
            self._usb_scanner is not None
            and self._usb_scanner.controller.supports_le
        )

    def device_information_hint(self, device: BluetoothDevice) -> str:
        """Per-device explanation of why a GATT model is (not) available."""
        if getattr(device, "model_number", ""):
            return f"cached {device.model_number}"
        reason = self._enrichment_unavailable_reason()
        if reason:
            return f"sweep off — {reason}"
        if getattr(device, "approximate_group", False):
            return "unavailable — privacy group of rotating identifiers"
        if BLE_RADIO not in getattr(device, "radio_types", ()):
            return "unavailable — Classic only, no BLE GATT endpoint"
        if not self._enrichment_usb_le_active() and not getattr(
            device, "is_connectable_with_bleak", True,
        ):
            return "unavailable — not a system BLE endpoint"
        if self._enrichment_transport_for(device) == "none":
            return (
                "unavailable — OS UUID only; dongle needs a MAC or enable OS BLE "
                "on splash"
            )
        non_connectable = self._platform_connectable.get(device.identifier) is False
        suffix = (
            " (advertised non-connectable; still trying)"
            if non_connectable
            else ""
        )
        if device.identifier in self._enrichment_attempts:
            return (
                "attempted — no Device Information service or connection failed"
                + suffix
            )
        return "pending — queued for background read" + suffix

    def device_information_status(self) -> str:
        """One-line, user-facing status of the passive model sweep for debugging."""
        reason = self._enrichment_unavailable_reason()
        if reason:
            return f"model sweep OFF · {reason}"
        detail = (
            f"model sweep ON · {self.enrichment_successes} ok / "
            f"{self.enrichment_attempts} tried · {self.enrichment_candidates} queued · "
            f"{self.enrichment_nonconnectable} non-connectable"
        )
        if self.enrichment_last_error:
            detail += f" · last error: {self.enrichment_last_error}"
        elif self.enrichment_last_target:
            detail += f" · last: {self.enrichment_last_target}"
        return detail

    async def _device_information_sweep_loop(self) -> None:
        first = True
        while True:
            try:
                await asyncio.sleep(3.0 if first else self._enrichment_interval_s)
                first = False
                await self._run_device_information_sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("Device Information sweep failed", exc_info=True)

    async def _run_device_information_sweep(self) -> None:
        reason = self._enrichment_unavailable_reason()
        self.enrichment_status_reason = reason or "running"
        if reason:
            return
        if self.connection is not None:
            self.enrichment_status_reason = "paused: active connection"
            return
        self.enrichment_nonconnectable = sum(
            1 for device in self._devices.values()
            if self._platform_connectable.get(device.identifier) is False
        )
        candidates = self._device_information_candidates()
        self.enrichment_candidates = len(candidates)
        for device in candidates:
            if self.connection is not None:
                break
            self._enrichment_attempts[device.identifier] = time.time()
            self.enrichment_attempts += 1
            self.enrichment_last_target = self._enrichment_target_label(device)
            error = await self._enrich_device_information(device)
            if error is None:
                self.enrichment_successes += 1
                self.enrichment_last_error = ""
            else:
                self.enrichment_failures += 1
                self.enrichment_last_error = f"{self.enrichment_last_target}: {error}"
            await asyncio.sleep(self._enrichment_gap_s)

    def _device_has_gatt_identity(self, device: BluetoothDevice) -> bool:
        return bool(
            getattr(device, "model_number", "")
            or getattr(device, "gatt_device_name", "")
            or getattr(device, "pnp_id", ""),
        )

    def _device_information_candidates(self) -> list[BluetoothDevice]:
        now = time.time()
        candidates: list[BluetoothDevice] = []
        for device in list(self._devices.values()):
            if device.identifier in self._device_information:
                continue
            if self._device_has_gatt_identity(device):
                continue
            if not self._is_enrichable(device):
                continue
            last = self._enrichment_attempts.get(device.identifier, 0.0)
            if now - last < self._enrichment_retry_s:
                continue
            candidates.append(device)
        return candidates

    def _enrichment_target_label(self, device: BluetoothDevice) -> str:
        if device.name and device.name != "<Unknown>":
            return device.name
        from wifit3.bluetooth.assigned_numbers import manufacturer_label

        manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier)
        if manufacturer:
            return manufacturer
        return device.identifier[:20]

    def _enrichment_transport_for(self, device: BluetoothDevice) -> str:
        """Return ``usb``, ``bleak``, or ``none`` for passive DIS reads."""
        from wifit3.bluetooth.analytics import device_lacks_usb_hci_bd_addr

        bleak_ok = bool(getattr(device, "is_connectable_with_bleak", True))
        os_ble = self._scanner is not None
        if self._enrichment_usb_le_active():
            if not device_lacks_usb_hci_bd_addr(
                device.identifier, device.related_identifiers,
            ):
                return "usb"
            if os_ble and bleak_ok:
                return "bleak"
            return "none"
        if os_ble and bleak_ok:
            return "bleak"
        return "none"

    def _is_enrichable(self, device: BluetoothDevice) -> bool:
        if getattr(device, "approximate_group", False):
            return False
        if BLE_RADIO not in getattr(device, "radio_types", ()):
            return False
        # CoreBluetooth's connectable flag is a hint only (see USB lab narrative).
        return self._enrichment_transport_for(device) != "none"

    async def _enrich_device_information(self, device: BluetoothDevice) -> str | None:
        """Read the Device Information Service over the active LE transport."""
        transport = self._enrichment_transport_for(device)
        if transport == "none":
            return None
        usb_scanner = self._usb_scanner
        was_usb_scanning = False
        if usb_scanner is not None and hasattr(usb_scanner, "suspend_background_scan"):
            was_usb_scanning = await usb_scanner.suspend_background_scan()
        os_scanner = None
        if transport == "bleak" and self._scanner is not None:
            # Mirror manual Focus connect: quiet discovery while GATT runs.
            os_scanner = self._scanner
            self._scanner = None
            try:
                await os_scanner.stop()
            except Exception:
                logger.debug("OS BLE scanner stop for enrichment failed", exc_info=True)
        try:
            if transport == "usb":
                return await self._enrich_device_information_usb(device)
            return await self._enrich_device_information_bleak(device)
        finally:
            if os_scanner is not None:
                try:
                    await os_scanner.start()
                except Exception:
                    logger.debug("OS BLE scanner restart after enrichment failed", exc_info=True)
                self._scanner = os_scanner
            if usb_scanner is not None:
                await usb_scanner.resume_background_scan(was_usb_scanning)

    async def _enrich_device_information_usb(
        self, device: BluetoothDevice,
    ) -> str | None:
        from wifit3.bluetooth.usb_connection import UsbBluetoothConnection

        scanner = self._usb_scanner
        if scanner is None:
            return "USB scanner unavailable"
        connection = UsbBluetoothConnection(
            device, scanner, update_callback=self._cache_device_information,
        )
        self._enrichment_connection = connection
        try:
            await connection.connect()
            read_any = False
            for service in connection.inspection.services:
                service_short = compact_uuid(service.uuid)
                allowed = ENRICHMENT_IDENTITY_BY_SERVICE.get(service_short)
                if allowed is None:
                    continue
                for characteristic in service.characteristics:
                    if "read" not in characteristic.properties:
                        continue
                    if compact_uuid(characteristic.uuid) not in allowed:
                        continue
                    try:
                        await connection.read_characteristic(characteristic.handle)
                        read_any = True
                    except Exception:
                        logger.debug("USB DIS read failed", exc_info=True)
            return None if read_any else "no readable GATT identity characteristics"
        except Exception as exc:
            logger.debug(
                "USB Device Information enrichment failed for %s",
                device.identifier,
                exc_info=True,
            )
            return str(exc).strip() or type(exc).__name__
        finally:
            try:
                await connection.disconnect()
            except Exception:
                logger.debug("USB enrichment disconnect failed", exc_info=True)
            if self._enrichment_connection is connection:
                self._enrichment_connection = None

    async def _enrich_device_information_bleak(
        self, device: BluetoothDevice,
    ) -> str | None:
        """Read the Device Information Service. Returns an error string on failure."""
        platform_device = self._platform_devices.get(device.identifier, device.identifier)
        connection = BluetoothConnection(
            device,
            platform_device,
            client_factory=self._client_factory,
            update_callback=self._cache_device_information,
            connect_timeout_s=14.0,
        )
        self._enrichment_connection = connection
        try:
            await connection.inspect_device_information()
            return None
        except Exception as exc:
            logger.debug(
                "Device Information enrichment failed for %s",
                device.identifier,
                exc_info=True,
            )
            return str(exc).strip() or type(exc).__name__
        finally:
            if self._enrichment_connection is connection:
                self._enrichment_connection = None

    async def disconnect(self) -> None:
        connection, self.connection = self.connection, None
        if connection is not None:
            await connection.disconnect()

    def _on_advertisement(self, device, advertisement_data) -> None:
        identifier = str(device.address)
        self._platform_devices[identifier] = device
        connectable = _advertised_connectable(
            tuple(getattr(advertisement_data, "platform_data", ())),
        )
        if connectable is not None:
            self._platform_connectable[identifier] = connectable
        now = time.time()
        self.last_advertisement_at = now
        self.received_advertisements += 1
        self.observations_by_radio[BLE_RADIO] += 1
        self.last_observation_by_radio[BLE_RADIO] = now
        previous = self._devices.get(identifier)
        name = advertisement_data.local_name or (
            previous.name if previous is not None else device.name or "<Unknown>"
        )
        service_uuids = set(advertisement_data.service_uuids or ())
        manufacturer_ids = set((advertisement_data.manufacturer_data or {}).keys())
        service_data_uuids = set((advertisement_data.service_data or {}).keys())
        if previous is not None:
            service_uuids.update(previous.service_uuids)
            manufacturer_ids.update(previous.manufacturer_ids)
            service_data_uuids.update(previous.service_data_uuids)
        similarity_key = (
            name if name != "<Unknown>" else "",
            tuple(sorted(manufacturer_ids)),
            tuple(sorted(uuid.lower() for uuid in service_uuids)),
            tuple(sorted(uuid.lower() for uuid in service_data_uuids)),
        )
        similar_identifier_count = 1
        platform_metadata = bluez_platform_metadata(
            getattr(advertisement_data, "platform_data", ()), identifier,
        )
        address_type = (
            platform_metadata.get("address_type")
            or (
                previous.address_type
                if previous is not None
                else platform_address_type(identifier)
            )
        )
        if _is_private_identifier(identifier, address_type) and any(similarity_key):
            identifiers = self._similar_identifiers.setdefault(similarity_key, set())
            identifiers.add(identifier)
            similar_identifier_count = len(identifiers)
            for similar_identifier in identifiers:
                known = self._devices.get(similar_identifier)
                if known is not None:
                    self._devices[similar_identifier] = replace(
                        known, similar_identifier_count=similar_identifier_count,
                    )
        signal = self._signal_fields(identifier, advertisement_data.rssi)
        protocol_hint = protocol_type_hint(
            advertisement_data.manufacturer_data,
            advertisement_data.service_data,
            advertisement_data.service_uuids or (),
            name=name,
        )
        observed = BluetoothDevice(
            identifier=identifier,
            name=name,
            rssi=advertisement_data.rssi,
            service_uuids=tuple(sorted(uuid.lower() for uuid in service_uuids)),
            service_data_uuids=tuple(sorted(uuid.lower() for uuid in service_data_uuids)),
            manufacturer_ids=tuple(sorted(manufacturer_ids)),
            manufacturer_data_bytes=sum(
                len(value) for value in (advertisement_data.manufacturer_data or {}).values()
            ),
            service_data_bytes=sum(
                len(value) for value in (advertisement_data.service_data or {}).values()
            ),
            tx_power=advertisement_data.tx_power,
            advertisement_count=(previous.advertisement_count + 1) if previous else 1,
            advertisement_interval=(now - previous.last_seen) if previous else None,
            first_seen=previous.first_seen if previous is not None else now,
            last_seen=now,
            similar_identifier_count=similar_identifier_count,
            radio_types=tuple(sorted(
                set(previous.radio_types) | {BLE_RADIO}
                if previous is not None else {BLE_RADIO}
            )),
            discovery_source=_merged_discovery_source(
                previous.discovery_source if previous is not None else "", "system",
            ),
            class_of_device=(
                platform_metadata.get("class_of_device")
                or (previous.class_of_device if previous is not None else None)
            ),
            appearance=(
                platform_metadata.get("appearance")
                or (previous.appearance if previous is not None else None)
            ),
            address_type=address_type,
            payload_fingerprint=payload_fingerprint(
                advertisement_data.manufacturer_data,
                advertisement_data.service_data,
            ),
            baseline_status=(
                previous.baseline_status if previous is not None else "unavailable"
            ),
            profile_changed=previous.profile_changed if previous is not None else False,
            protocol_category=(
                protocol_hint.get("protocol_category")
                or (previous.protocol_category if previous is not None else "")
            ),
            protocol_type=(
                protocol_hint.get("protocol_type")
                or (previous.protocol_type if previous is not None else "")
            ),
            protocol_source=(
                protocol_hint.get("protocol_source")
                or (previous.protocol_source if previous is not None else "")
            ),
            protocol_confidence=(
                protocol_hint.get("protocol_confidence")
                or (previous.protocol_confidence if previous is not None else "")
            ),
            decode_state=(
                protocol_hint["decode_state"]
                if "decode_state" in protocol_hint
                else previous.decode_state if previous is not None else ""
            ),
            signature_watch=(
                protocol_hint.get("signature_watch") == "1"
                if "signature_watch" in protocol_hint
                else previous.signature_watch if previous is not None else False
            ),
            modalias=(
                platform_metadata.get("modalias")
                or (previous.modalias if previous is not None else "")
            ),
            hardware_vendor=(
                platform_metadata.get("hardware_vendor")
                or (previous.hardware_vendor if previous is not None else "")
            ),
            hardware_product=(
                platform_metadata.get("hardware_product")
                or (previous.hardware_product if previous is not None else "")
            ),
            hardware_source=(
                platform_metadata.get("hardware_source")
                or (previous.hardware_source if previous is not None else "")
            ),
            **signal,
        )
        observed.profile_fingerprint = _profile_fingerprint(observed)
        self._correlate_radios(observed)
        if self.history is not None and has_stable_persistent_identifier(observed):
            self.history.enrich(observed, classify=previous is None)
            observed.profile_fingerprint = _profile_fingerprint(observed)
        if has_coherent_persistent_identity(observed):
            self._observe_position(observed)
            if self.history is not None:
                self.history.remember(observed)
        self._devices[identifier] = self._apply_cached_device_information(observed)
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth advertisement callback failed", exc_info=True)

    def _on_usb_observation(self, observation: DiscoveryObservation) -> None:
        now = time.time()
        self.last_advertisement_at = now
        self.received_advertisements += 1
        self.observations_by_radio[observation.radio_type] += 1
        self.last_observation_by_radio[observation.radio_type] = now
        previous = self._devices.get(observation.identifier)
        name = observation.name
        if name == "<Unknown>" and previous is not None:
            name = previous.name
        signal = self._signal_fields(observation.identifier, observation.rssi)
        observed = BluetoothDevice(
            identifier=observation.identifier,
            name=name,
            rssi=observation.rssi,
            service_uuids=tuple(sorted(set(observation.service_uuids) | (
                set(previous.service_uuids) if previous is not None else set()
            ))),
            service_data_uuids=tuple(sorted(set(observation.service_data_uuids) | (
                set(previous.service_data_uuids) if previous is not None else set()
            ))),
            manufacturer_ids=tuple(sorted(set(observation.manufacturer_ids) | (
                set(previous.manufacturer_ids) if previous is not None else set()
            ))),
            manufacturer_data_bytes=max(
                observation.manufacturer_data_bytes,
                previous.manufacturer_data_bytes if previous is not None else 0,
            ),
            service_data_bytes=max(
                observation.service_data_bytes,
                previous.service_data_bytes if previous is not None else 0,
            ),
            tx_power=(
                observation.tx_power
                if observation.tx_power is not None
                else previous.tx_power if previous is not None else None
            ),
            advertisement_count=(previous.advertisement_count + 1) if previous else 1,
            advertisement_interval=(now - previous.last_seen) if previous else None,
            first_seen=previous.first_seen if previous is not None else now,
            last_seen=now,
            similar_identifier_count=(
                previous.similar_identifier_count if previous is not None else 1
            ),
            radio_types=tuple(sorted(
                set(previous.radio_types) | {observation.radio_type}
                if previous is not None else {observation.radio_type}
            )),
            discovery_source=_merged_discovery_source(
                previous.discovery_source if previous is not None else "", "usb-hci",
            ),
            class_of_device=observation.class_of_device or (
                previous.class_of_device if previous is not None else None
            ),
            page_scan_repetition_mode=observation.page_scan_repetition_mode or (
                previous.page_scan_repetition_mode if previous is not None else None
            ),
            clock_offset=observation.clock_offset or (
                previous.clock_offset if previous is not None else None
            ),
            appearance=(
                observation.appearance
                if observation.appearance is not None
                else previous.appearance if previous is not None else None
            ),
            address_type=(
                observation.address_type
                if observation.address_type != "unknown"
                else previous.address_type if previous is not None else "unknown"
            ),
            payload_fingerprint=(
                observation.payload_fingerprint
                or (previous.payload_fingerprint if previous is not None else "")
            ),
            baseline_status=(
                previous.baseline_status if previous is not None else "unavailable"
            ),
            profile_changed=previous.profile_changed if previous is not None else False,
            protocol_category=(
                observation.protocol_category
                or (previous.protocol_category if previous is not None else "")
            ),
            protocol_type=(
                observation.protocol_type
                or (previous.protocol_type if previous is not None else "")
            ),
            protocol_source=(
                observation.protocol_source
                or (previous.protocol_source if previous is not None else "")
            ),
            protocol_confidence=(
                observation.protocol_confidence
                or (previous.protocol_confidence if previous is not None else "")
            ),
            decode_state=(
                observation.decode_state
                if observation.decode_state or observation.signature_watch
                else previous.decode_state if previous is not None else ""
            ),
            signature_watch=(
                observation.signature_watch == "1"
                if observation.decode_state or observation.signature_watch
                else previous.signature_watch if previous is not None else False
            ),
            modalias=previous.modalias if previous is not None else "",
            hardware_vendor=previous.hardware_vendor if previous is not None else "",
            hardware_product=previous.hardware_product if previous is not None else "",
            hardware_source=previous.hardware_source if previous is not None else "",
            **signal,
        )
        observed.profile_fingerprint = _profile_fingerprint(observed)
        self._correlate_radios(observed)
        if self.history is not None and has_stable_persistent_identifier(observed):
            self.history.enrich(observed, classify=previous is None)
            observed.profile_fingerprint = _profile_fingerprint(observed)
        if has_coherent_persistent_identity(observed):
            self._observe_position(observed)
            if self.history is not None:
                self.history.remember(observed)
        self._devices[observation.identifier] = self._apply_cached_device_information(
            observed,
        )
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth observation callback failed", exc_info=True)

    def _correlate_radios(self, observed: BluetoothDevice) -> None:
        """Link, but never merge, Classic and BLE identities using cautious evidence."""
        matches: list[tuple[BluetoothDevice, str, tuple[str, ...]]] = []
        for candidate in self._devices.values():
            if candidate.identifier == observed.identifier:
                continue
            if set(candidate.radio_types) & set(observed.radio_types):
                continue
            evidence: list[str] = []
            observed_name = _correlation_name(observed.name)
            candidate_name = _correlation_name(candidate.name)
            if observed_name and observed_name == candidate_name:
                evidence.append("exact normalized name")
            shared_services = set(observed.service_uuids) & set(candidate.service_uuids)
            if shared_services:
                evidence.append("shared advertised/SDP service")
            if (
                observed.protocol_type
                and observed.protocol_type == candidate.protocol_type
            ):
                evidence.append("matching protocol profile")
            if abs(observed.last_seen - candidate.last_seen) <= 10:
                evidence.append("observed within 10 seconds")
            if abs(observed.rssi - candidate.rssi) <= 10:
                evidence.append("RSSI within 10 dB")
            strong_identity = any(
                item in evidence for item in (
                    "exact normalized name",
                    "shared advertised/SDP service",
                    "matching protocol profile",
                )
            )
            if not strong_identity or len(evidence) < 2:
                continue
            confidence = "high" if (
                "exact normalized name" in evidence and len(evidence) >= 3
            ) else "medium"
            matches.append((candidate, confidence, tuple(evidence)))
        if not matches:
            return
        observed.related_identifiers = tuple(
            sorted(candidate.identifier for candidate, _, _ in matches)
        )
        observed.correlation_confidence = (
            "high" if any(level == "high" for _, level, _ in matches) else "medium"
        )
        observed.correlation_evidence = tuple(sorted({
            item for _, _, evidence in matches for item in evidence
        }))
        for candidate, confidence, evidence in matches:
            candidate.related_identifiers = tuple(sorted(
                set(candidate.related_identifiers) | {observed.identifier}
            ))
            if confidence == "high" or not candidate.correlation_confidence:
                candidate.correlation_confidence = confidence
            candidate.correlation_evidence = tuple(sorted(
                set(candidate.correlation_evidence) | set(evidence)
            ))

    def _observe_position(self, device: BluetoothDevice) -> None:
        if self.location_store is None or self.fix_provider is None:
            return
        movement_m = self.movement_provider() if self.movement_provider else 20.0
        max_accuracy_m = self.accuracy_provider() if self.accuracy_provider else 20.0
        device.positions = self.location_store.observe(
            "bluetooth",
            device.identifier,
            self.fix_provider(),
            device.rssi,
            mobile=True,
            movement_m=movement_m,
            max_accuracy_m=max_accuracy_m,
        )

    def _signal_fields(self, identifier: str, rssi: int) -> dict[str, Any]:
        samples = self._rssi_history.setdefault(identifier, deque(maxlen=12))
        samples.append(rssi)
        average, minimum, maximum, count, trend = signal_summary(samples)
        return {
            "rssi_average": average,
            "rssi_min": minimum,
            "rssi_max": maximum,
            "rssi_samples": count,
            "rssi_trend": trend,
        }

    def usb_reservation_held(self, controller: UsbBluetoothController) -> bool:
        with self._usb_reservation_lock:
            return controller.instance_key in self._usb_reservations

    def _reserve_macos_controllers(
        self, controllers: list[UsbBluetoothController],
    ) -> None:
        """Claim dedicated USB controllers as soon as they enumerate.

        macOS reattaches its Bluetooth driver as soon as the interface is
        released, and a later detach then fails with the replug alert. Holding
        the interface from first sight — Classic-only and dual-mode — means a
        replug sticks instead of racing the OS until the scan button.
        """
        present = {controller.instance_key for controller in controllers}
        active = (
            self._usb_scanner.controller.instance_key
            if self._usb_scanner is not None else None
        )
        with self._usb_reservation_lock:
            stale = [
                key for key in self._usb_reservations
                if key not in present
            ]
            for key in stale:
                scanner = self._usb_reservations.pop(key, None)
                self._usb_not_claimed.discard(key)
                self._usb_claim_verified.discard(key)
                if scanner is None:
                    continue
                try:
                    scanner.release()
                except Exception:
                    pass
            for key in list(self._usb_not_claimed):
                if key not in present:
                    self._usb_not_claimed.discard(key)
            for controller in controllers:
                key = controller.instance_key
                if key in self._usb_reservations or key == active:
                    self._usb_not_claimed.discard(key)
                    continue
                scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
                if not hasattr(scanner, "reserve"):
                    continue
                try:
                    scanner.reserve()
                except Exception:
                    logger.debug(
                        "Could not reserve macOS Bluetooth USB controller",
                        exc_info=True,
                    )
                    self._usb_not_claimed.add(key)
                    self._usb_claim_verified.discard(key)
                    try:
                        scanner.release()
                    except Exception:
                        pass
                    continue
                self._usb_not_claimed.discard(key)
                self._usb_claim_verified.add(key)
                self._usb_reservations[key] = scanner

    def _probe_usb_claim_status(
        self, controllers: list[UsbBluetoothController],
    ) -> None:
        """One-shot claim probe for Linux/Windows splash status (macOS uses reserve)."""
        present = {controller.instance_key for controller in controllers}
        for key in list(self._usb_not_claimed):
            if key not in present:
                self._usb_not_claimed.discard(key)
        self._usb_claim_verified.intersection_update(present)
        reserved = set(self._usb_reservations.keys())
        if self._usb_scanner is not None:
            reserved.add(self._usb_scanner.controller.instance_key)
        for controller in controllers:
            key = controller.instance_key
            if key in reserved:
                self._usb_not_claimed.discard(key)
                self._usb_claim_verified.add(key)
                continue
            if key in self._usb_claim_verified and key not in self._usb_not_claimed:
                continue
            scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
            if not hasattr(scanner, "reserve"):
                continue
            try:
                scanner.reserve()
            except Exception:
                logger.debug("Bluetooth USB claim probe failed", exc_info=True)
                self._usb_not_claimed.add(key)
                self._usb_claim_verified.discard(key)
                try:
                    scanner.release()
                except Exception:
                    pass
                continue
            try:
                scanner.release()
            except Exception:
                pass
            self._usb_not_claimed.discard(key)
            self._usb_claim_verified.add(key)


def _profile_fingerprint(device: BluetoothDevice) -> str:
    return profile_fingerprint(
        name=device.name,
        address_type=device.address_type,
        service_uuids=device.service_uuids,
        service_data_uuids=device.service_data_uuids,
        manufacturer_ids=device.manufacturer_ids,
        class_of_device=device.class_of_device,
        appearance=device.appearance,
        protocol_type=device.protocol_type,
        decode_state=device.decode_state,
        modalias=device.modalias,
        hardware_product=device.hardware_product,
    )


def _correlation_name(name: str) -> str:
    normalized = "".join(character for character in name.casefold() if character.isalnum())
    if normalized in {"", "unknown", "unnamed", "bluetoothdevice"}:
        return ""
    return normalized if len(normalized) >= 4 else ""


def _is_private_identifier(identifier: str, address_type: str) -> bool:
    return address_type in {
        "resolvable-private",
        "non-resolvable-private",
        "platform-opaque",
        "anonymous",
    }


def _merged_discovery_source(previous: str, current: str) -> str:
    sources = set(previous.split("+")) if previous else set()
    sources.add(current)
    return "+".join(source for source in ("system", "usb-hci") if source in sources)

