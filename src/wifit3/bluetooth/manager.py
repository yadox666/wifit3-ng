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
from typing import Any, Callable, Sequence


from bleak import BleakClient, BleakScanner

from wifit3.bluetooth.analytics import (
    bluez_platform_metadata,
    normalize_ble_mac,
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
    GATT_IDENTITY_STORAGE_FIELDS,
    compact_uuid,
    device_information_fields,
    merge_gatt_identity_fields,
)
from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.observe.product_catalog import (
    CatalogHit,
    choose_catalog,
    device_fields,
    match_bluetooth,
    supplement_catalog_hit,
    with_protocol_live,
)
from wifit3.bluetooth import routing
from wifit3.bluetooth.routing import Route, UsbRadio, route_classic, route_le
from wifit3.bluetooth import scan_modes
from wifit3.bluetooth.sources import (
    OS_SOURCE_ID,
    merge_sources,
    source_chip_label,
    usb_source_id,
)
from wifit3.bluetooth.usb_hci import (
    UsbBluetoothController,
    UsbBluetoothError,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)
from wifit3.models import BluetoothDevice, BluetoothInspection, LocationFix
from wifit3.models.location import positions_digest
from wifit3.models.bluetooth_device import (
    BLE_RADIO,
    CLASSIC_RADIO,
    should_persist_bluetooth_observation,
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


def _guess_os_ble_backend() -> tuple[str, str]:
    """Best-known (backend, manufacturer) for this OS without a scanner instance.

    Bleak's backend is 1:1 with the platform, so this matches what
    ``_os_ble_backend_info`` will report once actually probed. Used for the
    startup placeholder so its name text is already correct and the adapter
    boxes never have to resize once the real probe completes.
    """
    if sys.platform == "darwin":
        return "CoreBluetooth", "Apple"
    if sys.platform.startswith("win"):
        return "WinRT", "Microsoft"
    if sys.platform.startswith("linux"):
        return "BlueZ", ""
    return "Bleak", ""


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
    """Describe the system BLE endpoint and return a BD_ADDR when one is exposed.

    Address availability is platform-dependent, so the portable path is tried
    first and the OS-specific fallback runs only where it is actually needed:

    * **Linux (BlueZ) / Windows (WinRT):** Bleak's public, cross-platform
      ``BLEDevice.address`` already *is* the device BD_ADDR (MAC). It is used
      directly - no backend-specific code runs on these platforms.
    * **macOS (CoreBluetooth):** the public identifier is a per-host UUID, not a
      MAC; macOS hides the hardware address on purpose. Only on macOS do we fall
      back to :func:`_corebluetooth_bd_addr`, which recovers the BD_ADDR through
      Bleak's raw backend handle when the OS still exposes it.
    """
    address = str(getattr(platform_device, "address", "") or "")
    if is_bluetooth_bd_addr(address):
        # Linux/Windows: the portable Bleak address is already the MAC.
        return f"system address={address}", address
    # Any non-MAC public address means the OS masks the hardware address.
    uuid_label = address or "unavailable"
    if sys.platform != "darwin":
        # No portable way to recover a MAC here; report the masked identifier.
        return f"system identifier={uuid_label}; MAC unavailable", None
    return _corebluetooth_bd_addr(platform_device, uuid_label)


def _corebluetooth_bd_addr(
    platform_device: Any, uuid_label: str,
) -> tuple[str, str | None]:
    """macOS-only: resolve a BD_ADDR hidden behind CoreBluetooth's per-host UUID.

    Uses the undocumented ``retrieveAddressForPeripheral_`` selector reachable on
    Bleak's raw backend handle (``platform_device.details``). This is **not** part
    of Bleak's public API and may stop working in a future macOS release, so every
    step is probed defensively and any failure degrades to ``MAC unavailable``
    rather than raising.
    """
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
        if not os_ble_enabled:
            self.os_ble_status = self._disabled_os_ble_status()
        else:
            # Guess the backend/manufacturer from the OS so the placeholder's name
            # text already matches what the real probe will report - otherwise the
            # adapter boxes resize once CHECKING resolves to the real backend.
            guess_backend, guess_manufacturer = _guess_os_ble_backend()
            self.os_ble_status = OsBleSourceStatus(
                True,
                None,
                "CHECKING",
                guess_backend,
                platform.system(),
                guess_manufacturer,
                "System adapter",
                "Checking operating-system BLE availability",
            )
        self._scanner = None
        # ``_usb_scanner`` is the *operational* scanner (labs/connect/SDP use it,
        # chosen per-operation by the router). ``_usb_scanners`` is the registry
        # of every concurrently-active discovery scanner, keyed by instance_key.
        self._usb_scanner = None
        self._usb_scanners: dict[tuple, Any] = {}
        self._usb_reservations: dict[tuple, Any] = {}
        self._known_controllers: list[UsbBluetoothController] = []
        self._usb_source_ids: dict[tuple, str] = {}
        # Per-controller scan mode (keyed by instance_key); default AUTO.
        self._usb_scan_mode: dict[tuple, str] = {}
        self._usb_not_claimed: set[tuple] = set()
        self._usb_claim_verified: set[tuple] = set()
        self._usb_reservation_lock = threading.Lock()
        self._resume_usb_controller: UsbBluetoothController | None = None
        self._resume_usb_controllers: list[UsbBluetoothController] = []
        self._devices: dict[str, BluetoothDevice] = {}
        self._device_information: dict[str, dict[str, str]] = {}
        self._gatt_services_enriched: set[str] = set()
        self._last_manufacturer_data: dict[str, dict[int, bytes]] = {}
        self._last_service_data: dict[str, dict[str, bytes]] = {}
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
        self.focus_connection_source: str = ""
        self.focus_connection_route: Route | None = None
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
        return self._scanner is not None or self.is_usb_scanning

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
        device = self._resolve_bluetooth_device(identifier)
        if device is not None:
            # Prefer the Classic-capable controller that observed this row.
            classic_route = self._route_classic(device)
            if classic_route.transport == routing.USB:
                routed = self._scanner_for_source(classic_route.source_id)
                if routed is not None:
                    self._usb_scanner = routed
        await self._ensure_usb_scanner_ready()
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
            self._persist_device(device)
            for callback in list(self._advertisement_callbacks):
                try:
                    callback(device)
                except Exception:
                    logger.debug("Bluetooth SDP callback failed", exc_info=True)
        return services

    @property
    def is_usb_scanning(self) -> bool:
        return any(
            getattr(scanner, "is_scanning", True)
            for scanner in self._all_usb_scanners()
        )

    @property
    def is_os_ble_scanning(self) -> bool:
        return self._scanner is not None

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
        chipsets: list[str] = []
        for scanner in self._all_usb_scanners():
            chipset = getattr(getattr(scanner, "controller", None), "chipset", None)
            if chipset and chipset not in chipsets:
                chipsets.append(chipset)
        if chipsets:
            parts = list(chipsets)
            if self._scanner is not None:
                parts.append("OS BLE")
            return " + ".join(parts)
        scanner = self._scanner
        return scanner.__class__.__name__ if scanner is not None else "Bleak"

    def devices(self) -> list[BluetoothDevice]:
        return list(self._devices.values())

    def active_radio_types(self) -> tuple[str, ...]:
        radios = set()
        if self._scanner is not None or self.connection is not None:
            radios.add(BLE_RADIO)
        for scanner in self._all_usb_scanners():
            controller = getattr(scanner, "controller", None)
            if controller is None:
                continue
            # Reflect the *effective* scan toggle when the scanner exposes it, so
            # a dongle restricted to Classic-only stops advertising BLE here.
            le_on = getattr(
                scanner, "_usb_le_scan_enabled", getattr(controller, "supports_le", False)
            )
            classic_on = getattr(
                scanner,
                "_usb_classic_scan_enabled",
                getattr(controller, "supports_classic", False),
            )
            if getattr(controller, "supports_le", False) and le_on:
                radios.add(BLE_RADIO)
            if getattr(controller, "supports_classic", False) and classic_on:
                radios.add(CLASSIC_RADIO)
        return tuple(radio for radio in (BLE_RADIO, CLASSIC_RADIO) if radio in radios)

    def backend_name_for_radio(self, radio_type: str) -> str:
        for scanner in self._all_usb_scanners():
            controller = getattr(scanner, "controller", None)
            if controller is None:
                continue
            if (
                radio_type == CLASSIC_RADIO and getattr(controller, "supports_classic", False)
                or radio_type == BLE_RADIO and getattr(controller, "supports_le", False)
            ):
                return controller.chipset
        scanner = self._scanner
        return scanner.__class__.__name__ if scanner is not None else "Bleak"

    def connection_transport_label(self) -> str:
        """Human label for the radio that performed the active Focus connection."""
        route = self.focus_connection_route
        if route is None or not route.source_id:
            return ""
        if route.source_id == OS_SOURCE_ID:
            return self.os_ble_status.backend or "OS BLE"
        scanner = self._usb_scanner
        chipset = (
            getattr(scanner.controller, "chipset", "USB")
            if scanner is not None else "USB"
        )
        return f"{chipset} USB"

    def is_usb_radio(self, radio_type: str) -> bool:
        for scanner in self._all_usb_scanners():
            controller = getattr(scanner, "controller", None)
            if controller is None:
                continue
            if (
                radio_type == CLASSIC_RADIO and getattr(controller, "supports_classic", False)
                or radio_type == BLE_RADIO and getattr(controller, "supports_le", False)
            ):
                return True
        return False

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
        self._remember_known_controllers(controllers)
        return controllers

    def _remember_known_controllers(
        self, controllers: list[UsbBluetoothController],
    ) -> None:
        """Track the detected controller set so source ids get stable ordinals."""
        keys = [c.instance_key for c in controllers]
        if keys != [c.instance_key for c in self._known_controllers]:
            self._known_controllers = list(controllers)
            # Recompute lazily; a newly-arrived sibling can change ordinals.
            self._usb_source_ids.clear()

    def _source_id_for_controller(
        self, controller: UsbBluetoothController,
    ) -> str:
        """Stable ``usb:<slug>`` id for a controller (cached, non-blocking)."""
        key = controller.instance_key
        cached = self._usb_source_ids.get(key)
        if cached is not None:
            return cached
        pool = self._known_controllers or [controller]
        source_id = usb_source_id(controller, pool)
        self._usb_source_ids[key] = source_id
        return source_id

    def _all_usb_scanners(self) -> list[Any]:
        """Every active USB scanner: the registry plus the operational primary.

        Tests (and some legacy paths) set ``_usb_scanner`` directly without the
        registry, so it is always included.
        """
        scanners = list(self._usb_scanners.values())
        if self._usb_scanner is not None and self._usb_scanner not in scanners:
            scanners.append(self._usb_scanner)
        return scanners

    def _register_usb_scanner(self, scanner: Any) -> None:
        controller = getattr(scanner, "controller", None)
        key = getattr(controller, "instance_key", None)
        if key is not None:
            self._usb_scanners[key] = scanner
        self._select_primary_usb_scanner(prefer=scanner)

    def _select_primary_usb_scanner(self, *, prefer: Any = None) -> None:
        """Pick the operational scanner: LE-capable preferred for GATT work."""
        candidates = self._all_usb_scanners()
        if not candidates:
            self._usb_scanner = None
            return
        if prefer is not None and getattr(
            getattr(prefer, "controller", None), "supports_le", False,
        ):
            self._usb_scanner = prefer
            return
        for scanner in candidates:
            if getattr(getattr(scanner, "controller", None), "supports_le", False):
                self._usb_scanner = scanner
                return
        self._usb_scanner = prefer if prefer is not None else candidates[0]

    def _scanner_for_source(self, source_id: str) -> Any:
        for scanner in self._all_usb_scanners():
            controller = getattr(scanner, "controller", None)
            if controller is None or not hasattr(controller, "instance_key"):
                continue
            if self._source_id_for_controller(controller) == source_id:
                return scanner
        return None

    def _usb_observation_callback(
        self, controller: UsbBluetoothController,
    ) -> Callable[[DiscoveryObservation], None]:
        return lambda observation: self._on_usb_observation(observation, controller)

    def _active_usb_radios(self) -> list[UsbRadio]:
        """USB radios the router can choose from (all active controllers)."""
        radios: list[UsbRadio] = []
        seen: set[str] = set()
        for scanner in self._all_usb_scanners():
            controller = getattr(scanner, "controller", None)
            if controller is None:
                continue
            source_id = (
                self._source_id_for_controller(controller)
                if hasattr(controller, "instance_key") else "usb"
            )
            if source_id in seen:
                continue
            seen.add(source_id)
            radios.append(UsbRadio(
                source_id=source_id,
                supports_classic=bool(getattr(controller, "supports_classic", True)),
                supports_le=bool(getattr(controller, "supports_le", True)),
            ))
        return radios

    def _route_le(self, device: BluetoothDevice) -> Route:
        return route_le(
            device,
            os_active=self._scanner is not None,
            usb_radios=self._active_usb_radios(),
        )

    def _route_classic(self, device: BluetoothDevice) -> Route:
        return route_classic(device, usb_radios=self._active_usb_radios())

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
        active = {
            getattr(scanner.controller, "instance_key", None)
            for scanner in self._all_usb_scanners()
            if getattr(scanner, "controller", None) is not None
        }
        with self._usb_reservation_lock:
            if key in self._usb_reservations or key in active:
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
            message = str(exc) or type(exc).__name__
            if sys.platform == "darwin":
                message = (
                    f"{message}. macOS still owns this adapter. Turn Bluetooth "
                    "off in System Settings, then click ↻ again (or unplug and "
                    "replug the dedicated adapter while Bluetooth is off)."
                )
            return False, message
        with self._usb_reservation_lock:
            self._usb_not_claimed.discard(key)
            self._usb_claim_verified.add(key)
            self._usb_reservations[key] = scanner
        return True, "USB Bluetooth adapter claimed for wifit3"

    def _disabled_os_ble_status(self) -> OsBleSourceStatus:
        """Keep the detected backend/manufacturer/adapter when disabling.

        Otherwise the picker flips from e.g. "Apple CoreBluetooth" to a generic
        "Bleak" every time the OS BLE checkbox is unchecked.
        """
        previous = getattr(self, "os_ble_status", None)
        if previous is not None:
            backend, manufacturer, adapter = (
                previous.backend, previous.manufacturer, previous.adapter,
            )
        else:
            backend, manufacturer = _guess_os_ble_backend()
            adapter = "System adapter"
        return OsBleSourceStatus(
            False,
            None,
            "APP-DISABLED",
            backend,
            platform.system(),
            manufacturer,
            adapter,
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
        if not self._usb_scanners:
            self._resume_usb_controller = None
        self.scan_started_at = time.time()
        self._start_device_information_sweep()

    async def start_usb(self, controller: UsbBluetoothController) -> None:
        if self.is_scanning:
            return
        await self._activate_usb(controller, pair_os_ble=True)

    def _usb_controller_active(self, controller: UsbBluetoothController) -> bool:
        key = getattr(controller, "instance_key", None)
        return key is not None and key in self._usb_scanners

    def set_usb_scan_mode(
        self, controller: UsbBluetoothController, mode: str
    ) -> None:
        """Record the user's scan-mode choice for a controller.

        Applied when the controller is (re)activated, and immediately to a live
        scanner so cycling the picker chip changes real discovery behavior.
        """
        self._usb_scan_mode[controller.instance_key] = mode
        for scanner in self._all_usb_scanners():
            scanner_controller = getattr(scanner, "controller", None)
            if scanner_controller is None:
                continue
            if scanner_controller.instance_key != controller.instance_key:
                continue
            if hasattr(scanner, "set_scan_radios"):
                le_on, classic_on = scan_modes.effective_scan_radios(
                    controller, mode, os_ble_active=self._os_ble_active_now()
                )
                scanner.set_scan_radios(le=le_on, classic=classic_on)

    def usb_scan_mode(self, controller: UsbBluetoothController) -> str:
        return self._usb_scan_mode.get(controller.instance_key, scan_modes.AUTO)

    def _os_ble_active_now(self) -> bool:
        return self._scanner is not None

    async def start_parallel(
        self,
        *,
        os_ble: bool,
        controller: UsbBluetoothController | None = None,
        controllers: Sequence[UsbBluetoothController] | None = None,
    ) -> list[str]:
        """Start OS BLE and one or more USB controllers together.

        One radio failing leaves the others running. ``controllers`` activates
        several dedicated dongles concurrently; ``controller`` is the legacy
        single-dongle form.
        """
        failures: list[str] = []
        targets: list[UsbBluetoothController] = []
        if controllers is not None:
            targets.extend(controllers)
        elif controller is not None:
            targets.append(controller)
        for target in targets:
            if self._usb_controller_active(target):
                continue
            try:
                await self._activate_usb(
                    target, pair_os_ble=False, os_ble_active_hint=os_ble
                )
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
        os_ble_active_hint: bool = False,
    ) -> None:
        system_scanner = None
        if pair_os_ble and self.os_ble_enabled and self._scanner is None:
            system_scanner = self._scanner_factory(
                detection_callback=self._on_advertisement,
            )
        with self._usb_reservation_lock:
            usb_scanner = self._usb_reservations.pop(controller.instance_key, None)
        if usb_scanner is None:
            usb_scanner = self._usb_scanner_factory(
                controller, self._usb_observation_callback(controller),
            )
        os_ble_active = (
            system_scanner is not None
            or self._scanner is not None
            or os_ble_active_hint
        )
        mode = self._usb_scan_mode.get(controller.instance_key, scan_modes.AUTO)
        if hasattr(usb_scanner, "set_scan_radios"):
            le_on, classic_on = scan_modes.effective_scan_radios(
                controller, mode, os_ble_active=os_ble_active
            )
            usb_scanner.set_scan_radios(le=le_on, classic=classic_on)
        elif system_scanner is not None and controller.supports_le:
            # Legacy/fake scanner without the richer radio toggle: keep the
            # original "OS runs BLE" behavior.
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
        self._register_usb_scanner(usb_scanner)
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
        if controller not in self._resume_usb_controllers:
            self._resume_usb_controllers.append(controller)
        self.mark_usb_claimed(controller)
        self.scan_started_at = time.time()
        self._start_device_information_sweep()

    async def resume_scan(self) -> None:
        resume = list(self._resume_usb_controllers) or (
            [self._resume_usb_controller]
            if self._resume_usb_controller is not None else []
        )
        if resume:
            # Mirror the legacy single-dongle resume: re-pair OS BLE too.
            await self.start_parallel(os_ble=self.os_ble_enabled, controllers=resume)
        else:
            await self.start()

    async def stop(self) -> None:
        await self._stop_device_information_sweep()
        scanner, self._scanner = self._scanner, None
        usb_scanners = self._all_usb_scanners()
        self._usb_scanners = {}
        self._usb_scanner = None
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
        for usb_scanner in usb_scanners:
            keep_reserved = (
                sys.platform == "darwin"
                and hasattr(usb_scanner, "pause")
            )
            try:
                if keep_reserved:
                    await usb_scanner.pause()
                    key = getattr(usb_scanner.controller, "instance_key", None)
                    if key is not None:
                        with self._usb_reservation_lock:
                            self._usb_reservations[key] = usb_scanner
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
        route = self._route_le(device)
        self.focus_connection_source = route.source_id
        self.focus_connection_route = route
        if route.transport == routing.USB:
            routed = self._scanner_for_source(route.source_id)
            if routed is not None:
                self._usb_scanner = routed
            if self._usb_scanner is not None:
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

    def _persist_device(
        self,
        device: BluetoothDevice,
        *,
        force: bool = False,
        manufacturer_data: dict[int, bytes] | None = None,
        service_data: dict[str, bytes] | None = None,
    ) -> None:
        if self.history is None:
            return
        identifier = device.identifier
        mfg = manufacturer_data
        if mfg is None:
            mfg = self._last_manufacturer_data.get(identifier)
        svc = service_data
        if svc is None:
            svc = self._last_service_data.get(identifier)
        try:
            self.history.remember(
                device,
                force=force,
                manufacturer_data=mfg,
                service_data=svc,
            )
        except Exception:
            logger.debug("Bluetooth history persist failed", exc_info=True)

    def _cache_device_information(self, inspection) -> None:
        """Cache GATT identity and discovered services from a live inspection.

        The exact model string is only available from the Device Information
        Service (0x180A) after a GATT connection, so it is stored per identifier
        and surfaced on the scanner row the next time the table repaints. Service
        discovery also reveals UUIDs omitted from the advertising packet.
        """
        identifier = getattr(getattr(inspection, "device", None), "identifier", None)
        if not identifier:
            return
        info = device_information_fields(inspection)
        discovered_services = tuple(sorted({
            str(service.uuid).casefold()
            for service in getattr(inspection, "services", ())
            if str(getattr(service, "uuid", "") or "").strip()
        }))
        if discovered_services:
            self._gatt_services_enriched.add(identifier)
        if not info and not discovered_services:
            return
        previous_info = self._device_information.get(identifier, {})
        merged = {**previous_info, **info}
        learned_identity = merged != previous_info
        self._device_information[identifier] = merged
        existing = self._devices.get(identifier)
        if existing is not None:
            updated = merge_gatt_identity_fields(existing, merged)
            merged_services = tuple(sorted({
                *updated.service_uuids,
                *discovered_services,
            }))
            learned_services = merged_services != updated.service_uuids
            if learned_services:
                updated = replace(updated, service_uuids=merged_services)
            updated = self._refresh_catalog_from_gatt(updated)
            self._devices[identifier] = updated
            if learned_identity or learned_services:
                self._persist_device(updated, force=True)

    def _apply_cached_device_information(self, device):
        """Overlay cached Device Information onto a freshly observed device."""
        cached = self._device_information.get(device.identifier)
        if not cached:
            return device
        return merge_gatt_identity_fields(device, cached)

    def _observation_with_gatt_identity(
        self,
        device: BluetoothDevice,
        previous: BluetoothDevice | None,
    ) -> BluetoothDevice:
        """Carry GATT reads from memory, cache, and SQLite before persistence."""
        merged = merge_gatt_identity_fields(device, previous)
        return self._apply_cached_device_information(merged)

    def _seed_gatt_cache_from_device(self, device: BluetoothDevice) -> None:
        payload = {
            field: str(getattr(device, field, "") or "").strip()
            for field in GATT_IDENTITY_STORAGE_FIELDS
            if str(getattr(device, field, "") or "").strip()
        }
        if not payload:
            return
        identifier = device.identifier
        self._device_information[identifier] = {
            **self._device_information.get(identifier, {}),
            **payload,
        }

    def _resolve_ble_mac(
        self,
        identifier: str,
        platform_device: Any | None,
        *,
        previous: BluetoothDevice | None = None,
    ) -> str:
        mac = ""
        if platform_device is not None:
            _identity, mac = _platform_ble_identity(platform_device)
            if mac:
                self._platform_observed_macs[identifier] = mac
        if not mac:
            mac = normalize_ble_mac(identifier)
        if not mac and previous is not None:
            mac = normalize_ble_mac(previous.ble_mac)
        if not mac:
            mac = normalize_ble_mac(self._platform_observed_macs.get(identifier, ""))
        return mac

    @staticmethod
    def _apply_supplemental_catalog(device: BluetoothDevice) -> BluetoothDevice:
        if device.catalog_family_id or device.catalog_labels or device.catalog_class:
            return device
        extra = supplement_catalog_hit(CatalogHit(), device)
        if not extra.present:
            return device
        return replace(device, **device_fields(extra))

    def _refresh_catalog_from_gatt(self, device: BluetoothDevice) -> BluetoothDevice:
        if device.catalog_family_id:
            return device
        manufacturer_data = self._last_manufacturer_data.get(device.identifier, {})
        service_data = self._last_service_data.get(device.identifier, {})
        fresh_catalog = with_protocol_live(
            match_bluetooth(
                manufacturer_data,
                service_data,
                device.service_uuids,
                name=device.name,
                mac=device.identifier,
                gatt_source=device,
            ),
            device.protocol_type,
            device.decode_state or "",
        )
        catalog = choose_catalog(fresh_catalog, device, name=device.name)
        if not catalog.present:
            catalog = supplement_catalog_hit(catalog, device)
        if not catalog.present:
            return device
        return replace(device, **device_fields(catalog))

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
            return f"sweep off - {reason}"
        if getattr(device, "approximate_group", False):
            return "unavailable - privacy group of rotating identifiers"
        if BLE_RADIO not in getattr(device, "radio_types", ()):
            return "unavailable - Classic only, no BLE GATT endpoint"
        if not self._enrichment_usb_le_active() and not getattr(
            device, "is_connectable_with_bleak", True,
        ):
            return "unavailable - not a system BLE endpoint"
        if self._enrichment_transport_for(device) == "none":
            return (
                "unavailable - OS UUID only; dongle needs a MAC or enable OS BLE "
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
                "attempted - no Device Information service or connection failed"
                + suffix
            )
        return "pending - queued for background read" + suffix

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

    def _device_information_candidates(self) -> list[BluetoothDevice]:
        now = time.time()
        candidates: list[BluetoothDevice] = []
        for device in list(self._devices.values()):
            if (
                device.identifier in self._device_information
                and device.identifier in self._gatt_services_enriched
            ):
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
        return self._route_le(device).transport

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
        manufacturer_data = dict(advertisement_data.manufacturer_data or {})
        service_data = dict(advertisement_data.service_data or {})
        if manufacturer_data:
            self._last_manufacturer_data[identifier] = manufacturer_data
        if service_data:
            self._last_service_data[identifier] = service_data
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
        ble_mac = self._resolve_ble_mac(identifier, device, previous=previous)
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
        gatt_source = (
            self._apply_cached_device_information(previous)
            if previous is not None
            else None
        )
        fresh_catalog = with_protocol_live(
            match_bluetooth(
                advertisement_data.manufacturer_data,
                advertisement_data.service_data,
                advertisement_data.service_uuids or (),
                name=name,
                mac=ble_mac or identifier,
                gatt_source=gatt_source,
            ),
            protocol_hint.get("protocol_type", ""),
            protocol_hint.get("decode_state", ""),
        )
        catalog = choose_catalog(fresh_catalog, previous, name=name)
        observed = BluetoothDevice(
            identifier=identifier,
            ble_mac=ble_mac,
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
            observation_sources=merge_sources(
                previous.observation_sources if previous is not None else (),
                OS_SOURCE_ID,
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
                (
                    protocol_hint.get("signature_watch") == "1"
                    if "signature_watch" in protocol_hint
                    else previous.signature_watch if previous is not None else False
                )
                or bool(fresh_catalog.attention)
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
        observed = replace(observed, **device_fields(catalog))
        observed = self._apply_supplemental_catalog(observed)
        if previous is not None and previous.catalog_family_id:
            observed = replace(observed, catalog_family_id=previous.catalog_family_id)
        observed.profile_fingerprint = _profile_fingerprint(observed)
        self._correlate_radios(observed)
        observed = self._observation_with_gatt_identity(observed, previous)
        if self.history is not None:
            self.history.enrich(
                observed,
                classify=previous is None and has_stable_persistent_identifier(observed),
            )
            observed.profile_fingerprint = _profile_fingerprint(observed)
            observed = self._observation_with_gatt_identity(observed, previous)
            self._seed_gatt_cache_from_device(observed)
        observed = self._refresh_catalog_from_gatt(observed)
        observed = self._apply_supplemental_catalog(observed)
        if should_persist_bluetooth_observation(observed):
            prior_gps = positions_digest(
                previous.positions if previous is not None else [],
            )
            if has_stable_persistent_identifier(observed):
                self._observe_position(observed)
            force_persist = positions_digest(observed.positions) != prior_gps
            self._persist_device(
                observed,
                force=force_persist,
                manufacturer_data=manufacturer_data,
                service_data=service_data,
            )
        self._devices[identifier] = observed
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth advertisement callback failed", exc_info=True)

    def _on_usb_observation(
        self,
        observation: DiscoveryObservation,
        controller: UsbBluetoothController | None = None,
    ) -> None:
        now = time.time()
        source_controller = controller
        if source_controller is None and self._usb_scanner is not None:
            source_controller = self._usb_scanner.controller
        usb_source = (
            self._source_id_for_controller(source_controller)
            if source_controller is not None
            and hasattr(source_controller, "instance_key")
            else "usb"
        )
        self.last_advertisement_at = now
        self.received_advertisements += 1
        self.observations_by_radio[observation.radio_type] += 1
        self.last_observation_by_radio[observation.radio_type] = now
        previous = self._devices.get(observation.identifier)
        platform_device = self._platform_devices.get(observation.identifier)
        ble_mac = self._resolve_ble_mac(
            observation.identifier,
            platform_device,
            previous=previous,
        )
        name = observation.name
        if name == "<Unknown>" and previous is not None:
            name = previous.name
        signal = self._signal_fields(observation.identifier, observation.rssi)
        fresh_catalog = CatalogHit(
            labels=tuple(observation.catalog_labels),
            catalog_class=observation.catalog_class,
            notes=observation.catalog_notes,
            attention=observation.catalog_attention,
            live=observation.catalog_live,
            live_strong=observation.catalog_live_strong,
            sentence=observation.catalog_sentence,
        )
        catalog = choose_catalog(fresh_catalog, previous, name=name)
        observed = BluetoothDevice(
            identifier=observation.identifier,
            ble_mac=ble_mac,
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
            observation_sources=merge_sources(
                previous.observation_sources if previous is not None else (),
                usb_source,
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
                (
                    observation.signature_watch == "1"
                    if observation.decode_state or observation.signature_watch
                    else previous.signature_watch if previous is not None else False
                )
                or bool(fresh_catalog.attention)
            ),
            modalias=previous.modalias if previous is not None else "",
            hardware_vendor=previous.hardware_vendor if previous is not None else "",
            hardware_product=previous.hardware_product if previous is not None else "",
            hardware_source=previous.hardware_source if previous is not None else "",
            **signal,
        )
        observed = replace(observed, **device_fields(catalog))
        observed = self._apply_supplemental_catalog(observed)
        if previous is not None and previous.catalog_family_id:
            observed = replace(observed, catalog_family_id=previous.catalog_family_id)
        observed.profile_fingerprint = _profile_fingerprint(observed)
        self._correlate_radios(observed)
        observed = self._observation_with_gatt_identity(observed, previous)
        if self.history is not None:
            self.history.enrich(
                observed,
                classify=previous is None and has_stable_persistent_identifier(observed),
            )
            observed.profile_fingerprint = _profile_fingerprint(observed)
            observed = self._observation_with_gatt_identity(observed, previous)
            self._seed_gatt_cache_from_device(observed)
        observed = self._refresh_catalog_from_gatt(observed)
        observed = self._apply_supplemental_catalog(observed)
        if should_persist_bluetooth_observation(observed):
            prior_gps = positions_digest(
                previous.positions if previous is not None else [],
            )
            if has_stable_persistent_identifier(observed):
                self._observe_position(observed)
            usb_mfg = dict(observation.manufacturer_data) if observation.manufacturer_data else None
            usb_svc = dict(observation.service_data) if observation.service_data else None
            if usb_mfg:
                self._last_manufacturer_data[observation.identifier] = usb_mfg
            if usb_svc:
                self._last_service_data[observation.identifier] = usb_svc
            self._persist_device(
                observed,
                force=positions_digest(observed.positions) != prior_gps,
                manufacturer_data=usb_mfg,
                service_data=usb_svc,
            )
        self._devices[observation.identifier] = observed
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
        observed.correlation_links = tuple(sorted(
            (
                candidate.identifier,
                confidence,
                tuple(sorted(evidence)),
            )
            for candidate, confidence, evidence in matches
        ))
        for candidate, confidence, evidence in matches:
            candidate.related_identifiers = tuple(sorted(
                set(candidate.related_identifiers) | {observed.identifier}
            ))
            if confidence == "high" or not candidate.correlation_confidence:
                candidate.correlation_confidence = confidence
            candidate.correlation_evidence = tuple(sorted(
                set(candidate.correlation_evidence) | set(evidence)
            ))
            links = {
                identifier: (level, link_evidence)
                for identifier, level, link_evidence in candidate.correlation_links
            }
            links[observed.identifier] = (
                confidence,
                tuple(sorted(evidence)),
            )
            candidate.correlation_links = tuple(sorted(
                (
                    identifier,
                    level,
                    link_evidence,
                )
                for identifier, (level, link_evidence) in links.items()
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
        the interface from first sight - Classic-only and dual-mode - means a
        replug sticks instead of racing the OS until the scan button.
        """
        present = {controller.instance_key for controller in controllers}
        active = {
            getattr(scanner.controller, "instance_key", None)
            for scanner in self._all_usb_scanners()
            if getattr(scanner, "controller", None) is not None
        }
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
                if key in self._usb_reservations or key in active:
                    self._usb_not_claimed.discard(key)
                    continue
                scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
                if not hasattr(scanner, "reserve"):
                    continue
                try:
                    scanner.reserve()
                except Exception as initial_exc:
                    logger.debug(
                        "Initial macOS Bluetooth USB reservation failed; trying OS reclaim",
                        exc_info=True,
                    )
                    try:
                        # Closing the partial claim before recovery matters for
                        # RTL8761: otherwise its stale libusb handle can keep the
                        # retry from claiming the interface it just released.
                        scanner.release()
                    except Exception:
                        pass
                    try:
                        if hasattr(scanner, "reclaim_from_os"):
                            scanner.reclaim_from_os()
                        else:
                            scanner.reserve(recover=True)
                    except Exception:
                        logger.debug(
                            "Could not reclaim macOS Bluetooth USB controller",
                            exc_info=True,
                        )
                        self._usb_not_claimed.add(key)
                        self._usb_claim_verified.discard(key)
                        try:
                            scanner.release()
                        except Exception:
                            pass
                        continue
                    logger.info(
                        "Reclaimed macOS Bluetooth USB controller %s after initial claim failure: %s",
                        controller.label,
                        initial_exc,
                    )
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
        for scanner in self._all_usb_scanners():
            controller_key = getattr(
                getattr(scanner, "controller", None), "instance_key", None,
            )
            if controller_key is not None:
                reserved.add(controller_key)
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

