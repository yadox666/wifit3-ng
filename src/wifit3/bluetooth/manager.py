"""OS-backed Bluetooth Low Energy discovery."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import replace
from typing import Any, Callable

from bleak import BleakClient, BleakScanner

from wifit3.bluetooth.analytics import (
    bluez_platform_metadata,
    payload_fingerprint,
    platform_address_type,
    profile_fingerprint,
    protocol_type_hint,
    signal_summary,
)
from wifit3.bluetooth.connection import BluetoothConnection, BluetoothConnectionError
from wifit3.bluetooth.hci_protocol import DiscoveryObservation
from wifit3.bluetooth.usb_hci import (
    UsbBluetoothController,
    UsbBluetoothError,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)
from wifit3.models import BluetoothDevice
from wifit3.models.bluetooth_device import BLE_RADIO
from wifit3.persist.bluetooth_history import BluetoothHistoryStore

logger = logging.getLogger(__name__)


class BluetoothScanError(RuntimeError):
    """The platform Bluetooth backend could not start scanning."""


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
    ) -> None:
        self._scanner_factory = scanner_factory
        self._client_factory = client_factory
        self._usb_scanner_factory = usb_scanner_factory
        self._usb_controller_finder = usb_controller_finder
        self.history = history
        self._scanner = None
        self._usb_scanner = None
        self._devices: dict[str, BluetoothDevice] = {}
        self._platform_devices: dict[str, Any] = {}
        self._similar_identifiers: dict[tuple, set[str]] = {}
        self._rssi_history: dict[str, deque[int]] = {}
        self.connection: BluetoothConnection | None = None
        self._advertisement_callbacks: list[Callable[[BluetoothDevice], None]] = []
        self._inspection_callbacks: list[Callable[[Any], None]] = []
        self.scan_started_at: float | None = None
        self.last_advertisement_at: float | None = None
        self.received_advertisements = 0
        self.scan_failures = 0

    @property
    def is_scanning(self) -> bool:
        return self._scanner is not None or (
            self._usb_scanner is not None
            and getattr(self._usb_scanner, "is_scanning", True)
        )

    @property
    def is_usb_scanning(self) -> bool:
        return (
            self._usb_scanner is not None
            and getattr(self._usb_scanner, "is_scanning", True)
        )

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

    def forget_devices(self) -> None:
        """Drop the in-memory discovery picture after confirmed history deletion."""
        if self.is_scanning:
            raise BluetoothScanError(
                "Stop Bluetooth discovery before clearing its history",
            )
        self._devices.clear()
        self._platform_devices.clear()
        self._similar_identifiers.clear()
        self._rssi_history.clear()

    def available_usb_controllers(self) -> list[UsbBluetoothController]:
        try:
            return self._usb_controller_finder()
        except Exception:
            logger.debug("Bluetooth USB controller scan failed", exc_info=True)
            return []

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
        scanner = self._scanner_factory(detection_callback=self._on_advertisement)
        try:
            await scanner.start()
        except Exception as exc:
            self.scan_failures += 1
            try:
                await scanner.stop()
            except Exception:
                pass
            raise BluetoothScanError(str(exc) or type(exc).__name__) from exc
        self._scanner = scanner
        self.scan_started_at = time.time()

    async def start_usb(self, controller: UsbBluetoothController) -> None:
        if self.is_scanning:
            return
        system_scanner = None
        if not controller.supports_le:
            system_scanner = self._scanner_factory(detection_callback=self._on_advertisement)
        usb_scanner = self._usb_scanner_factory(controller, self._on_usb_observation)
        try:
            await usb_scanner.start()
            if system_scanner is not None:
                await system_scanner.start()
        except Exception as exc:
            self.scan_failures += 1
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
        self._scanner = system_scanner
        self._usb_scanner = usb_scanner
        self.scan_started_at = time.time()

    async def stop(self) -> None:
        scanner, self._scanner = self._scanner, None
        usb_scanner, self._usb_scanner = self._usb_scanner, None
        for active in (scanner, usb_scanner):
            if active is None:
                continue
            try:
                await active.stop()
            except Exception:
                logger.debug("Bluetooth scanner stop failed", exc_info=True)

    async def connect(self, device: BluetoothDevice, update_callback=None) -> BluetoothConnection:
        if not getattr(device, "is_connectable_with_bleak", True):
            raise BluetoothConnectionError(
                "Direct USB HCI observations are discovery-only; use SCAN BLE for GATT Focus"
            )
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

    def _connection_updated(self, inspection, update_callback) -> None:
        if update_callback is not None:
            update_callback(inspection)
        for callback in list(self._inspection_callbacks):
            try:
                callback(inspection)
            except Exception:
                logger.debug("Bluetooth inspection callback failed", exc_info=True)

    async def disconnect(self) -> None:
        connection, self.connection = self.connection, None
        if connection is not None:
            await connection.disconnect()

    def _on_advertisement(self, device, advertisement_data) -> None:
        identifier = str(device.address)
        self._platform_devices[identifier] = device
        now = time.time()
        self.last_advertisement_at = now
        self.received_advertisements += 1
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
        if self.history is not None:
            self.history.enrich(observed, classify=previous is None)
            observed.profile_fingerprint = _profile_fingerprint(observed)
            self.history.remember(observed)
        self._devices[identifier] = observed
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth advertisement callback failed", exc_info=True)

    def _on_usb_observation(self, observation: DiscoveryObservation) -> None:
        now = time.time()
        self.last_advertisement_at = now
        self.received_advertisements += 1
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
            modalias=previous.modalias if previous is not None else "",
            hardware_vendor=previous.hardware_vendor if previous is not None else "",
            hardware_product=previous.hardware_product if previous is not None else "",
            hardware_source=previous.hardware_source if previous is not None else "",
            **signal,
        )
        observed.profile_fingerprint = _profile_fingerprint(observed)
        if self.history is not None:
            self.history.enrich(observed, classify=previous is None)
            observed.profile_fingerprint = _profile_fingerprint(observed)
            self.history.remember(observed)
        self._devices[observation.identifier] = observed
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth observation callback failed", exc_info=True)

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
        modalias=device.modalias,
        hardware_product=device.hardware_product,
    )


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

