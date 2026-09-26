"""OS-backed Bluetooth Low Energy discovery."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace
from typing import Any, Callable

from bleak import BleakClient, BleakScanner

from wifit3.bluetooth.connection import BluetoothConnection
from wifit3.models import BluetoothDevice

logger = logging.getLogger(__name__)


class BluetoothScanError(RuntimeError):
    """The platform Bluetooth backend could not start scanning."""


class BluetoothManager:
    """Owns a Bleak scanner and the latest advertisement from each nearby device."""

    def __init__(
        self,
        scanner_factory: Callable[..., Any] = BleakScanner,
        client_factory: Callable[..., Any] = BleakClient,
    ) -> None:
        self._scanner_factory = scanner_factory
        self._client_factory = client_factory
        self._scanner = None
        self._devices: dict[str, BluetoothDevice] = {}
        self._platform_devices: dict[str, Any] = {}
        self._similar_identifiers: dict[tuple, set[str]] = {}
        self.connection: BluetoothConnection | None = None
        self._advertisement_callbacks: list[Callable[[BluetoothDevice], None]] = []
        self._inspection_callbacks: list[Callable[[Any], None]] = []
        self.scan_started_at: float | None = None
        self.last_advertisement_at: float | None = None
        self.received_advertisements = 0
        self.scan_failures = 0

    @property
    def is_scanning(self) -> bool:
        return self._scanner is not None

    @property
    def backend_name(self) -> str:
        scanner = self._scanner
        return scanner.__class__.__name__ if scanner is not None else "Bleak"

    def devices(self) -> list[BluetoothDevice]:
        return list(self._devices.values())

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
        if self._scanner is not None:
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

    async def stop(self) -> None:
        scanner, self._scanner = self._scanner, None
        if scanner is None:
            return
        try:
            await scanner.stop()
        except Exception:
            logger.debug("Bluetooth scanner stop failed", exc_info=True)

    async def connect(self, device: BluetoothDevice, update_callback=None) -> BluetoothConnection:
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
        if _is_private_identifier(identifier) and any(similarity_key):
            identifiers = self._similar_identifiers.setdefault(similarity_key, set())
            identifiers.add(identifier)
            similar_identifier_count = len(identifiers)
            for similar_identifier in identifiers:
                known = self._devices.get(similar_identifier)
                if known is not None:
                    self._devices[similar_identifier] = replace(
                        known, similar_identifier_count=similar_identifier_count,
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
        )
        self._devices[identifier] = observed
        for callback in list(self._advertisement_callbacks):
            try:
                callback(observed)
            except Exception:
                logger.debug("Bluetooth advertisement callback failed", exc_info=True)


def _is_private_identifier(identifier: str) -> bool:
    parts = identifier.split(":")
    if len(parts) == 6:
        try:
            return bool(int(parts[0], 16) & 0x02)
        except ValueError:
            return False
    return len(identifier) == 36 and identifier.count("-") == 4

