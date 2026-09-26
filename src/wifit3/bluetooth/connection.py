from __future__ import annotations

import asyncio
import struct
import time
from typing import Any, Callable

from bleak import BleakClient

from wifit3.bluetooth.assigned_numbers import characteristic_name, resolved_service_name
from wifit3.models import (
    BluetoothCharacteristic,
    BluetoothDevice,
    BluetoothInspection,
    BluetoothService,
)


class BluetoothConnectionError(RuntimeError):
    """A selected BLE device could not be inspected."""


_TEXT_CHARACTERISTICS = {"2a00", "2a24", "2a25", "2a26", "2a27", "2a28", "2a29"}
_SAFE_READ_CHARACTERISTICS = _TEXT_CHARACTERISTICS | {"2a01", "2a19", "2a23", "2a50"}


class BluetoothConnection:
    """One explicit, read-only BLE connection and its discovered GATT state."""

    def __init__(
        self,
        device: BluetoothDevice,
        platform_device: Any,
        *,
        client_factory: Callable[..., Any] = BleakClient,
        update_callback: Callable[[BluetoothInspection], None] | None = None,
    ) -> None:
        self.inspection = BluetoothInspection(device=device)
        self._platform_device = platform_device
        self._client_factory = client_factory
        self._update_callback = update_callback
        self._client = None
        self._characteristics: dict[int, BluetoothCharacteristic] = {}

    async def connect(self) -> BluetoothInspection:
        state = self.inspection
        state.connecting = True
        self._notify_update()
        client = self._client_factory(
            self._platform_device,
            disconnected_callback=self._on_disconnected,
            timeout=10.0,
            pair=False,
        )
        self._client = client
        try:
            await asyncio.wait_for(client.connect(), timeout=12.0)
            state.connected = True
            state.connected_at = time.time()
            state.services = self._discover_services(client.services)
            await self._read_standard_information()
            await self._subscribe_battery_notifications()
            return state
        except Exception as exc:
            state.traffic.errors += 1
            state.disconnected_reason = str(exc) or type(exc).__name__
            await self._disconnect_after_failure()
            raise BluetoothConnectionError(state.disconnected_reason) from exc
        finally:
            state.connecting = False
            self._notify_update()

    async def disconnect(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                self.inspection.traffic.errors += 1
        self.inspection.connected = False
        self._notify_update()

    async def read_characteristic(self, handle: int) -> BluetoothCharacteristic:
        """Read one explicitly selected readable characteristic."""
        client = self._client
        info = self._characteristics.get(handle)
        if client is None or not self.inspection.connected:
            raise BluetoothConnectionError("Device is not connected")
        if info is None:
            raise BluetoothConnectionError("Characteristic is unavailable")
        if "read" not in info.properties:
            raise BluetoothConnectionError("Characteristic is not readable")
        try:
            value = await asyncio.wait_for(client.read_gatt_char(handle), timeout=3.0)
        except Exception as exc:
            info.read_error = str(exc) or type(exc).__name__
            self.inspection.traffic.errors += 1
            self._notify_update()
            raise BluetoothConnectionError(info.read_error) from exc
        raw = bytes(value)
        info.value = _decode_value(info.uuid, raw)
        info.value_bytes = len(raw)
        info.read_error = None
        self.inspection.traffic.gatt_reads += 1
        self.inspection.traffic.read_bytes += len(raw)
        self._notify_update()
        return info

    def _discover_services(self, services) -> list[BluetoothService]:
        discovered = []
        for service in services:
            characteristic_uuids = (
                characteristic.uuid for characteristic in service.characteristics
            )
            service_info = BluetoothService(
                uuid=service.uuid,
                name=resolved_service_name(service.uuid, characteristic_uuids),
            )
            for characteristic in service.characteristics:
                info = BluetoothCharacteristic(
                    handle=characteristic.handle,
                    uuid=characteristic.uuid,
                    name=characteristic_name(characteristic.uuid),
                    properties=tuple(characteristic.properties),
                )
                service_info.characteristics.append(info)
                self._characteristics[characteristic.handle] = info
            discovered.append(service_info)
        return discovered

    async def _read_standard_information(self) -> None:
        client = self._client
        if client is None:
            return
        for service in self.inspection.services:
            for info in service.characteristics:
                if "read" not in info.properties or _uuid16(info.uuid) not in _SAFE_READ_CHARACTERISTICS:
                    continue
                try:
                    value = await asyncio.wait_for(client.read_gatt_char(info.handle), timeout=3.0)
                    raw = bytes(value)
                    info.value = _decode_value(info.uuid, raw)
                    info.value_bytes = len(raw)
                    self.inspection.traffic.gatt_reads += 1
                    self.inspection.traffic.read_bytes += len(raw)
                except Exception as exc:
                    info.read_error = str(exc) or type(exc).__name__
                    self.inspection.traffic.errors += 1
                self._notify_update()

    async def _subscribe_battery_notifications(self) -> None:
        client = self._client
        if client is None:
            return
        for service in self.inspection.services:
            for info in service.characteristics:
                if _uuid16(info.uuid) != "2a19" or "notify" not in info.properties:
                    continue
                try:
                    await client.start_notify(info.handle, self._notification_callback(info))
                except Exception:
                    self.inspection.traffic.errors += 1

    def _notification_callback(self, info: BluetoothCharacteristic):
        def receive(_sender, data: bytearray) -> None:
            raw = bytes(data)
            info.value = _decode_value(info.uuid, raw)
            info.value_bytes = len(raw)
            info.notifications += 1
            info.notification_bytes += len(raw)
            self.inspection.traffic.notifications += 1
            self.inspection.traffic.notification_bytes += len(raw)
            self._notify_update()

        return receive

    def _on_disconnected(self, _client) -> None:
        self.inspection.connected = False
        if not self.inspection.disconnected_reason:
            self.inspection.disconnected_reason = "Device disconnected"
        self._notify_update()

    async def _disconnect_after_failure(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass
        self.inspection.connected = False

    def _notify_update(self) -> None:
        if self._update_callback is not None:
            self._update_callback(self.inspection)


def _uuid16(uuid: str) -> str:
    lowered = uuid.lower()
    suffix = "-0000-1000-8000-00805f9b34fb"
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return lowered if len(lowered) == 4 else ""


def _decode_value(uuid: str, value: bytes) -> str:
    short = _uuid16(uuid)
    if short in _TEXT_CHARACTERISTICS:
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    if short == "2a19" and value:
        return f"{value[0]}%"
    if short == "2a01" and len(value) >= 2:
        return f"0x{int.from_bytes(value[:2], 'little'):04X}"
    if short == "2a50" and len(value) >= 7:
        source, vendor, product, version = struct.unpack_from("<BHHH", value)
        return f"source {source}, vendor 0x{vendor:04X}, product 0x{product:04X}, v{version}"
    return value.hex(" ")

