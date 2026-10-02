"""BLE GATT inspection over USB HCI (no Bleak)."""
from __future__ import annotations

import asyncio
import time
from typing import Callable

from wifit3.bluetooth.exposure import assess_exposure
from wifit3.models import BluetoothCharacteristic, BluetoothDevice, BluetoothInspection


class UsbBluetoothConnectionError(RuntimeError):
    pass


class UsbBluetoothConnection:
    """Read-only LE GATT session via the dedicated USB controller."""

    def __init__(
        self,
        device: BluetoothDevice,
        scanner,
        *,
        update_callback: Callable[[BluetoothInspection], None] | None = None,
    ) -> None:
        self.inspection = BluetoothInspection(device=device)
        self._scanner = scanner
        self._update_callback = update_callback
        self._usb_backed = True
        self._le_handle: int | None = None

    async def connect(self) -> BluetoothInspection:
        state = self.inspection
        state.connecting = True
        self._notify_update()
        try:
            handle, services = await asyncio.to_thread(
                self._scanner.gatt.le_gatt_session_start, state.device,
            )
            self._le_handle = handle
            state.connected = True
            state.services = services
            state.connected_at = time.time()
            return state
        except Exception as exc:
            state.traffic.errors += 1
            state.disconnected_reason = str(exc) or type(exc).__name__
            raise UsbBluetoothConnectionError(state.disconnected_reason) from exc
        finally:
            state.connecting = False
            self._notify_update()

    async def disconnect(self) -> None:
        handle, self._le_handle = self._le_handle, None
        if handle is not None:
            await asyncio.to_thread(self._scanner.gatt.le_gatt_session_stop, handle)
        self.inspection.connected = False
        self._notify_update()

    async def read_characteristic(self, handle: int) -> BluetoothCharacteristic:
        from wifit3.bluetooth import gatt_att as att

        if self._le_handle is None or not self.inspection.connected:
            raise UsbBluetoothConnectionError("Device is not connected")
        state = self.inspection
        info = None
        for service in state.services:
            for characteristic in service.characteristics:
                if characteristic.handle == handle:
                    info = characteristic
                    break
        if info is None:
            raise UsbBluetoothConnectionError("Characteristic is unavailable")
        if "read" not in info.properties:
            raise UsbBluetoothConnectionError("Characteristic is not readable")
        try:
            body = await asyncio.to_thread(
                self._scanner.gatt.att_exchange,
                self._le_handle,
                att.read_request(handle),
            )
            opcode, data = att.parse_att_response(body)
            if opcode == att.ATT_ERROR_RESPONSE:
                request_opcode, attribute_handle, error_code = (
                    att.parse_error_response(data)
                )
                raise UsbBluetoothConnectionError(
                    f"{att.att_error_name(error_code)} — request opcode "
                    f"0x{request_opcode:02x}, handle 0x{attribute_handle:04x}",
                )
            if opcode != att.ATT_READ_RESPONSE:
                raise UsbBluetoothConnectionError(
                    f"Unexpected ATT response opcode 0x{opcode:02x}; "
                    f"expected Read Response 0x{att.ATT_READ_RESPONSE:02x}",
                )
        except Exception as exc:
            info.read_error = str(exc) or type(exc).__name__
            state.traffic.errors += 1
            self._notify_update()
            raise UsbBluetoothConnectionError(info.read_error) from exc
        info.value_hex = data.hex()
        info.value = data.decode("utf-8", errors="replace")
        info.value_bytes = len(data)
        info.read_error = ""
        state.traffic.gatt_reads += 1
        state.traffic.read_bytes += len(data)
        self._notify_update()
        return info

    def exposure_findings(self):
        return assess_exposure(self.inspection)

    def _notify_update(self) -> None:
        if self._update_callback is not None:
            self._update_callback(self.inspection)
