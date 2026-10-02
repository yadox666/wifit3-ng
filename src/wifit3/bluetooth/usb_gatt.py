"""USB HCI LE GATT connect + discovery (no Bluetooth lab suite)."""
from __future__ import annotations

import logging
import struct
import time
import uuid
from collections import deque

from wifit3.bluetooth.analytics import (
    hci_bd_addr_bytes,
    is_bluetooth_bd_addr,
    le_hci_peer_address_type,
    platform_address_type,
)
from wifit3.bluetooth.assigned_numbers import (
    characteristic_name,
    descriptor_name,
    resolved_service_name,
)
from wifit3.bluetooth import gatt_att as att
from wifit3.bluetooth.gatt_metadata import compact_uuid, decode_descriptor_value
from wifit3.bluetooth.hci_protocol import (
    ATT_CID,
    DiscoveryObservation,
    EVENT_LE_META,
    HCI_DISCONNECT,
    HCI_LE_CREATE_CONNECTION,
    HCI_LE_CREATE_CONNECTION_CANCEL,
    HCI_LE_SET_SCAN_ENABLE,
    LE_SUBEVENT_CONNECTION_COMPLETE,
    hci_status_message,
)
from wifit3.bluetooth.usb_hci import UsbBluetoothError, UsbHciScanner
from wifit3.models import (
    BluetoothCharacteristic,
    BluetoothDescriptor,
    BluetoothDevice,
    BluetoothService,
)

logger = logging.getLogger(__name__)


class UsbHciGattAccess:
    """LE link setup, ATT exchange, and GATT discovery on a USB dongle."""

    def __init__(self, scanner: UsbHciScanner) -> None:
        self._scanner = scanner

    def _step(self, message: str) -> None:
        step = getattr(self._scanner, "lab_step", None)
        if callable(step):
            step(message)

    def _debug(self, phase: str, name: str, **details) -> None:
        debug = getattr(self._scanner, "lab_debug_event", None)
        if callable(debug):
            debug(phase, name, **details)


    def le_gatt_session_start(self, device: BluetoothDevice) -> tuple[int, list[BluetoothService]]:
        """Open an LE ACL and discover GATT; caller must call ``le_gatt_session_stop``."""
        if not self._scanner.controller.supports_le:
            raise UsbBluetoothError("This USB controller does not support BLE")
        listen_s = (
            10.0
            if platform_address_type(device.identifier) == "platform-opaque"
            else 3.0
        )
        self._step(
            f"BLE: listen for target advertisements (≤{listen_s:.0f}s)…",
        )
        ble_adv = self._scanner.wait_for_ble_advertisement(
            device.identifier,
            listen_s,
            alternate_identifiers=tuple(device.related_identifiers),
            name=device.name,
        )
        if ble_adv is not None:
            self._step(
                f"BLE: advertisement seen (RSSI={ble_adv.rssi}, type={ble_adv.address_type})",
            )
        else:
            self._step(
                "BLE: no advertisement in window — will still attempt direct connect",
            )
        self._step("BLE: pausing USB LE scan for connection…")
        self.pause_le_scan()
        self._step("BLE: HCI LE Create Connection…")
        try:
            handle = self.le_connect(device, ble_adv=ble_adv)
        except UsbBluetoothError:
            self.resume_le_scan()
            raise
        try:
            self._step("BLE: ATT/GATT service discovery…")
            services = self._gatt_discover(handle)
            self._step(
                f"BLE: GATT discovery finished ({len(services)} primary services)",
            )
        except Exception:
            self.le_disconnect(handle)
            raise
        return handle, services

    def le_gatt_session_stop(self, handle: int) -> None:
        self.le_disconnect(handle)
        self.resume_le_scan()

    def pause_le_scan(self) -> None:
        self._scanner._running = False
        try:
            self._scanner._command(HCI_LE_SET_SCAN_ENABLE, b"\x00\x00")
        except UsbBluetoothError:
            pass

    def resume_le_scan(self) -> None:
        if self._scanner._device is None:
            return
        if not getattr(self._scanner, "_usb_le_scan_enabled", True):
            return
        self._scanner._running = True
        try:
            self._scanner._command(HCI_LE_SET_SCAN_ENABLE, b"\x01\x00")
        except UsbBluetoothError:
            pass

    def _resolve_le_peer(
        self,
        device: BluetoothDevice,
        ble_adv: DiscoveryObservation | None,
    ) -> tuple[str, str]:
        if ble_adv is not None and is_bluetooth_bd_addr(ble_adv.identifier):
            return ble_adv.identifier, ble_adv.address_type
        if is_bluetooth_bd_addr(device.identifier):
            return device.identifier, device.address_type
        for related in device.related_identifiers:
            if is_bluetooth_bd_addr(related):
                return related, device.address_type
        opaque = device.identifier
        if len(opaque) > 24:
            opaque = opaque[:20] + "…"
        raise UsbBluetoothError(
            "USB BLE lab needs a 6-byte Bluetooth address (AA:BB:CC:DD:EE:FF). "
            f"This row uses an OS-only identifier ({opaque}). "
            "The dongle did not hear a matching advertisement with a MAC during "
            "the listen window — keep the device awake and in range, or pick a "
            "row whose ADDRESS / ID column shows a MAC."
        )

    def le_connect(
        self,
        device: BluetoothDevice,
        *,
        ble_adv: DiscoveryObservation | None = None,
    ) -> int:
        peer_address, address_type = self._resolve_le_peer(device, ble_adv)
        if ble_adv is not None and ble_adv.address_type not in {
            "",
            "unknown",
            "platform-opaque",
        }:
            address_type = ble_adv.address_type
        primary = le_hci_peer_address_type(address_type, peer_address)
        alternate = 1 - primary
        attempts = (primary, alternate) if alternate != primary else (primary,)
        last_error: UsbBluetoothError | None = None
        for index, addr_type in enumerate(attempts):
            if index > 0:
                self._step(
                    f"BLE: retry HCI LE Create Connection (peer address type={addr_type})…",
                )
            try:
                return self.le_connect_once(
                    device,
                    addr_type,
                    peer_address=peer_address,
                )
            except UsbBluetoothError as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def le_connect_once(
        self,
        device: BluetoothDevice,
        addr_type: int,
        *,
        peer_address: str,
    ) -> int:
        address = hci_bd_addr_bytes(peer_address)
        self._scanner.ensure_le_connection_events()
        self._debug(
            "le",
            "create_connection",
            address=peer_address,
            address_type=device.address_type,
            hci_peer_address_type=addr_type,
        )
        params = struct.pack(
            "<HHBB6sBHHHHHH",
            0x0060,
            0x0030,
            0x00,
            addr_type,
            address,
            0x00,
            0x0018,
            0x0028,
            0x0000,
            0x00C8,
            0x0004,
            0x0006,
        )
        self._scanner._command(HCI_LE_CREATE_CONNECTION, params, 12_000)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self._scanner._pending_events:
                code, parameters = self._scanner._pending_events.popleft()
            else:
                packet = self._scanner._read_event(
                    max(1, int((deadline - time.monotonic()) * 1000)),
                )
                if packet is None:
                    continue
                parsed = self._scanner._parse_event_packet(packet)
                if parsed is None:
                    continue
                code, parameters = parsed
            if code != EVENT_LE_META or len(parameters) < 3:
                self._scanner._handle_aux_hci_event(code, parameters, 0)
                continue
            if parameters[0] != LE_SUBEVENT_CONNECTION_COMPLETE:
                continue
            status = parameters[1]
            if status != 0:
                self._debug(
                    "le",
                    "connect_failed",
                    status=status,
                    address=device.identifier,
                    hci_peer_address_type=addr_type,
                )
                logger.warning(
                    "LE connection to %s failed with HCI status 0x%02x",
                    device.identifier,
                    status,
                )
                raise UsbBluetoothError(
                    f"LE connection failed: {hci_status_message(status)}",
                    hci_status=status,
                )
            handle = int.from_bytes(parameters[2:4], "little") & 0x0FFF
            # Seed ACL MTU/credits so L2CAP writes on this LE link don't stall
            # ("ACL transmit credits timed out"); only the Classic path did this.
            self._scanner.prepare_le_acl_buffers()
            # Mark the handle LE so L2CAP writes use PB flag 0b00 (LE-U) instead
            # of the BR/EDR auto-flushable 0b10, which LE controllers drop.
            self._scanner.register_le_acl_handle(handle)
            self._debug(
                "le",
                "connect_ok",
                handle=handle,
                address=device.identifier,
                hci_peer_address_type=addr_type,
            )
            return handle
        try:
            self._scanner._command(HCI_LE_CREATE_CONNECTION_CANCEL, b"", 2_000)
        except UsbBluetoothError:
            pass
        # The cancel yields an LE Connection Complete with status 0x02; drain it
        # so a follow-up attempt doesn't consume it as its own connect failure.
        self._drain_le_connection_complete()
        logger.warning("LE connection to %s timed out", device.identifier)
        self._debug(
            "le",
            "connect_timeout",
            address=device.identifier,
            hci_peer_address_type=addr_type,
        )
        raise UsbBluetoothError("LE connection timed out")

    def _drain_le_connection_complete(self, timeout_ms: int = 500) -> None:
        """Consume a pending LE Connection Complete left by a cancelled connect.

        LE Create Connection Cancel completes by emitting an LE Connection
        Complete subevent (status 0x02). If left in the queue, the next connect
        attempt misreads it as its own failure, so swallow it here.
        """
        scanner = self._scanner
        remaining = deque(scanner._pending_events)
        scanner._pending_events.clear()
        drained = False
        for code, parameters in remaining:
            if (
                not drained
                and code == EVENT_LE_META
                and len(parameters) >= 2
                and parameters[0] == LE_SUBEVENT_CONNECTION_COMPLETE
            ):
                drained = True
                continue
            scanner._pending_events.append((code, parameters))
        if drained:
            return
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            packet = scanner._read_event(
                max(1, int((deadline - time.monotonic()) * 1000)),
            )
            if packet is None:
                continue
            parsed = scanner._parse_event_packet(packet)
            if parsed is None:
                continue
            code, parameters = parsed
            if (
                code == EVENT_LE_META
                and len(parameters) >= 2
                and parameters[0] == LE_SUBEVENT_CONNECTION_COMPLETE
            ):
                return
            scanner._handle_aux_hci_event(code, parameters, 0)

    def le_disconnect(self, handle: int) -> None:
        self._scanner.unregister_le_acl_handle(handle)
        try:
            self._scanner._command(
                HCI_DISCONNECT, struct.pack("<HB", handle, 0x13),
            )
        except UsbBluetoothError:
            pass

    def att_exchange(self, handle: int, pdu: bytes, timeout_s: float = 3.0) -> bytes:
        self._scanner._send_l2cap(handle, ATT_CID, pdu)
        deadline = time.monotonic() + timeout_s
        _, payload = self._scanner._read_l2cap(handle, deadline)
        return payload

    def _gatt_discover(self, handle: int) -> list[BluetoothService]:
        try:
            self.att_exchange(handle, att.exchange_mtu_request())
        except UsbBluetoothError:
            pass
        services: list[BluetoothService] = []
        start = 0x0001
        end = 0xFFFF
        while start <= end:
            try:
                body = self.att_exchange(
                    handle,
                    att.read_by_group_type_request(start, end, att.GATT_PRIMARY_SERVICE),
                )
            except UsbBluetoothError:
                break
            opcode, data = att.parse_att_response(body)
            if opcode == att.ATT_ERROR_RESPONSE:
                if len(data) >= 2:
                    self._debug(
                        "le",
                        "att_error",
                        opcode=att.ATT_READ_BY_GROUP_TYPE_REQUEST,
                        error_code=data[1],
                    )
                break
            if opcode != att.ATT_READ_BY_GROUP_TYPE_RESPONSE:
                self._debug(
                    "le",
                    "att_unexpected",
                    opcode=opcode,
                )
                break
            advanced = False
            for svc_start, svc_end, uuid_value in att.iter_group_type_services(data):
                advanced = True
                if isinstance(uuid_value, int):
                    svc_uuid = str(
                        uuid.UUID(f"0000{uuid_value:04x}-0000-1000-8000-00805f9b34fb"),
                    )
                else:
                    svc_uuid = str(uuid.UUID(bytes=bytes(uuid_value)))
                service = BluetoothService(
                    uuid=svc_uuid,
                    name=resolved_service_name(svc_uuid),
                    characteristics=[],
                )
                self._discover_characteristics(handle, service, svc_start, svc_end)
                services.append(service)
                start = svc_end + 1
            if not advanced:
                break
        return services

    def _discover_characteristics(
        self,
        handle: int,
        service: BluetoothService,
        start: int,
        end: int,
    ) -> None:
        cursor = start
        while cursor <= end:
            try:
                body = self.att_exchange(
                    handle,
                    att.read_by_type_request(cursor, end, att.GATT_CHARACTERISTIC),
                )
            except UsbBluetoothError:
                break
            opcode, data = att.parse_att_response(body)
            if opcode == att.ATT_ERROR_RESPONSE:
                break
            if opcode != att.ATT_READ_BY_TYPE_RESPONSE:
                break
            moved = False
            for decl, props, value_handle, uuid16 in att.iter_characteristics(data):
                moved = True
                char_uuid = str(
                    uuid.UUID(
                        f"0000{uuid16:04x}-0000-1000-8000-00805f9b34fb",
                    ),
                )
                props_labels = att.properties_label(props)
                value = ""
                value_hex = ""
                if "read" in props_labels:
                    try:
                        read_body = self.att_exchange(
                            handle, att.read_request(value_handle),
                        )
                        rop, rdata = att.parse_att_response(read_body)
                        if rop == att.ATT_READ_RESPONSE:
                            value_hex = rdata.hex()
                            value = rdata.decode("utf-8", errors="replace")
                    except UsbBluetoothError as exc:
                        value = str(exc)
                service.characteristics.append(
                    BluetoothCharacteristic(
                        handle=value_handle,
                        uuid=char_uuid,
                        name=characteristic_name(char_uuid),
                        properties=props_labels,
                        value=value,
                        value_hex=value_hex,
                        value_bytes=len(value_hex) // 2,
                        declaration_handle=decl,
                    ),
                )
                cursor = decl + 1
            if not moved:
                break
        self._discover_descriptors(handle, service, end)

    def _discover_descriptors(
        self,
        connection_handle: int,
        service: BluetoothService,
        service_end: int,
    ) -> None:
        readable_metadata = {"2900", "2901", "2902", "2904"}
        for index, characteristic in enumerate(service.characteristics):
            start = characteristic.handle + 1
            if index + 1 < len(service.characteristics):
                next_declaration = (
                    service.characteristics[index + 1].declaration_handle
                )
                end = (
                    next_declaration - 1
                    if next_declaration is not None
                    else service_end
                )
            else:
                end = service_end
            cursor = start
            while cursor <= end:
                try:
                    body = self.att_exchange(
                        connection_handle,
                        att.find_information_request(cursor, end),
                    )
                except UsbBluetoothError:
                    break
                opcode, data = att.parse_att_response(body)
                if opcode == att.ATT_ERROR_RESPONSE:
                    break
                if opcode != att.ATT_FIND_INFORMATION_RESPONSE:
                    break
                found = list(att.iter_information(data))
                if not found:
                    break
                for descriptor_handle, uuid_value in found:
                    descriptor_uuid = (
                        str(uuid.UUID(
                            f"0000{uuid_value:04x}-0000-1000-8000-00805f9b34fb",
                        ))
                        if isinstance(uuid_value, int)
                        else str(uuid.UUID(bytes_le=uuid_value))
                    )
                    descriptor = BluetoothDescriptor(
                        handle=descriptor_handle,
                        uuid=descriptor_uuid,
                        name=descriptor_name(descriptor_uuid),
                    )
                    if compact_uuid(descriptor_uuid) in readable_metadata:
                        self._read_descriptor(
                            connection_handle,
                            descriptor,
                        )
                    characteristic.descriptors.append(descriptor)
                next_cursor = found[-1][0] + 1
                if next_cursor <= cursor:
                    break
                cursor = next_cursor

    def _read_descriptor(
        self,
        connection_handle: int,
        descriptor: BluetoothDescriptor,
    ) -> None:
        try:
            body = self.att_exchange(
                connection_handle,
                att.read_request(descriptor.handle),
            )
            opcode, data = att.parse_att_response(body)
            if opcode == att.ATT_ERROR_RESPONSE:
                request_opcode, attribute_handle, error_code = (
                    att.parse_error_response(data)
                )
                descriptor.read_error = (
                    f"{att.att_error_name(error_code)} — request opcode "
                    f"0x{request_opcode:02x}, handle 0x{attribute_handle:04x}"
                )
                return
            if opcode != att.ATT_READ_RESPONSE:
                descriptor.read_error = (
                    f"Unexpected ATT response opcode 0x{opcode:02x}"
                )
                return
            descriptor.value_hex = data.hex(" ")
            descriptor.value = decode_descriptor_value(descriptor.uuid, data)
        except (UsbBluetoothError, ValueError) as exc:
            descriptor.read_error = str(exc) or type(exc).__name__
