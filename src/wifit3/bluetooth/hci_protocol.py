from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from wifit3.bluetooth.analytics import (
    hci_address_type,
    protocol_type_hint,
    raw_payload_fingerprint,
)
from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO

HCI_RESET = 0x0C03
HCI_SET_EVENT_MASK = 0x0C01
HCI_READ_LOCAL_VERSION = 0x1001
HCI_INQUIRY = 0x0401
HCI_INQUIRY_CANCEL = 0x0402
HCI_CREATE_CONNECTION = 0x0405
HCI_DISCONNECT = 0x0406
HCI_CREATE_CONNECTION_CANCEL = 0x0408
HCI_LINK_KEY_REQUEST_NEG_REPLY = 0x040C
HCI_PIN_CODE_REQUEST_NEG_REPLY = 0x040E
HCI_REMOTE_NAME_REQUEST = 0x0419
HCI_REMOTE_NAME_REQUEST_CANCEL = 0x041A
HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY = 0x042D
HCI_USER_PASSKEY_REQUEST_NEG_REPLY = 0x042F
HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY = 0x0433
HCI_IO_CAPABILITY_REQUEST_NEG_REPLY = 0x0434
HCI_READ_BUFFER_SIZE = 0x1005
HCI_LE_READ_BUFFER_SIZE = 0x2002
HCI_WRITE_INQUIRY_MODE = 0x0C45
HCI_LE_SET_EVENT_MASK = 0x2001
# LE Meta events we consume: bit0 Connection Complete, bit1 Advertising Report
# (bits 2-5 are the intermediate connection/feature events). 0x3f = bits 0-5.
LE_EVENT_MASK_SCAN_AND_CONNECT = b"\x3f" + b"\x00" * 7
# Active scan with window == interval == 0x0060 (96 x 0.625 ms = 60 ms): a 100%
# duty cycle so the whole advertising-channel dwell is spent listening.
LE_SCAN_TYPE_ACTIVE = 0x01
LE_SCAN_INTERVAL = 0x0060
LE_SCAN_WINDOW = 0x0060
LE_SCAN_PARAMETERS = struct.pack(
    "<BHHBB",
    LE_SCAN_TYPE_ACTIVE,
    LE_SCAN_INTERVAL,
    LE_SCAN_WINDOW,
    0x00,
    0x00,
)
# GIAC 0x9E8B33. Inquiry_Length in units of 1.28 s (HCI spec).
CLASSIC_INQUIRY_LENGTH_SHORT = 0x05  # ~6.4 s — when USB also runs LE scan on a shared radio
CLASSIC_INQUIRY_LENGTH_FULL = 0x0A  # ~12.8 s — Classic-only USB path (OS Bleak owns BLE)
CLASSIC_INQUIRY_LENGTH = CLASSIC_INQUIRY_LENGTH_SHORT
CLASSIC_INQUIRY_PARAMETERS = bytes(
    (0x33, 0x8B, 0x9E, CLASSIC_INQUIRY_LENGTH_SHORT, 0x00),
)


def classic_inquiry_parameters(length: int = CLASSIC_INQUIRY_LENGTH_SHORT) -> bytes:
    return bytes((0x33, 0x8B, 0x9E, length, 0x00))


def classic_inquiry_timeout_ms(length: int) -> int:
    return max(5_000, int(length * 1.28 * 1000) + 2_000)
HCI_LE_SET_SCAN_PARAMETERS = 0x200B
HCI_LE_SET_SCAN_ENABLE = 0x200C
HCI_LE_CREATE_CONNECTION = 0x200D
HCI_LE_CREATE_CONNECTION_CANCEL = 0x200E
HCI_LE_READ_REMOTE_FEATURES = 0x2016
HCI_READ_REMOTE_SUPPORTED_FEATURES = 0x041B
HCI_READ_REMOTE_VERSION_INFORMATION = 0x041D
HCI_PIN_CODE_REQUEST_REPLY = 0x040D
HCI_LINK_KEY_REQUEST_REPLY = 0x040B
HCI_AUTHENTICATION_REQUESTED = 0x0411
HCI_SET_CONNECTION_ENCRYPTION = 0x0413
HCI_IO_CAPABILITY_REQUEST_REPLY = 0x042B
HCI_USER_CONFIRMATION_REQUEST_REPLY = 0x042C
HCI_USER_PASSKEY_REQUEST_REPLY = 0x042E
HCI_READ_ENCRYPTION_KEY_SIZE = 0x1408

EVENT_INQUIRY_COMPLETE = 0x01
EVENT_AUTHENTICATION_COMPLETE = 0x06
EVENT_ENCRYPTION_CHANGE = 0x08
EVENT_CONNECTION_COMPLETE = 0x03
EVENT_PIN_CODE_REQUEST = 0x16
EVENT_LINK_KEY_REQUEST = 0x17
EVENT_LINK_KEY_NOTIFICATION = 0x18
EVENT_IO_CAPABILITY_REQUEST = 0x31
EVENT_IO_CAPABILITY_RESPONSE = 0x32
EVENT_USER_CONFIRMATION_REQUEST = 0x33
EVENT_USER_PASSKEY_REQUEST = 0x34
EVENT_REMOTE_OOB_DATA_REQUEST = 0x35
EVENT_USER_PASSKEY_NOTIFICATION = 0x3B

# SSP IO capabilities (HCI IO_Capability_Request_Reply / IO Capability Response).
IO_CAPABILITY_DISPLAY_ONLY = 0x00
IO_CAPABILITY_DISPLAY_YES_NO = 0x01
IO_CAPABILITY_KEYBOARD_ONLY = 0x02
IO_CAPABILITY_NO_INPUT_NO_OUTPUT = 0x03

# SSP Authentication Requirements (bonding + MITM protection).
AUTH_REQ_NO_MITM_GENERAL_BONDING = 0x04
AUTH_REQ_MITM_GENERAL_BONDING = 0x05

IO_CAPABILITY_NAMES: dict[int, str] = {
    IO_CAPABILITY_DISPLAY_ONLY: "DisplayOnly",
    IO_CAPABILITY_DISPLAY_YES_NO: "DisplayYesNo",
    IO_CAPABILITY_KEYBOARD_ONLY: "KeyboardOnly",
    IO_CAPABILITY_NO_INPUT_NO_OUTPUT: "NoInputNoOutput",
}


def io_capability_name(value: int) -> str:
    return IO_CAPABILITY_NAMES.get(value, f"0x{value:02x}")


def io_capability_has_display(value: int) -> bool:
    """True for peers that can show a code (DisplayOnly / DisplayYesNo)."""
    return value in (IO_CAPABILITY_DISPLAY_ONLY, IO_CAPABILITY_DISPLAY_YES_NO)


def io_capability_supports_mitm(value: int) -> bool:
    """True when the peer has I/O for Numeric Comparison or Passkey Entry."""
    return value in (
        IO_CAPABILITY_DISPLAY_ONLY,
        IO_CAPABILITY_DISPLAY_YES_NO,
        IO_CAPABILITY_KEYBOARD_ONLY,
    )
EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE = 0x0B
EVENT_READ_REMOTE_VERSION_COMPLETE = 0x0C
LE_SUBEVENT_READ_REMOTE_FEATURES_COMPLETE = 0x04
EVENT_DISCONNECTION_COMPLETE = 0x05
EVENT_INQUIRY_RESULT = 0x02
EVENT_REMOTE_NAME_REQUEST_COMPLETE = 0x07
EVENT_INQUIRY_RESULT_WITH_RSSI = 0x22
EVENT_EXTENDED_INQUIRY_RESULT = 0x2F
EVENT_COMMAND_COMPLETE = 0x0E
EVENT_COMMAND_STATUS = 0x0F
EVENT_LE_META = 0x3E

LE_ADVERTISING_REPORT = 0x02
LE_EXTENDED_ADVERTISING_REPORT = 0x0D
LE_SUBEVENT_CONNECTION_COMPLETE = 0x01

ATT_CID = 0x0004

_HCI_STATUS_NAMES: dict[int, str] = {
    0x00: "Success",
    0x01: "Unknown HCI command",
    0x02: "Unknown connection identifier",
    0x03: "Hardware failure",
    0x04: "Page timeout",
    0x05: "Authentication failure",
    0x06: "PIN or key missing",
    0x07: "Memory capacity exceeded",
    0x08: "Connection timeout",
    0x09: "Connection limit exceeded",
    0x0A: "Synchronous connection limit exceeded",
    0x0B: "ACL connection already exists",
    0x0C: "Command disallowed",
    0x0D: "Connection rejected: limited resources",
    0x0E: "Connection rejected: security reasons",
    0x0F: "Connection rejected: unacceptable BD_ADDR",
    0x10: "Connection accept timeout exceeded",
    0x11: "Unsupported feature or parameter value",
    0x12: "Invalid HCI command parameters",
    0x13: "Remote user terminated connection",
    0x14: "Remote device terminated connection due to low resources",
    0x15: "Remote device terminated connection due to power off",
    0x16: "Connection terminated by local host",
    0x17: "Repeated attempts",
    0x18: "Pairing not allowed",
    0x19: "Unknown LMP PDU",
    0x1A: "Unsupported remote feature",
    0x1B: "SCO offset rejected",
    0x1C: "SCO interval rejected",
    0x1D: "SCO air mode rejected",
    0x1E: "Invalid LMP parameters / invalid LL parameters",
    0x1F: "Unspecified error",
    0x20: "Unsupported LMP parameter value / unsupported LL parameter value",
    0x21: "Role change not allowed",
    0x22: "LMP response timeout / LL response timeout",
    0x23: "LMP error transaction collision / LL procedure collision",
    0x24: "LMP PDU not allowed",
    0x25: "Encryption mode not acceptable",
    0x26: "Link key cannot be changed",
    0x27: "Requested QoS not supported",
    0x28: "Instant passed",
    0x29: "Pairing with unit key not supported",
    0x2A: "Different transaction collision",
    0x2C: "QoS unacceptable parameter",
    0x2D: "QoS rejected",
    0x2E: "Channel classification not supported",
    0x2F: "Insufficient security",
    0x30: "Parameter out of mandatory range",
    0x32: "Role switch pending",
    0x34: "Reserved slot violation",
    0x35: "Role switch failed",
    0x36: "Extended inquiry response too large",
    0x37: "Secure Simple Pairing not supported by host",
    0x38: "Host busy pairing",
    0x39: "Connection rejected: no suitable channel found",
    0x3A: "Controller busy",
    0x3B: "Unacceptable connection parameters",
    0x3C: "Advertising timeout",
    0x3D: "Connection terminated due to MIC failure",
    0x3E: "Connection failed to be established / synchronization timeout",
    0x3F: "Previously used error code (reserved)",
    0x40: (
        "Coarse clock adjustment rejected; controller will try clock dragging"
    ),
    0x41: "Type 0 submap not defined",
    0x42: "Unknown advertising identifier",
    0x43: "Limit reached",
    0x44: "Operation cancelled by host",
    0x45: "Packet too long",
    0x46: "Too late",
    0x47: "Too early",
    0x48: "Insufficient channels",
}


CLASSIC_CONNECT_RETRYABLE_STATUSES = frozenset(
    {0x04, 0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x0E},
)


def classic_connect_retryable(status: int) -> bool:
    return status in CLASSIC_CONNECT_RETRYABLE_STATUSES


def classic_connect_exception_retriable(exc: Exception) -> bool:
    """Whether a failed Classic ACL connect is worth retrying with fresh inquiry."""
    from wifit3.bluetooth.usb_hci import UsbBluetoothError

    if isinstance(exc, UsbBluetoothError) and exc.hci_status is not None:
        return classic_connect_retryable(exc.hci_status)
    message = str(exc).casefold()
    return (
        "event 0x03 timed out" in message
        or "connection complete" in message
        or "page timeout" in message
        or "connection timeout" in message
        or "acl packet timed out" in message
    )


def hci_status_message(status: int) -> str:
    name = _HCI_STATUS_NAMES.get(status, "Reserved or unknown HCI status")
    label = f"{name} (HCI 0x{status:02x})"
    if status == 0x04:
        return (
            f"{label}: the remote device did not answer Classic paging. "
            "It may be BLE-only, out of range, asleep, or not connectable over BR/EDR."
        )
    if status == 0x08:
        return f"{label}: the link setup timed out."
    if status == 0x0D:
        return (
            f"{label}: the target refused a new BR/EDR link (often already connected "
            "to a phone/PC, out of pairing slots, or not in discoverable/pairing mode). "
            "Disconnect other hosts, open pairing on the device, then retry."
        )
    if status == 0x0E:
        return (
            f"{label}: the target rejected the connection for security policy "
            "(pairing mode required or bond mismatch)."
        )
    if status == 0x0B:
        return (
            f"{label}: an ACL to this address may already exist on the target or "
            "controller — disconnect other Bluetooth users and retry."
        )
    if status == 0x12:
        return (
            f"{label}: the controller rejected a pairing command as malformed "
            "(invalid HCI parameters) — this is a lab bug, not a device issue."
        )
    if status == 0x21:
        return (
            f"{label}: the controller rejected the pairing step for the current "
            "master/slave role — the lab retries the ACL with role switch disabled."
        )
    return label


@dataclass(frozen=True, slots=True)
class DiscoveryObservation:
    identifier: str
    radio_type: str
    rssi: int
    name: str = "<Unknown>"
    service_uuids: tuple[str, ...] = ()
    service_data_uuids: tuple[str, ...] = ()
    manufacturer_ids: tuple[int, ...] = ()
    manufacturer_data_bytes: int = 0
    service_data_bytes: int = 0
    tx_power: int | None = None
    class_of_device: int | None = None
    appearance: int | None = None
    address_type: str = "unknown"
    payload_fingerprint: str = ""
    protocol_category: str = ""
    protocol_type: str = ""
    protocol_source: str = ""
    protocol_confidence: str = ""
    page_scan_repetition_mode: int = 0
    clock_offset: int = 0
    decode_state: str = ""
    signature_watch: str = ""


def command_packet(opcode: int, parameters: bytes = b"") -> bytes:
    if len(parameters) > 255:
        raise ValueError("HCI command parameters exceed 255 bytes")
    return struct.pack("<HB", opcode, len(parameters)) + parameters


def parse_event(packet: bytes) -> tuple[int, bytes]:
    if len(packet) < 2:
        raise ValueError("short HCI event")
    event_code, length = packet[0], packet[1]
    if len(packet) < length + 2:
        raise ValueError("truncated HCI event")
    return event_code, packet[2:2 + length]


def command_result(event_code: int, parameters: bytes) -> tuple[int, int, bytes] | None:
    if event_code == EVENT_COMMAND_COMPLETE and len(parameters) >= 3:
        opcode = int.from_bytes(parameters[1:3], "little")
        result = parameters[3:]
        status = result[0] if result else 0
        return opcode, status, result
    if event_code == EVENT_COMMAND_STATUS and len(parameters) >= 4:
        return int.from_bytes(parameters[2:4], "little"), parameters[0], parameters[:1]
    return None


def parse_discovery_event(event_code: int, parameters: bytes) -> list[DiscoveryObservation]:
    if event_code == EVENT_INQUIRY_RESULT:
        return _parse_inquiry_results_without_rssi(parameters)
    if event_code == EVENT_INQUIRY_RESULT_WITH_RSSI:
        return _parse_inquiry_results(parameters)
    if event_code == EVENT_EXTENDED_INQUIRY_RESULT:
        return _parse_extended_inquiry_result(parameters)
    if event_code == EVENT_LE_META and parameters:
        if parameters[0] == LE_ADVERTISING_REPORT:
            return _parse_le_advertising_reports(parameters[1:])
        if parameters[0] == LE_EXTENDED_ADVERTISING_REPORT:
            return _parse_le_extended_reports(parameters[1:])
    return []


def parse_remote_name_event(parameters: bytes) -> tuple[str, str] | None:
    if len(parameters) < 7 or parameters[0] != 0:
        return None
    name = parameters[7:].split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    if not name:
        return None
    return _address(parameters[1:7]), name


def _address(raw: bytes) -> str:
    return ":".join(f"{part:02X}" for part in reversed(raw))


def _signed(value: int) -> int:
    return value - 256 if value > 127 else value


def _uuid128(raw: bytes) -> str:
    return str(uuid.UUID(bytes=bytes(reversed(raw))))


def _advertising_data(data: bytes) -> dict:
    name = "<Unknown>"
    services: set[str] = set()
    service_data: set[str] = set()
    manufacturers: set[int] = set()
    manufacturer_payloads: dict[int, bytes] = {}
    service_payloads: dict[str, bytes] = {}
    manufacturer_bytes = 0
    service_bytes = 0
    tx_power = None
    class_of_device = None
    appearance = None
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if offset + length > len(data):
            break
        data_type = data[offset]
        value = data[offset + 1:offset + length]
        offset += length
        if data_type in {0x08, 0x09} and value:
            decoded = value.decode("utf-8", errors="replace").strip("\x00")
            if decoded and (name == "<Unknown>" or data_type == 0x09):
                name = decoded
        elif data_type in {0x02, 0x03}:
            services.update(
                f"{int.from_bytes(value[i:i + 2], 'little'):04x}"
                for i in range(0, len(value) - 1, 2)
            )
        elif data_type in {0x04, 0x05}:
            services.update(
                f"{int.from_bytes(value[i:i + 4], 'little'):08x}"
                for i in range(0, len(value) - 3, 4)
            )
        elif data_type in {0x06, 0x07}:
            services.update(
                _uuid128(value[i:i + 16]) for i in range(0, len(value) - 15, 16)
            )
        elif data_type == 0x0A and value:
            tx_power = _signed(value[0])
        elif data_type == 0x0D and len(value) >= 3:
            class_of_device = int.from_bytes(value[:3], "little")
        elif data_type == 0x19 and len(value) >= 2:
            appearance = int.from_bytes(value[:2], "little")
        elif data_type == 0xFF and len(value) >= 2:
            manufacturer = int.from_bytes(value[:2], "little")
            manufacturers.add(manufacturer)
            manufacturer_payloads[manufacturer] = value[2:]
            manufacturer_bytes += len(value) - 2
        elif data_type == 0x16 and len(value) >= 2:
            service_uuid = f"{int.from_bytes(value[:2], 'little'):04x}"
            service_data.add(service_uuid)
            service_payloads[service_uuid] = value[2:]
            service_bytes += len(value) - 2
        elif data_type == 0x20 and len(value) >= 4:
            service_uuid = f"{int.from_bytes(value[:4], 'little'):08x}"
            service_data.add(service_uuid)
            service_payloads[service_uuid] = value[4:]
            service_bytes += len(value) - 4
        elif data_type == 0x21 and len(value) >= 16:
            service_uuid = _uuid128(value[:16])
            service_data.add(service_uuid)
            service_payloads[service_uuid] = value[16:]
            service_bytes += len(value) - 16
    return {
        "name": name,
        "service_uuids": tuple(sorted(services)),
        "service_data_uuids": tuple(sorted(service_data)),
        "manufacturer_ids": tuple(sorted(manufacturers)),
        "manufacturer_data_bytes": manufacturer_bytes,
        "service_data_bytes": service_bytes,
        "tx_power": tx_power,
        "class_of_device": class_of_device,
        "appearance": appearance,
        "payload_fingerprint": raw_payload_fingerprint(data),
        **protocol_type_hint(
            manufacturer_payloads, service_payloads, services, name=name,
        ),
    }


def _parse_inquiry_results(parameters: bytes) -> list[DiscoveryObservation]:
    if not parameters:
        return []
    count = parameters[0]
    expected = 1 + count * 14
    if len(parameters) < expected:
        return []
    observations = []
    for index in range(count):
        base = 1 + index * 14
        observations.append(DiscoveryObservation(
            identifier=_address(parameters[base:base + 6]),
            radio_type=CLASSIC_RADIO,
            rssi=_signed(parameters[base + 13]),
            page_scan_repetition_mode=parameters[base + 6],
            class_of_device=int.from_bytes(
                parameters[base + 8:base + 11], "little"
            ),
            clock_offset=int.from_bytes(
                parameters[base + 11:base + 13], "little"
            ),
        ))
    return observations


def _parse_inquiry_results_without_rssi(parameters: bytes) -> list[DiscoveryObservation]:
    if not parameters:
        return []
    count = parameters[0]
    expected = 1 + count * 14
    if len(parameters) < expected:
        return []
    observations = []
    for index in range(count):
        base = 1 + index * 14
        observations.append(DiscoveryObservation(
            identifier=_address(parameters[base:base + 6]),
            radio_type=CLASSIC_RADIO,
            rssi=-100,
            page_scan_repetition_mode=parameters[base + 6],
            class_of_device=int.from_bytes(
                parameters[base + 9:base + 12], "little"
            ),
            clock_offset=int.from_bytes(
                parameters[base + 12:base + 14], "little"
            ),
        ))
    return observations


def _parse_extended_inquiry_result(parameters: bytes) -> list[DiscoveryObservation]:
    if len(parameters) < 255 or parameters[0] != 1:
        return []
    details = _advertising_data(parameters[15:255])
    details["class_of_device"] = int.from_bytes(parameters[9:12], "little")
    return [DiscoveryObservation(
        identifier=_address(parameters[1:7]),
        radio_type=CLASSIC_RADIO,
        rssi=_signed(parameters[14]),
        page_scan_repetition_mode=parameters[7],
        clock_offset=int.from_bytes(parameters[12:14], "little"),
        **details,
    )]


def _parse_le_advertising_reports(parameters: bytes) -> list[DiscoveryObservation]:
    if not parameters:
        return []
    reports = []
    offset = 1
    for _ in range(parameters[0]):
        if offset + 10 > len(parameters):
            break
        address = parameters[offset + 2:offset + 8]
        data_length = parameters[offset + 8]
        end = offset + 9 + data_length
        if end >= len(parameters):
            break
        details = _advertising_data(parameters[offset + 9:end])
        reports.append(DiscoveryObservation(
            identifier=(identifier := _address(address)),
            radio_type=BLE_RADIO,
            rssi=_signed(parameters[end]),
            address_type=hci_address_type(identifier, parameters[offset + 1]),
            **details,
        ))
        offset = end + 1
    return reports


def _parse_le_extended_reports(parameters: bytes) -> list[DiscoveryObservation]:
    if not parameters:
        return []
    reports = []
    offset = 1
    for _ in range(parameters[0]):
        if offset + 24 >= len(parameters):
            break
        address = parameters[offset + 3:offset + 9]
        tx_power = _signed(parameters[offset + 12])
        rssi = _signed(parameters[offset + 13])
        data_length = parameters[offset + 23]
        end = offset + 24 + data_length
        if end > len(parameters):
            break
        details = _advertising_data(parameters[offset + 24:end])
        if details["tx_power"] is None and tx_power != 127:
            details["tx_power"] = tx_power
        reports.append(DiscoveryObservation(
            identifier=(identifier := _address(address)),
            radio_type=BLE_RADIO,
            rssi=rssi,
            address_type=hci_address_type(identifier, parameters[offset + 2]),
            **details,
        ))
        offset = end
    return reports
