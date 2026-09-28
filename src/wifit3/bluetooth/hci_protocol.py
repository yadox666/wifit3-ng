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
HCI_WRITE_INQUIRY_MODE = 0x0C45
HCI_LE_SET_EVENT_MASK = 0x2001
HCI_LE_SET_SCAN_PARAMETERS = 0x200B
HCI_LE_SET_SCAN_ENABLE = 0x200C

EVENT_INQUIRY_COMPLETE = 0x01
EVENT_INQUIRY_RESULT = 0x02
EVENT_REMOTE_NAME_REQUEST_COMPLETE = 0x07
EVENT_INQUIRY_RESULT_WITH_RSSI = 0x22
EVENT_EXTENDED_INQUIRY_RESULT = 0x2F
EVENT_COMMAND_COMPLETE = 0x0E
EVENT_COMMAND_STATUS = 0x0F
EVENT_LE_META = 0x3E

LE_ADVERTISING_REPORT = 0x02
LE_EXTENDED_ADVERTISING_REPORT = 0x0D


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
