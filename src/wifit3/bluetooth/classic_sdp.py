"""Minimal, read-only SDP framing and attribute parsing for Classic Bluetooth."""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST = 0x06
SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE = 0x07

L2CAP_SIGNALING_CID = 0x0001
SDP_PSM = 0x0001
L2CAP_CONNECTION_REQUEST = 0x02
L2CAP_CONNECTION_RESPONSE = 0x03
L2CAP_CONFIGURATION_REQUEST = 0x04
L2CAP_CONFIGURATION_RESPONSE = 0x05
L2CAP_DISCONNECTION_REQUEST = 0x06
L2CAP_DISCONNECTION_RESPONSE = 0x07
L2CAP_ECHO_REQUEST = 0x08
L2CAP_ECHO_RESPONSE = 0x09
L2CAP_INFORMATION_REQUEST = 0x0A
L2CAP_INFORMATION_RESPONSE = 0x0B


class SdpProtocolError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SdpService:
    uuid: str
    name: str = ""


@dataclass(frozen=True, slots=True)
class DataElement:
    element_type: int
    value: object


def l2cap_packet(cid: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload), cid) + payload


def signaling_command(code: int, identifier: int, payload: bytes) -> bytes:
    return struct.pack("<BBH", code, identifier, len(payload)) + payload


def iter_signaling_commands(payload: bytes):
    offset = 0
    while offset + 4 <= len(payload):
        code, identifier, length = struct.unpack_from("<BBH", payload, offset)
        end = offset + 4 + length
        if end > len(payload):
            raise SdpProtocolError("Truncated L2CAP signaling command")
        yield code, identifier, payload[offset + 4:end]
        offset = end
    if offset != len(payload):
        raise SdpProtocolError("Trailing bytes in L2CAP signaling packet")


def service_search_attribute_request(
    transaction_id: int,
    continuation_state: bytes = b"",
) -> bytes:
    if len(continuation_state) > 16:
        raise ValueError("SDP continuation state is too long")
    search_pattern = bytes.fromhex("3503191002")  # Public Browse Group
    attribute_ids = bytes.fromhex("35050a0000ffff")  # all attributes
    parameters = (
        search_pattern
        + struct.pack(">H", 0xFFFF)
        + attribute_ids
        + bytes((len(continuation_state),))
        + continuation_state
    )
    return (
        bytes((SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST,))
        + struct.pack(">HH", transaction_id & 0xFFFF, len(parameters))
        + parameters
    )


def parse_service_search_attribute_response(
    packet: bytes,
    expected_transaction_id: int,
) -> tuple[bytes, bytes]:
    if len(packet) < 8:
        raise SdpProtocolError("Truncated SDP response")
    pdu_id, transaction_id, parameter_length = struct.unpack_from(">BHH", packet)
    if pdu_id != SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE:
        raise SdpProtocolError(f"Unexpected SDP PDU 0x{pdu_id:02x}")
    if transaction_id != (expected_transaction_id & 0xFFFF):
        raise SdpProtocolError("SDP transaction identifier mismatch")
    if len(packet) != 5 + parameter_length:
        raise SdpProtocolError("SDP parameter length mismatch")
    attribute_length = struct.unpack_from(">H", packet, 5)[0]
    attribute_end = 7 + attribute_length
    if attribute_end >= len(packet):
        raise SdpProtocolError("Truncated SDP attribute list")
    continuation_length = packet[attribute_end]
    if continuation_length > 16:
        raise SdpProtocolError("SDP continuation state is too long")
    if attribute_end + 1 + continuation_length != len(packet):
        raise SdpProtocolError("Invalid SDP continuation state")
    return (
        packet[7:attribute_end],
        packet[attribute_end + 1:],
    )


def parse_service_records(encoded: bytes) -> tuple[SdpService, ...]:
    if len(encoded) > 0xFFFF:
        raise SdpProtocolError("SDP attribute list is too large")
    root, end = parse_data_element(encoded)
    if end != len(encoded) or root.element_type != 6:
        raise SdpProtocolError("SDP attributes are not a complete sequence")
    services: dict[str, SdpService] = {}
    for record in root.value:
        if not isinstance(record, DataElement) or record.element_type != 6:
            continue
        attributes = _attributes(record)
        service_classes = attributes.get(0x0001)
        if service_classes is None or service_classes.element_type != 6:
            continue
        name_element = attributes.get(0x0100)
        name = (
            str(name_element.value)
            if name_element is not None and name_element.element_type in {4, 8}
            else ""
        )
        for element in service_classes.value:
            if isinstance(element, DataElement) and element.element_type == 3:
                service = SdpService(str(element.value), name)
                existing = services.get(service.uuid)
                if existing is None or (not existing.name and service.name):
                    services[service.uuid] = service
    return tuple(services.values())


def parse_data_element(
    data: bytes,
    offset: int = 0,
    *,
    _depth: int = 0,
) -> tuple[DataElement, int]:
    if _depth > 16:
        raise SdpProtocolError("SDP data elements are nested too deeply")
    if offset >= len(data):
        raise SdpProtocolError("Missing SDP data element")
    descriptor = data[offset]
    offset += 1
    element_type = descriptor >> 3
    size_index = descriptor & 0x07
    if element_type == 0:
        length = 0
    elif size_index <= 4:
        length = (1, 2, 4, 8, 16)[size_index]
    else:
        size_bytes = (1, 2, 4)[size_index - 5]
        if offset + size_bytes > len(data):
            raise SdpProtocolError("Truncated SDP data-element length")
        length = int.from_bytes(data[offset:offset + size_bytes], "big")
        offset += size_bytes
    end = offset + length
    if end > len(data):
        raise SdpProtocolError("Truncated SDP data element")
    raw = data[offset:end]
    if element_type in {6, 7}:
        children = []
        child_offset = offset
        while child_offset < end:
            if len(children) >= 4096:
                raise SdpProtocolError("Too many SDP data elements")
            child, child_offset = parse_data_element(
                data, child_offset, _depth=_depth + 1,
            )
            children.append(child)
        value: object = tuple(children)
    elif element_type in {1, 2}:
        value = int.from_bytes(raw, "big", signed=element_type == 2)
    elif element_type == 3:
        if length == 2:
            value = f"{int.from_bytes(raw, 'big'):04x}"
        elif length == 4:
            value = f"{int.from_bytes(raw, 'big'):08x}"
        elif length == 16:
            value = str(uuid.UUID(bytes=raw))
        else:
            raise SdpProtocolError("Invalid SDP UUID length")
    elif element_type in {4, 8}:
        value = raw.decode("utf-8", errors="replace").rstrip("\x00")
    elif element_type == 5:
        value = bool(raw and raw[0])
    elif element_type == 0:
        value = None
    else:
        value = raw
    return DataElement(element_type, value), end


def _attributes(record: DataElement) -> dict[int, DataElement]:
    children = record.value
    attributes: dict[int, DataElement] = {}
    for index in range(0, len(children) - 1, 2):
        identifier, value = children[index:index + 2]
        if (
            isinstance(identifier, DataElement)
            and identifier.element_type == 1
            and isinstance(identifier.value, int)
            and isinstance(value, DataElement)
        ):
            attributes[identifier.value] = value
    return attributes
