"""ATT helpers for LE GATT discovery over USB HCI (product + lab)."""
from __future__ import annotations

import struct
from typing import Iterable

ATT_ERROR_RESPONSE = 0x01
ATT_EXCHANGE_MTU_REQUEST = 0x02
ATT_EXCHANGE_MTU_RESPONSE = 0x03
ATT_FIND_INFORMATION_REQUEST = 0x04
ATT_FIND_INFORMATION_RESPONSE = 0x05
ATT_READ_BY_GROUP_TYPE_REQUEST = 0x10
ATT_READ_BY_GROUP_TYPE_RESPONSE = 0x11
ATT_READ_BY_TYPE_REQUEST = 0x08
ATT_READ_BY_TYPE_RESPONSE = 0x09
ATT_READ_REQUEST = 0x0A
ATT_READ_RESPONSE = 0x0B

GATT_PRIMARY_SERVICE = 0x2800
GATT_CHARACTERISTIC = 0x2803

# ATT error codes (Core Vol 3, Part F, 3.4.1.1) relevant to access control.
ATT_ERR_READ_NOT_PERMITTED = 0x02
ATT_ERR_INSUFFICIENT_AUTHENTICATION = 0x05
ATT_ERR_REQUEST_NOT_SUPPORTED = 0x06
ATT_ERR_INSUFFICIENT_AUTHORIZATION = 0x08
ATT_ERR_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0C
ATT_ERR_INSUFFICIENT_ENCRYPTION = 0x0F

_ATT_ERROR_NAMES: dict[int, str] = {
    0x01: "Invalid Handle",
    ATT_ERR_READ_NOT_PERMITTED: "Read Not Permitted",
    0x03: "Write Not Permitted",
    0x04: "Invalid PDU",
    ATT_ERR_INSUFFICIENT_AUTHENTICATION: "Insufficient Authentication",
    ATT_ERR_REQUEST_NOT_SUPPORTED: "Request Not Supported",
    0x07: "Invalid Offset",
    ATT_ERR_INSUFFICIENT_AUTHORIZATION: "Insufficient Authorization",
    0x09: "Prepare Queue Full",
    0x0A: "Attribute Not Found",
    0x0B: "Attribute Not Long",
    ATT_ERR_INSUFFICIENT_ENCRYPTION_KEY_SIZE: "Insufficient Encryption Key Size",
    0x0D: "Invalid Attribute Value Length",
    0x0E: "Unlikely Error",
    ATT_ERR_INSUFFICIENT_ENCRYPTION: "Insufficient Encryption",
    0x10: "Unsupported Group Type",
    0x11: "Insufficient Resources",
    0x12: "Database Out Of Sync",
    0x13: "Value Not Allowed",
}

_ATT_MTU = 517


def exchange_mtu_request() -> bytes:
    return struct.pack("<BH", ATT_EXCHANGE_MTU_REQUEST, _ATT_MTU)


def read_by_group_type_request(start: int, end: int, uuid16: int) -> bytes:
    return struct.pack(
        "<BHHH", ATT_READ_BY_GROUP_TYPE_REQUEST, start, end, uuid16,
    )


def read_by_type_request(start: int, end: int, uuid16: int) -> bytes:
    return struct.pack(
        "<BHHH", ATT_READ_BY_TYPE_REQUEST, start, end, uuid16,
    )


def read_request(handle: int) -> bytes:
    return struct.pack("<BH", ATT_READ_REQUEST, handle)


def find_information_request(start: int, end: int) -> bytes:
    return struct.pack("<BHH", ATT_FIND_INFORMATION_REQUEST, start, end)


def parse_att_response(payload: bytes) -> tuple[int, bytes]:
    if not payload:
        raise ValueError("empty ATT payload")
    opcode = payload[0]
    return opcode, payload[1:]


def parse_error_response(data: bytes) -> tuple[int, int, int]:
    """Return (request_opcode, attribute_handle, error_code) from an Error Rsp.

    ``data`` is the ATT payload *after* the 0x01 opcode byte, i.e.
    Request_Opcode (1) + Attribute_Handle (2, LE) + Error_Code (1).
    """
    if len(data) < 4:
        raise ValueError("short ATT error response")
    request_opcode = data[0]
    attribute_handle = int.from_bytes(data[1:3], "little")
    error_code = data[3]
    return request_opcode, attribute_handle, error_code


def att_error_name(code: int) -> str:
    known = _ATT_ERROR_NAMES.get(code)
    if known is not None:
        return f"{known} (ATT 0x{code:02x})"
    if 0x80 <= code <= 0x9F:
        return f"Application Error (ATT 0x{code:02x})"
    if 0xE0 <= code <= 0xFF:
        return f"Common Profile/Service Error (ATT 0x{code:02x})"
    return f"Reserved or unknown ATT error (ATT 0x{code:02x})"


def att_security_requirement(error_code: int) -> str:
    """Classify the access-control requirement implied by an ATT read error."""
    if error_code == ATT_ERR_INSUFFICIENT_AUTHENTICATION:
        return "authentication"
    if error_code == ATT_ERR_INSUFFICIENT_ENCRYPTION:
        return "encryption"
    if error_code == ATT_ERR_INSUFFICIENT_AUTHORIZATION:
        return "authorization"
    if error_code == ATT_ERR_INSUFFICIENT_ENCRYPTION_KEY_SIZE:
        return "encryption-key-size"
    if error_code == ATT_ERR_READ_NOT_PERMITTED:
        return "read-not-permitted"
    return "other"


def iter_group_type_services(body: bytes) -> Iterable[tuple[int, int, int | bytes]]:
    """Yield (start_handle, end_handle, uuid16 or uuid128 bytes) from group-type data."""
    if len(body) < 2:
        return
    data_len = struct.unpack_from("<H", body, 0)[0]
    chunk = body[2:2 + data_len]
    if not chunk:
        return
    entry_size = 20 if len(chunk) % 20 == 0 else 6 if len(chunk) % 6 == 0 else 0
    if entry_size == 0:
        return
    offset = 0
    while offset + entry_size <= len(chunk):
        start, end = struct.unpack_from("<HH", chunk, offset)
        if entry_size == 6:
            uuid16 = struct.unpack_from("<H", chunk, offset + 4)[0]
            yield start, end, uuid16
        else:
            yield start, end, bytes(chunk[offset + 4:offset + 20])
        offset += entry_size


def iter_characteristics(body: bytes) -> Iterable[tuple[int, int, int, int]]:
    """Yield (declaration_handle, properties, value_handle, uuid16) from read-by-type body."""
    offset = 0
    item_size = 7
    while offset + item_size <= len(body):
        decl, props, value_handle, uuid16 = struct.unpack_from("<HBHH", body, offset)
        yield decl, props, value_handle, uuid16
        offset += item_size


def iter_information(body: bytes) -> Iterable[tuple[int, int | bytes]]:
    """Yield descriptor (handle, UUID) entries from Find Information data."""
    if not body:
        return
    format_code = body[0]
    entry_size = 4 if format_code == 0x01 else 18 if format_code == 0x02 else 0
    if entry_size == 0:
        return
    offset = 1
    while offset + entry_size <= len(body):
        handle = int.from_bytes(body[offset:offset + 2], "little")
        if format_code == 0x01:
            uuid_value: int | bytes = int.from_bytes(
                body[offset + 2:offset + 4],
                "little",
            )
        else:
            uuid_value = bytes(body[offset + 2:offset + 18])
        yield handle, uuid_value
        offset += entry_size


def properties_label(props: int) -> tuple[str, ...]:
    labels = []
    if props & 0x01:
        labels.append("broadcast")
    if props & 0x02:
        labels.append("read")
    if props & 0x04:
        labels.append("write-without-response")
    if props & 0x08:
        labels.append("write")
    if props & 0x10:
        labels.append("notify")
    if props & 0x20:
        labels.append("indicate")
    if props & 0x40:
        labels.append("authenticated-signed-writes")
    if props & 0x80:
        labels.append("extended-properties")
    return tuple(labels)
