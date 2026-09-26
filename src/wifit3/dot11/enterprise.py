from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from wifit3.models import EnterpriseCertificate


EAP_TYPE_NAMES = {
    1: "Identity",
    4: "EAP-MD5",
    13: "EAP-TLS",
    17: "LEAP",
    21: "EAP-TTLS",
    25: "PEAP",
    26: "EAP-MSCHAPv2",
    43: "EAP-FAST",
    50: "EAP-AKA'",
    55: "TEAP",
}
TLS_EAP_TYPES = {13, 21, 25, 43, 55}
TLS_VERSION_NAMES = {
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}


@dataclass(slots=True)
class TlsMetadata:
    versions: set[str] = field(default_factory=set)
    cipher_suites: set[int] = field(default_factory=set)
    certificates: list[EnterpriseCertificate] = field(default_factory=list)


def eap_tls_fragment(data: bytes) -> tuple[bool, bool, int | None, bytes]:
    if not data:
        return False, False, None, b""
    flags = data[0]
    offset = 1
    total_length = None
    if flags & 0x80:
        if len(data) < 5:
            return bool(flags & 0x40), bool(flags & 0x20), None, b""
        total_length = int.from_bytes(data[1:5], "big")
        offset = 5
    return bool(flags & 0x40), bool(flags & 0x20), total_length, data[offset:]


def parse_tls_records(payload: bytes) -> TlsMetadata:
    metadata = TlsMetadata()
    offset = 0
    handshake = bytearray()
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        version = payload[offset + 1: offset + 3]
        length = int.from_bytes(payload[offset + 3: offset + 5], "big")
        end = offset + 5 + length
        if end > len(payload):
            break
        if version in TLS_VERSION_NAMES:
            metadata.versions.add(TLS_VERSION_NAMES[version])
        if content_type == 22:
            handshake.extend(payload[offset + 5: end])
        offset = end
    _parse_handshakes(bytes(handshake), metadata)
    return metadata


def _parse_handshakes(data: bytes, metadata: TlsMetadata) -> None:
    offset = 0
    while offset + 4 <= len(data):
        message_type = data[offset]
        length = int.from_bytes(data[offset + 1: offset + 4], "big")
        end = offset + 4 + length
        if end > len(data):
            return
        body = data[offset + 4: end]
        if message_type == 2:
            _parse_server_hello(body, metadata)
        elif message_type == 11:
            _parse_certificate_message(body, metadata)
        offset = end


def _parse_server_hello(body: bytes, metadata: TlsMetadata) -> None:
    if len(body) < 38:
        return
    version = body[:2]
    if version in TLS_VERSION_NAMES:
        metadata.versions.add(TLS_VERSION_NAMES[version])
    session_length = body[34]
    cipher_offset = 35 + session_length
    if cipher_offset + 2 > len(body):
        return
    metadata.cipher_suites.add(int.from_bytes(body[cipher_offset: cipher_offset + 2], "big"))
    extensions_offset = cipher_offset + 3
    if extensions_offset + 2 > len(body):
        return
    extensions_length = int.from_bytes(
        body[extensions_offset: extensions_offset + 2], "big",
    )
    cursor = extensions_offset + 2
    end = min(len(body), cursor + extensions_length)
    while cursor + 4 <= end:
        extension_type = int.from_bytes(body[cursor: cursor + 2], "big")
        extension_length = int.from_bytes(body[cursor + 2: cursor + 4], "big")
        value = body[cursor + 4: cursor + 4 + extension_length]
        if extension_type == 43 and len(value) == 2 and value in TLS_VERSION_NAMES:
            metadata.versions.add(TLS_VERSION_NAMES[value])
        cursor += 4 + extension_length


def _parse_certificate_message(body: bytes, metadata: TlsMetadata) -> None:
    candidates = []
    if len(body) >= 3:
        candidates.append((3, int.from_bytes(body[:3], "big"), False))
    if body:
        context_length = body[0]
        list_offset = 1 + context_length
        if list_offset + 3 <= len(body):
            candidates.append((
                list_offset + 3,
                int.from_bytes(body[list_offset: list_offset + 3], "big"),
                True,
            ))
    for cursor, list_length, tls13 in candidates:
        if cursor + list_length > len(body):
            continue
        end = cursor + list_length
        certificates = []
        while cursor + 3 <= end:
            certificate_length = int.from_bytes(body[cursor: cursor + 3], "big")
            cursor += 3
            if cursor + certificate_length > end:
                break
            der = body[cursor: cursor + certificate_length]
            cursor += certificate_length
            summary = parse_der_certificate(der)
            if summary is not None:
                certificates.append(summary)
            if tls13:
                if cursor + 2 > end:
                    break
                extension_length = int.from_bytes(body[cursor: cursor + 2], "big")
                cursor += 2 + extension_length
        if certificates:
            metadata.certificates.extend(certificates)
            return


def parse_der_certificate(der: bytes) -> EnterpriseCertificate | None:
    try:
        outer = _children(der, 0x30)
        tbs = _children(outer[0][1])
        index = 1 if tbs and tbs[0][0] == 0xA0 else 0
        signature = _algorithm_name(tbs[index + 1][1])
        validity = _children(tbs[index + 3][1])
        public_key_algorithm, public_key_bits = _public_key(tbs[index + 5][1])
        not_before = _asn1_time(validity[0]) if validity else None
        not_after = _asn1_time(validity[1]) if len(validity) > 1 else None
    except (IndexError, ValueError):
        return None
    return EnterpriseCertificate(
        fingerprint=hashlib.sha256(der).hexdigest(),
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=signature,
        public_key_algorithm=public_key_algorithm,
        public_key_bits=public_key_bits,
    )


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError
    tag = data[offset]
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        length_bytes = first_length & 0x7F
        if not length_bytes or cursor + length_bytes > len(data):
            raise ValueError
        length = int.from_bytes(data[cursor: cursor + length_bytes], "big")
        cursor += length_bytes
    else:
        length = first_length
    end = cursor + length
    if end > len(data):
        raise ValueError
    return tag, data[cursor:end], end


def _children(data: bytes, expected_tag: int | None = None) -> list[tuple[int, bytes]]:
    if expected_tag is not None:
        encoded_length = len(data)
        tag, value, end = _read_tlv(data, 0)
        if tag != expected_tag or end != encoded_length:
            raise ValueError
        data = value
    children = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _read_tlv(data, offset)
        children.append((tag, value))
    return children


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    parts = [value[0] // 40, value[0] % 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
    return ".".join(str(part) for part in parts)


def _algorithm_name(sequence: bytes) -> str | None:
    try:
        fields = _children(sequence)
        oid = _decode_oid(fields[0][1])
    except (IndexError, ValueError):
        return None
    return {
        "1.2.840.113549.1.1.4": "RSA-MD5",
        "1.2.840.113549.1.1.5": "RSA-SHA1",
        "1.2.840.113549.1.1.11": "RSA-SHA256",
        "1.2.840.113549.1.1.12": "RSA-SHA384",
        "1.2.840.113549.1.1.13": "RSA-SHA512",
        "1.2.840.10045.4.3.2": "ECDSA-SHA256",
        "1.2.840.10045.4.3.3": "ECDSA-SHA384",
        "1.2.840.10045.4.3.4": "ECDSA-SHA512",
    }.get(oid, oid or None)


def _asn1_time(field: tuple[int, bytes]) -> float | None:
    tag, value = field
    try:
        text = value.decode("ascii")
        if tag == 0x17:
            parsed = datetime.strptime(text, "%y%m%d%H%M%SZ")
        elif tag == 0x18:
            parsed = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            return None
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc).timestamp()


def _public_key(sequence: bytes) -> tuple[str | None, int | None]:
    try:
        fields = _children(sequence)
        algorithm_fields = _children(fields[0][1])
        oid = _decode_oid(algorithm_fields[0][1])
        key = fields[1][1][1:]
    except (IndexError, ValueError):
        return None, None
    if oid == "1.2.840.113549.1.1.1":
        try:
            rsa = _children(key, 0x30)
            modulus = rsa[0][1].lstrip(b"\x00")
            return "RSA", len(modulus) * 8
        except (IndexError, ValueError):
            return "RSA", None
    if oid == "1.2.840.10045.2.1":
        return "EC", max(0, (len(key) - 1) // 2 * 8)
    return oid or None, len(key) * 8 if key else None
