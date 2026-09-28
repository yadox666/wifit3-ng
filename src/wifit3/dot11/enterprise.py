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
    client_versions: set[str] = field(default_factory=set)
    cipher_suites: set[int] = field(default_factory=set)
    client_cipher_suites: set[int] = field(default_factory=set)
    server_names: set[str] = field(default_factory=set)
    supported_groups: set[int] = field(default_factory=set)
    signature_algorithms: set[int] = field(default_factory=set)
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
        if message_type == 1:
            _parse_client_hello(body, metadata)
        elif message_type == 2:
            _parse_server_hello(body, metadata)
        elif message_type == 11:
            _parse_certificate_message(body, metadata)
        offset = end


def _parse_client_hello(body: bytes, metadata: TlsMetadata) -> None:
    if len(body) < 35:
        return
    legacy_version = body[:2]
    session_length = body[34]
    cursor = 35 + session_length
    if cursor + 2 > len(body):
        return
    cipher_length = int.from_bytes(body[cursor: cursor + 2], "big")
    cursor += 2
    cipher_end = cursor + cipher_length
    if cipher_length % 2 or cipher_end > len(body):
        return
    metadata.client_cipher_suites.update(
        int.from_bytes(body[offset: offset + 2], "big")
        for offset in range(cursor, cipher_end, 2)
    )
    cursor = cipher_end
    if cursor >= len(body):
        if legacy_version in TLS_VERSION_NAMES:
            metadata.client_versions.add(TLS_VERSION_NAMES[legacy_version])
        return
    compression_length = body[cursor]
    cursor += 1 + compression_length
    extensions = _hello_extensions(body, cursor)
    offered_versions = _client_supported_versions(extensions.get(43, b""))
    if offered_versions:
        metadata.client_versions.update(offered_versions)
    elif legacy_version in TLS_VERSION_NAMES:
        metadata.client_versions.add(TLS_VERSION_NAMES[legacy_version])
    metadata.server_names.update(_server_names(extensions.get(0, b"")))
    metadata.supported_groups.update(_u16_vector(extensions.get(10, b"")))
    metadata.signature_algorithms.update(_u16_vector(extensions.get(13, b"")))


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
    extensions = _hello_extensions(body, extensions_offset)
    selected_version = extensions.get(43, b"")
    if len(selected_version) == 2 and selected_version in TLS_VERSION_NAMES:
        metadata.versions.add(TLS_VERSION_NAMES[selected_version])


def _hello_extensions(data: bytes, offset: int) -> dict[int, bytes]:
    if offset + 2 > len(data):
        return {}
    total = int.from_bytes(data[offset: offset + 2], "big")
    cursor = offset + 2
    end = min(len(data), cursor + total)
    extensions = {}
    while cursor + 4 <= end:
        extension_type = int.from_bytes(data[cursor: cursor + 2], "big")
        length = int.from_bytes(data[cursor + 2: cursor + 4], "big")
        value_end = cursor + 4 + length
        if value_end > end:
            break
        extensions[extension_type] = data[cursor + 4: value_end]
        cursor = value_end
    return extensions


def _client_supported_versions(value: bytes) -> set[str]:
    if not value:
        return set()
    length = value[0]
    values = value[1: 1 + length]
    return {
        TLS_VERSION_NAMES[version]
        for offset in range(0, len(values) - 1, 2)
        if (version := values[offset: offset + 2]) in TLS_VERSION_NAMES
    }


def _u16_vector(value: bytes) -> set[int]:
    if len(value) < 2:
        return set()
    length = int.from_bytes(value[:2], "big")
    values = value[2: 2 + length]
    return {
        int.from_bytes(values[offset: offset + 2], "big")
        for offset in range(0, len(values) - 1, 2)
    }


def _server_names(value: bytes) -> set[str]:
    if len(value) < 2:
        return set()
    cursor = 2
    end = min(len(value), 2 + int.from_bytes(value[:2], "big"))
    names = set()
    while cursor + 3 <= end:
        name_type = value[cursor]
        length = int.from_bytes(value[cursor + 1: cursor + 3], "big")
        cursor += 3
        raw = value[cursor: cursor + length]
        cursor += length
        if name_type == 0:
            try:
                names.add(raw.decode("idna"))
            except UnicodeError:
                pass
    return names


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
        issuer = _name(tbs[index + 2][1])
        validity = _children(tbs[index + 3][1])
        subject = _name(tbs[index + 4][1])
        public_key_algorithm, public_key_bits = _public_key(tbs[index + 5][1])
        not_before = _asn1_time(validity[0]) if validity else None
        not_after = _asn1_time(validity[1]) if len(validity) > 1 else None
        san_dns, extended_key_usage, is_ca = _certificate_extensions(tbs[index + 6:])
    except (IndexError, ValueError):
        return None
    return EnterpriseCertificate(
        fingerprint=hashlib.sha256(der).hexdigest(),
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=signature,
        public_key_algorithm=public_key_algorithm,
        public_key_bits=public_key_bits,
        subject=subject,
        issuer=issuer,
        san_dns=tuple(sorted(san_dns)),
        extended_key_usage=tuple(sorted(extended_key_usage)),
        is_ca=is_ca,
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


def _name(sequence: bytes) -> str | None:
    labels = {
        "2.5.4.3": "CN",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
    }
    parts = []
    try:
        for tag, relative_name in _children(sequence):
            if tag != 0x31:
                continue
            for item_tag, item in _children(relative_name):
                if item_tag != 0x30:
                    continue
                fields = _children(item)
                oid = _decode_oid(fields[0][1])
                value = _asn1_string(fields[1])
                if value:
                    parts.append(f"{labels.get(oid, oid)}={value}")
    except (IndexError, ValueError):
        return None
    return ", ".join(parts) or None


def _asn1_string(field: tuple[int, bytes]) -> str | None:
    tag, value = field
    encodings = {
        0x0C: "utf-8",
        0x12: "ascii",
        0x13: "ascii",
        0x14: "latin-1",
        0x16: "ascii",
        0x1E: "utf-16-be",
    }
    encoding = encodings.get(tag)
    if encoding is None:
        return None
    try:
        return value.decode(encoding)
    except UnicodeDecodeError:
        return None


def _certificate_extensions(
    fields: list[tuple[int, bytes]],
) -> tuple[set[str], set[str], bool | None]:
    extensions = {}
    for tag, value in fields:
        if tag != 0xA3:
            continue
        try:
            for extension_tag, extension in _children(value, 0x30):
                if extension_tag != 0x30:
                    continue
                parts = _children(extension)
                oid = _decode_oid(parts[0][1])
                encoded = next((item for item_tag, item in reversed(parts) if item_tag == 0x04), b"")
                if oid and encoded:
                    extensions[oid] = encoded
        except (IndexError, ValueError):
            continue
    return (
        _subject_alt_names(extensions.get("2.5.29.17", b"")),
        _extended_key_usage(extensions.get("2.5.29.37", b"")),
        _basic_constraints_ca(extensions.get("2.5.29.19", b"")),
    )


def _subject_alt_names(encoded: bytes) -> set[str]:
    if not encoded:
        return set()
    try:
        names = _children(encoded, 0x30)
    except ValueError:
        return set()
    result = set()
    for tag, value in names:
        if tag != 0x82:
            continue
        try:
            result.add(value.decode("idna"))
        except UnicodeError:
            pass
    return result


def _extended_key_usage(encoded: bytes) -> set[str]:
    if not encoded:
        return set()
    labels = {
        "1.3.6.1.5.5.7.3.1": "serverAuth",
        "1.3.6.1.5.5.7.3.2": "clientAuth",
        "1.3.6.1.5.5.7.3.3": "codeSigning",
        "1.3.6.1.5.5.7.3.4": "emailProtection",
    }
    try:
        usages = _children(encoded, 0x30)
    except ValueError:
        return set()
    return {
        labels.get(oid, oid)
        for tag, value in usages
        if tag == 0x06 and (oid := _decode_oid(value))
    }


def _basic_constraints_ca(encoded: bytes) -> bool | None:
    if not encoded:
        return None
    try:
        constraints = _children(encoded, 0x30)
    except ValueError:
        return None
    boolean = next((value for tag, value in constraints if tag == 0x01), None)
    return bool(boolean and boolean != b"\x00")


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
