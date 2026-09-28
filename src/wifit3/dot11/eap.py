from __future__ import annotations

import struct

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_GTC = 6
EAP_TYPE_NAK = 3
EAP_TYPE_PAP = 16
EAP_TYPE_MSCHAPV2 = 26
EAP_TYPE_PEAP = 25
EAP_TYPE_TTLS = 21
EAP_TYPE_TLS = 13
EAP_TYPE_NAK = 3
EAP_TLS_TYPES = frozenset({13, 21, 25, 43, 55})

_DOT1X_VERSION = 2
_DOT1X_EAP_PACKET = 0
_DOT1X_START = 1


def eapol_start_frame(bssid: bytes, client: bytes) -> bytes:
    payload = struct.pack(">BBH", _DOT1X_VERSION, _DOT1X_START, 0)
    return data_header(to_ds=True, bssid=bssid, client=client) + LLC_SNAP_EAPOL + payload


def eap_response_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    eap_type: int,
    data: bytes = b"",
) -> bytes:
    body = bytes([eap_type]) + data
    eap = struct.pack(">BBH", EAP_RESPONSE, identifier, 4 + len(body)) + body
    dot1x = struct.pack(">BBH", _DOT1X_VERSION, _DOT1X_EAP_PACKET, len(eap)) + eap
    return data_header(to_ds=True, bssid=bssid, client=client) + LLC_SNAP_EAPOL + dot1x


def eap_identity_response_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    identity: bytes = b"anonymous",
) -> bytes:
    return eap_response_frame(
        bssid,
        client,
        identifier,
        EAP_TYPE_IDENTITY,
        identity,
    )


def eap_nak_response_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    methods: tuple[int, ...],
) -> bytes:
    return eap_response_frame(
        bssid,
        client,
        identifier,
        EAP_TYPE_NAK,
        bytes(methods),
    )


def eap_request_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    eap_type: int,
    data: bytes = b"",
) -> bytes:
    body = bytes([eap_type]) + data
    eap = struct.pack(">BBH", EAP_REQUEST, identifier, 4 + len(body)) + body
    dot1x = struct.pack(">BBH", _DOT1X_VERSION, _DOT1X_EAP_PACKET, len(eap)) + eap
    return data_header(to_ds=False, bssid=bssid, client=client) + LLC_SNAP_EAPOL + dot1x


def eap_success_frame(bssid: bytes, client: bytes, identifier: int) -> bytes:
    eap = struct.pack(">BBH", EAP_SUCCESS, identifier, 4)
    dot1x = struct.pack(">BBH", _DOT1X_VERSION, _DOT1X_EAP_PACKET, len(eap)) + eap
    return data_header(to_ds=False, bssid=bssid, client=client) + LLC_SNAP_EAPOL + dot1x


def eap_tls_request_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    method: int,
    fragment: bytes = b"",
    *,
    more: bool = False,
    start: bool = False,
    total_length: int | None = None,
) -> bytes:
    flags = (0x20 if start else 0) | (0x40 if more else 0)
    data = b""
    if total_length is not None:
        flags |= 0x80
        data += int(total_length).to_bytes(4, "big")
    data = bytes([flags]) + data + fragment
    return eap_request_frame(bssid, client, identifier, method, data)


def eap_tls_response_frame(
    bssid: bytes,
    client: bytes,
    identifier: int,
    method: int,
    fragment: bytes = b"",
    *,
    more: bool = False,
    total_length: int | None = None,
    version_flags: int = 0,
) -> bytes:
    flags = (version_flags & 0x1F) | (0x40 if more else 0)
    data = b""
    if total_length is not None:
        flags |= 0x80
        data += int(total_length).to_bytes(4, "big")
    data = bytes([flags]) + data + fragment
    return eap_response_frame(bssid, client, identifier, method, data)
