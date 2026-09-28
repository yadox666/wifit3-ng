"""MS-CHAPv2 EAP payloads and Hashcat mode 5500 hash lines."""
from __future__ import annotations

import struct
from dataclasses import dataclass


EAP_TYPE_MSCHAPV2 = 26
_MSCHAP_OPCODE_CHALLENGE = 1
_MSCHAP_OPCODE_RESPONSE = 2


@dataclass(frozen=True, slots=True)
class MsChapV2Capture:
    username: str
    server_challenge: bytes
    peer_challenge: bytes
    nt_response: bytes
    flags: int


def build_mschapv2_challenge(mschap_id: int, challenge: bytes, name: bytes = b"") -> bytes:
    if len(challenge) != 16:
        raise ValueError("MS-CHAPv2 challenge must be 16 bytes")
    return bytes([_MSCHAP_OPCODE_CHALLENGE, mschap_id & 0xFF]) + struct.pack(
        ">H", 16,
    ) + challenge + name


def parse_mschapv2_eap_payload(payload: bytes) -> MsChapV2Capture | None:
    """Parse an EAP-MSCHAPv2 Response (opcode 2) body after the EAP type byte."""
    if len(payload) < 5 or payload[0] != _MSCHAP_OPCODE_RESPONSE:
        return None
    value_size = struct.unpack(">H", payload[2:4])[0]
    value_start = 4
    value_end = value_start + value_size
    if value_size != 49 or value_end > len(payload):
        return None
    value = payload[value_start:value_end]
    name = payload[value_end:].split(b"\x00", 1)[0]
    username = name.decode("utf-8", errors="replace").strip()
    if not username:
        username = "unknown"
    return MsChapV2Capture(
        username=username,
        server_challenge=b"",
        peer_challenge=value[:16],
        nt_response=value[24:48],
        flags=value[48],
    )


def attach_server_challenge(capture: MsChapV2Capture, server_challenge: bytes) -> MsChapV2Capture:
    if len(server_challenge) != 16:
        raise ValueError("server challenge must be 16 bytes")
    return MsChapV2Capture(
        username=capture.username,
        server_challenge=server_challenge,
        peer_challenge=capture.peer_challenge,
        nt_response=capture.nt_response,
        flags=capture.flags,
    )


def split_identity(identity: str) -> tuple[str, str]:
    if "\\" in identity:
        domain, user = identity.split("\\", 1)
        return user.strip() or identity, domain.strip()
    if "/" in identity:
        user, domain = identity.split("/", 1)
        return user.strip() or identity, domain.strip()
    return identity.strip() or "unknown", ""


def hashcat5500_line(capture: MsChapV2Capture) -> str:
    """One Hashcat mode 5500 line (NetNTLMv1 / MS-CHAPv2)."""
    if len(capture.server_challenge) != 16 or len(capture.nt_response) != 24:
        raise ValueError("incomplete MS-CHAPv2 capture")
    user = capture.username.replace("\n", "").replace(":", "")
    challenge = capture.server_challenge.hex().upper()
    response = capture.nt_response.hex().upper()
    return f"{user}:$MSCHAPv2${user}${challenge}${response}"


def hashcat5600_line(capture: MsChapV2Capture) -> str:
    """Hashcat mode 5600 (NetNTLMv2-SSP) derived from MS-CHAPv2 material."""
    if len(capture.server_challenge) != 16 or len(capture.nt_response) != 24:
        raise ValueError("incomplete MS-CHAPv2 capture")
    user, domain = split_identity(capture.username)
    nt_proof = capture.nt_response[:16].hex()
    blob = (
        "0101000000000000000000000000000000000000000000000000"
        + capture.peer_challenge.hex()
    )
    return f"{user}::{domain}:{capture.server_challenge.hex()}:{nt_proof}:{blob}"


def dedupe_key(capture: MsChapV2Capture) -> tuple[str, str, str]:
    return (
        capture.username.casefold(),
        capture.server_challenge.hex(),
        capture.nt_response.hex(),
    )
