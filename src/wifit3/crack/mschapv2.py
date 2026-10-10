"""MS-CHAPv2 EAP payloads and Hashcat mode 5500 hash lines."""
from __future__ import annotations

import hashlib
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
    """RFC 2759 Challenge: MS-Length + Value-Size=16 + challenge + authenticator Name."""
    if len(challenge) != 16:
        raise ValueError("MS-CHAPv2 challenge must be 16 bytes")
    ms_length = 4 + 1 + 16 + len(name)
    return (
        bytes([_MSCHAP_OPCODE_CHALLENGE, mschap_id & 0xFF])
        + struct.pack(">H", ms_length)
        + bytes([16])
        + challenge
        + name
    )


@dataclass(frozen=True, slots=True)
class MsChapV2Challenge:
    mschap_id: int
    server_challenge: bytes
    authenticator_name: str = ""


def parse_mschapv2_challenge_payload(payload: bytes) -> MsChapV2Challenge | None:
    """Parse an EAP-MSCHAPv2 Challenge (opcode 1) body after the EAP type byte."""
    if len(payload) < 4 or payload[0] != _MSCHAP_OPCODE_CHALLENGE:
        return None
    declared = struct.unpack(">H", payload[2:4])[0]
    # RFC 2759 / FreeRADIUS / wpa_supplicant: MS-Length + Value-Size (16) + challenge + name.
    # Challenge Name is the authenticator (often "freeradius-x.y.z"), not the user.
    # Legacy compact honeypot: 2-byte value-size of 16 and no extra size byte.
    if declared != 16 and len(payload) >= 21 and payload[4] == 16:
        challenge = payload[5:21]
        name = payload[21:].split(b"\x00", 1)[0]
    elif declared == 16 and len(payload) >= 20:
        challenge = payload[4:20]
        name = payload[20:].split(b"\x00", 1)[0]
    else:
        return None
    authenticator = name.decode("utf-8", errors="replace").strip()
    return MsChapV2Challenge(
        mschap_id=payload[1],
        server_challenge=challenge,
        authenticator_name=authenticator,
    )


def parse_mschapv2_eap_payload(payload: bytes) -> MsChapV2Capture | None:
    """Parse an EAP-MSCHAPv2 Response (opcode 2) body after the EAP type byte."""
    if len(payload) < 5 or payload[0] != _MSCHAP_OPCODE_RESPONSE:
        return None
    declared = struct.unpack(">H", payload[2:4])[0]
    # RFC 2759 / wpa_supplicant: MS-Length + 1-byte Value-Size (49) + 49-byte value + name.
    # Legacy compact: 2-byte value-size of 49 and no extra size byte.
    if declared != 49 and len(payload) >= 54 and payload[4] == 49:
        value = payload[5:54]
        name = payload[54:].split(b"\x00", 1)[0]
    elif declared == 49 and len(payload) >= 53:
        value = payload[4:53]
        name = payload[53:].split(b"\x00", 1)[0]
    else:
        return None
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


def is_complete_mschapv2_capture(capture: MsChapV2Capture) -> bool:
    """True when the honeypot has peer + server challenge and a non-empty NT-response."""
    return (
        len(capture.server_challenge) == 16
        and len(capture.peer_challenge) == 16
        and len(capture.nt_response) == 24
        and any(capture.nt_response)
    )


def mschapv2_challenge_hash(peer: bytes, server: bytes, username: str) -> bytes:
    """RFC 2759 ChallengeHash: SHA1(Peer || Authenticator || UserName)[:8]."""
    user, _domain = split_identity(username)
    return hashlib.sha1(peer + server + user.encode("ascii", errors="replace")).digest()[:8]


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(ch in "0123456789abcdefABCDEF" for ch in value)


def is_complete_hashcat5500_line(line: str) -> bool:
    """True for a Hashcat -m 5500 line that includes a 24-byte NT-response."""
    text = line.strip()
    parts = text.split(":")
    if len(parts) >= 6 and _is_hex(parts[-2], 48) and _is_hex(parts[-1], 16):
        return True
    if ":$MSCHAPv2$" in text or text.startswith("$MSCHAPv2$"):
        fields = text.split("$")
        return len(fields) >= 5 and _is_hex(fields[-1].strip(), 48)
    return False


def hashcat5500_challenge_line(username: str, challenge_hex: str) -> str:
    """Legacy challenge-only line. Not a Vault artifact (Hashcat will not load it)."""
    user = username.replace("\n", "").replace(":", "").strip() or "unknown"
    challenge = challenge_hex.replace(":", "").strip().upper()
    if len(challenge) != 32 or any(ch not in "0123456789ABCDEF" for ch in challenge):
        raise ValueError("MS-CHAPv2 challenge must be 16 bytes hex")
    return f"{user}:$MSCHAPv2${user}${challenge}$"


def hashcat5500_line(capture: MsChapV2Capture) -> str:
    """Native Hashcat -m 5500 (NetNTLMv1) from a complete PEAP MS-CHAPv2 capture."""
    if not is_complete_mschapv2_capture(capture):
        raise ValueError("incomplete MS-CHAPv2 capture")
    user = capture.username.replace("\n", "").replace(":", "")
    nt_hex = capture.nt_response.hex()
    chal8 = mschapv2_challenge_hash(
        capture.peer_challenge,
        capture.server_challenge,
        user,
    ).hex()
    return f"{user}::::{nt_hex}:{chal8}"


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
