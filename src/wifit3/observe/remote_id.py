"""OpenDroneID message decode for Wi-Fi vendor IE FA:0B:BC and BLE UUID 0xFFFA."""
from __future__ import annotations

from dataclasses import dataclass


_MESSAGE_SIZE = 25
_STATUSES = {
    0: "Undeclared",
    1: "Ground",
    2: "Airborne",
    3: "Emergency",
    4: "Remote ID failure",
}


@dataclass(frozen=True, slots=True)
class RemoteIdReport:
    """Decoded Remote ID fields worth showing on one row."""

    status: str
    protocol_type: str
    summary: str
    alert: bool = True


def summarize_remote_id(payload: bytes) -> RemoteIdReport | None:
    """Summarize a counter-prefixed pack, a pack, or one or more 25-byte messages."""
    messages = _messages(payload)
    if not messages:
        return None
    status = ""
    heading: float | None = None
    speed: float | None = None
    latitude: float | None = None
    longitude: float | None = None
    pilot_latitude: float | None = None
    pilot_longitude: float | None = None
    uas_id = ""
    for message in messages:
        kind = message[0] >> 4
        if kind == 0 and not uas_id:
            uas_id = _text(message[2:22])
        elif kind == 1:
            status, heading, speed, latitude, longitude = _location(message)
        elif kind == 4:
            pilot_latitude, pilot_longitude = _pilot(message)
    if not any((status, uas_id, latitude, longitude, pilot_latitude, pilot_longitude)):
        return None
    status_label = status or "Undeclared"
    parts = [status_label]
    if heading is not None:
        parts.append(f"{heading:.0f}°")
    if speed is not None:
        parts.append(f"{speed:.1f} m/s")
    if latitude is not None and longitude is not None:
        parts.append(f"{latitude:.5f}, {longitude:.5f}")
    if pilot_latitude is not None and pilot_longitude is not None:
        parts.append(f"pilot {pilot_latitude:.5f}, {pilot_longitude:.5f}")
    if uas_id:
        parts.append(f"ID {uas_id}")
    summary = " · ".join(parts)
    return RemoteIdReport(
        status=status_label,
        protocol_type=f"Remote ID · {status_label}",
        summary=summary,
        alert=True,
    )


def _messages(payload: bytes) -> list[bytes]:
    candidates: list[bytes] = []
    if len(payload) >= 4 and (payload[1] >> 4) == 0xF and payload[2] == _MESSAGE_SIZE:
        candidates.append(payload[1:])
    if (
        payload[:1] == b"\x0d"
        and len(payload) >= 5
        and (payload[2] >> 4) == 0xF
        and payload[3] == _MESSAGE_SIZE
    ):
        candidates.append(payload[2:])
    candidates.append(payload)
    for candidate in candidates:
        found = _messages_from(candidate)
        if found and any((message[0] >> 4) in {0, 1, 4, 5} for message in found):
            return found
    return []


def _messages_from(data: bytes) -> list[bytes]:
    if len(data) >= 3 and (data[0] >> 4) == 0xF and data[1] == _MESSAGE_SIZE:
        count = data[2]
        body = data[3:]
        if 1 <= count <= 9 and len(body) >= count * _MESSAGE_SIZE:
            return [
                body[index * _MESSAGE_SIZE:(index + 1) * _MESSAGE_SIZE]
                for index in range(count)
            ]
        return []
    if len(data) < _MESSAGE_SIZE or (data[0] >> 4) > 5:
        return []
    count = len(data) // _MESSAGE_SIZE
    if count == 0 or count > 9:
        return []
    messages = [
        data[index * _MESSAGE_SIZE:(index + 1) * _MESSAGE_SIZE]
        for index in range(count)
    ]
    if any((message[0] >> 4) > 5 for message in messages):
        return []
    return messages


def _location(
    message: bytes,
) -> tuple[str, float | None, float | None, float | None, float | None]:
    flags = message[1]
    status = _STATUSES.get(flags >> 4, f"status {flags >> 4}")
    direction = message[2]
    heading = float(direction + (180 if flags & 0x02 else 0))
    if direction > 179:
        heading = None
    raw_speed = message[3]
    if flags & 0x01:
        speed = raw_speed * 0.75 + 63.75
    else:
        speed = raw_speed * 0.25
    if speed >= 254.25:
        speed = None
    latitude = _coordinate(message[5:9])
    longitude = _coordinate(message[9:13])
    return status, heading, speed, latitude, longitude


def _pilot(message: bytes) -> tuple[float | None, float | None]:
    return _coordinate(message[2:6]), _coordinate(message[6:10])


def _coordinate(raw: bytes) -> float | None:
    if len(raw) != 4:
        return None
    encoded = int.from_bytes(raw, "little", signed=True)
    if encoded == 0:
        return None
    value = encoded / 10_000_000
    if not -180.0 <= value <= 180.0:
        return None
    return value


def _text(raw: bytes) -> str:
    text = raw.split(b"\x00", 1)[0]
    if not text or any(byte < 0x20 or byte > 0x7E for byte in text):
        return ""
    return text.decode("ascii")
