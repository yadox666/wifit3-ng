"""Identify the station address a saved enterprise-probe capture transmitted as."""
from __future__ import annotations

import struct
from pathlib import Path

_PCAP_MAGIC = 0xA1B2C3D4
_LINKTYPE_IEEE802_11 = 105
_GLOBAL_HEADER = 24
_RECORD_HEADER = 16


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _is_unicast(mac: str) -> bool:
    try:
        return not (int(mac.split(":", 1)[0], 16) & 1)
    except (ValueError, IndexError):
        return False


def dominant_probe_station(path: Path) -> str | None:
    """Return the station that sent the probe's auth, association, and uplink frames.

    Probe captures mix our transmissions with the AP's replies. The address we
    used is the unicast transmitter of those uplink frames.
    """
    payload = path.read_bytes()
    if len(payload) < _GLOBAL_HEADER:
        return None
    magic, _major, _minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack_from(
        "<IHHiIII", payload, 0,
    )
    if magic != _PCAP_MAGIC or linktype != _LINKTYPE_IEEE802_11:
        return None
    counts: dict[str, int] = {}
    offset = _GLOBAL_HEADER
    while offset + _RECORD_HEADER <= len(payload):
        _seconds, _micros, included, original = struct.unpack_from("<IIII", payload, offset)
        offset += _RECORD_HEADER
        frame = payload[offset:offset + included]
        offset += included
        if included != original or len(frame) < 24:
            continue
        frame_control_0 = frame[0]
        frame_control_1 = frame[1]
        frame_type = (frame_control_0 >> 2) & 0x03
        subtype = (frame_control_0 >> 4) & 0x0F
        to_ds = bool(frame_control_1 & 0x01)
        from_ds = bool(frame_control_1 & 0x02)
        transmitter = _mac(frame[10:16])
        if not _is_unicast(transmitter):
            continue
        if frame_type == 0 and subtype in (0, 2, 11) and not to_ds and not from_ds:
            bssid = _mac(frame[16:22])
            destination = _mac(frame[4:10])
            if transmitter in (destination, bssid):
                continue
        elif not (frame_type == 2 and to_ds and not from_ds):
            continue
        counts[transmitter] = counts.get(transmitter, 0) + 1
    if not counts:
        return None
    top = max(counts.values())
    if top < 2:
        return None
    winners = [mac for mac, count in counts.items() if count == top]
    if len(winners) != 1:
        return None
    return winners[0]
