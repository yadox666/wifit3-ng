"""Frames this process just transmitted.

Nearby-threat detection uses this to ignore our own injections. A deauth
spoofs the AP as the transmitter, so matching the adapter MAC is not enough.
The fingerprint is taken after the sequence number is stamped.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

_EXACT_WINDOW_S = 1.0
_ADDR_WINDOW_S = 0.30
_BEACON_WINDOW_S = 120.0
_MAX_MARKS = 512
_MGMT = 0
_BEACON = 0x08
_PROBE_RESP = 0x05
_DISASSOC = 0x0A
_DEAUTH = 0x0C


@dataclass(frozen=True)
class _Mark:
    subtype: int
    addr1: bytes
    addr2: bytes
    addr3: bytes
    seq: int
    reason: int | None
    at: float


_lock = threading.Lock()
_marks: deque[_Mark] = deque(maxlen=_MAX_MARKS)


def clear() -> None:
    """Drop every remembered transmission. Tests use this between cases."""
    with _lock:
        _marks.clear()


def note_own_transmission(frame: bytes, *, now: float | None = None) -> None:
    """Remember one management frame we are about to send."""
    if len(frame) < 24:
        return
    fc0 = frame[0]
    if ((fc0 >> 2) & 0x03) != _MGMT:
        return
    subtype = (fc0 >> 4) & 0x0F
    seq = (int.from_bytes(frame[22:24], "little") >> 4) & 0xFFF
    reason = None
    protected = bool(frame[1] & 0x40)
    if subtype in (_DISASSOC, _DEAUTH) and len(frame) >= 26 and not protected:
        reason = int.from_bytes(frame[24:26], "little")
    mark = _Mark(
        subtype,
        bytes(frame[4:10]),
        bytes(frame[10:16]),
        bytes(frame[16:22]),
        seq,
        reason,
        time.monotonic() if now is None else now,
    )
    with _lock:
        _marks.append(mark)


def is_own_transmission(frame: bytes, *, now: float | None = None) -> bool:
    """True when this received frame matches one we just transmitted."""
    if len(frame) < 24:
        return False
    fc0 = frame[0]
    if ((fc0 >> 2) & 0x03) != _MGMT:
        return False
    subtype = (fc0 >> 4) & 0x0F
    seq = (int.from_bytes(frame[22:24], "little") >> 4) & 0xFFF
    protected = bool(frame[1] & 0x40)
    reason = None
    if subtype in (_DISASSOC, _DEAUTH) and len(frame) >= 26 and not protected:
        reason = int.from_bytes(frame[24:26], "little")
    addr1 = bytes(frame[4:10])
    addr2 = bytes(frame[10:16])
    addr3 = bytes(frame[16:22])
    moment = time.monotonic() if now is None else now
    with _lock:
        for mark in reversed(_marks):
            age = moment - mark.at
            if age > _EXACT_WINDOW_S:
                break
            if (
                mark.subtype != subtype
                or mark.addr1 != addr1
                or mark.addr2 != addr2
                or mark.addr3 != addr3
                or mark.reason != reason
            ):
                continue
            if mark.seq == seq:
                return True
            if age <= _ADDR_WINDOW_S:
                return True
    return False


def recent_beacon_bssids(*, now: float | None = None) -> frozenset[str]:
    """BSSIDs of beacons and probe responses we transmitted recently."""
    moment = time.monotonic() if now is None else now
    found: set[str] = set()
    with _lock:
        for mark in _marks:
            if moment - mark.at > _BEACON_WINDOW_S:
                continue
            if mark.subtype in (_BEACON, _PROBE_RESP):
                found.add(_mac(mark.addr3))
    return frozenset(found)


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)
