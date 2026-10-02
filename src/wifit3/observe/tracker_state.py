"""DULT (UUID 0xFCB2) and Find Hub (UUID 0xFEAA frames 0x40/0x41) decoders."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TrackerState:
    """One decoded tracker advertisement."""

    category: str
    protocol_type: str
    detail: str
    alert: bool
    source: str
    confidence: str = "high"


_DULT_NETWORKS = {
    0x00: "reserved",
    0x01: "Apple",
    0x02: "Google",
    0x03: "Samsung",
    0x04: "Amazon",
    0xFF: "reserved",
}


def decode_dult(payload: bytes) -> TrackerState | None:
    """Decode a DULT location-enabled service-data value (bytes after UUID 0xFCB2)."""
    if len(payload) < 2:
        return None
    network = _DULT_NETWORKS.get(payload[0], f"network {payload[0]}")
    separated = (payload[1] & 0x01) == 0
    state = "Separated" if separated else "Near owner"
    detail = f"{state} · {network}"
    if separated:
        detail += ". The address can stay about a day"
    return TrackerState(
        category="Tracker",
        protocol_type=f"DULT tracker · {state}",
        detail=detail,
        alert=separated,
        source="DULT advertisement",
    )


def decode_find_hub(payload: bytes) -> TrackerState | None:
    """Decode Find Hub frames 0x40 (nearby) and 0x41 (separated). Other FEAA types are ignored."""
    if not payload or payload[0] not in (0x40, 0x41):
        return None
    separated = payload[0] == 0x41
    state = "Separated" if separated else "Nearby"
    detail = state
    if separated:
        detail += ". The address can stay about a day"
    return TrackerState(
        category="Tracker",
        protocol_type=f"Find Hub · {state}",
        detail=detail,
        alert=separated,
        source="Find Hub advertisement",
    )
