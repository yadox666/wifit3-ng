"""Per-card scan band plans for the AP/Clients scanner hopper only."""
from __future__ import annotations

from typing import Literal, Mapping, Optional, Sequence

from wifit3.wlan.channels import scan_hop_order
from wifit3.wlan.interface import WlanInterface

ScanBand = Literal["all", "2g", "5g"]


def channels_for_scan_band(supported: Sequence[int], band: ScanBand) -> list[int]:
    chs = sorted(set(supported))
    if band == "2g":
        return [c for c in chs if c <= 14]
    if band == "5g":
        return [c for c in chs if c > 14]
    return chs


def _global_channel_pool(
    members: Sequence[WlanInterface],
    global_channels: Optional[list[int]],
) -> set[int]:
    if global_channels is not None:
        return set(global_channels)
    out: set[int] = set()
    for member in members:
        out.update(member.supported_channels)
    return out


def uses_per_card_scan_bands(
    members: Sequence[WlanInterface],
    band_by_instance: Mapping[tuple, ScanBand],
) -> bool:
    """True when at least one card is pinned to a single band (not ``all``)."""
    if not members:
        return False
    return any(band_by_instance.get(m.instance_key, "all") != "all" for m in members)


def member_channels_for_scan(
    members: Sequence[WlanInterface],
    global_channels: Optional[list[int]],
    band_by_instance: Mapping[tuple, ScanBand],
) -> Optional[dict[WlanInterface, list[int]]]:
    """Build per-interface hop lists, or ``None`` to keep the array's SPREAD partition.

    Intersects each card's band pick with the scanner's global channel lock (if any).
    """
    pool = [m for m in members if m.supported_channels]
    if not pool:
        return None
    if not uses_per_card_scan_bands(pool, band_by_instance):
        return None
    allowed = _global_channel_pool(pool, global_channels)
    assignment: dict[WlanInterface, list[int]] = {}
    for member in pool:
        band = band_by_instance.get(member.instance_key, "all")
        subset = [
            ch for ch in channels_for_scan_band(member.supported_channels, band)
            if ch in allowed
        ]
        ordered = scan_hop_order(subset)
        if ordered:
            assignment[member] = ordered
    return assignment or None
