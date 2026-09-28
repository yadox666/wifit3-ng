"""802.11 channel helpers: scan-hop ordering and per-band label/range compression."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChannelSpec:
    """Primary channel plus the operating bandwidth advertised by an AP."""

    primary: int
    width_mhz: int = 20
    center_channel: int | None = None
    secondary_offset: int = 0

    def __post_init__(self) -> None:
        if self.width_mhz not in (20, 40):
            raise ValueError(f"unsupported channel width: {self.width_mhz} MHz")
        if self.width_mhz == 20:
            object.__setattr__(self, "center_channel", self.primary)
            object.__setattr__(self, "secondary_offset", 0)
        elif self.width_mhz == 40:
            if self.secondary_offset not in (-1, 1):
                raise ValueError("40 MHz requires a secondary channel above or below")
            expected = self.primary + 2 * self.secondary_offset
            if self.center_channel is None:
                object.__setattr__(self, "center_channel", expected)
            elif self.center_channel != expected:
                raise ValueError("40 MHz center channel conflicts with secondary offset")


def channel_spec_for_ap(ap) -> ChannelSpec:
    """Build a safe tune request from an AP's decoded Operation IEs."""
    caps = ap.capabilities
    width = caps.operating_width_mhz
    if width == 40 and caps.secondary_channel_offset in (-1, 1):
        return ChannelSpec(
            ap.channel,
            40,
            caps.center_channel_0,
            caps.secondary_channel_offset,
        )
    return ChannelSpec(ap.channel)


# The non-overlapping 2.4 GHz trio nearly every router parks on (FCC 1/6/11); visiting
# these first front-loads most 2.4 GHz targets into the first three hops.
_PRIORITY_2G = (1, 6, 11)


def scan_hop_order(channels: list[int]) -> list[int]:
    """Reorder a channel set into scan-priority order: the busy 2.4 GHz trio (1/6/11) first,
    then the rest of 2.4 GHz, then 5 GHz.

    Front-loads popular channels so the AP table is mostly populated before the first sort
    tick. Pure reordering: same channels; non-priority 2.4 GHz and 5 GHz keep the caller's
    original order.
    """
    priority = [c for c in _PRIORITY_2G if c in channels]
    rest_2g = [c for c in channels if c <= 14 and c not in _PRIORITY_2G]
    band_5g = [c for c in channels if c > 14]
    return priority + rest_2g + band_5g


def _split_bands(channels: list[int]) -> tuple[list[int], list[int]]:
    """Sorted, de-duped (2.4 GHz ≤14, 5 GHz >14) split of a channel set."""
    chs = sorted(set(channels))
    return [c for c in chs if c <= 14], [c for c in chs if c > 14]


def _compress_runs(channels: list[int], step: int) -> str:
    """Collapse a channel list into ``a-b, c, d-e``.

    ``step`` is the spacing between adjacent channels in that band: 1 on 2.4 GHz
    (1,2,3…) and 4 on the 5 GHz UNII grid (36,40,44,48…), so 36,40,44,48 renders
    ``36-48`` and any missing channel (e.g. an excluded DFS slot) breaks the run.
    """
    chs = sorted(channels)
    if not chs:
        return ""
    runs: list[tuple[int, int]] = []
    start = prev = chs[0]
    for c in chs[1:]:
        if c == prev + step:
            prev = c
        else:
            runs.append((start, prev))
            start = prev = c
    runs.append((start, prev))
    return ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in runs)


def band_label(channels: list[int]) -> str:
    """Bands present in a channel set: ``2.4 GHz``, ``5 GHz``, or ``2.4 GHz + 5 GHz``
    (empty string for none)."""
    ch_24, ch_5 = _split_bands(channels)
    parts = []
    if ch_24:
        parts.append("2.4 GHz")
    if ch_5:
        parts.append("5 GHz")
    return " + ".join(parts)


def band_ranges(channels: list[int]) -> list[tuple[str, str]]:
    """Per-band ``(name, compressed_ranges)`` for each band present, e.g.
    ``[("2.4 GHz", "1-13"), ("5 GHz", "36-48, 149-165")]``, the caller styles each
    piece. Bands absent from the set are omitted."""
    ch_24, ch_5 = _split_bands(channels)
    out: list[tuple[str, str]] = []
    if ch_24:
        out.append(("2.4 GHz", _compress_runs(ch_24, 1)))
    if ch_5:
        out.append(("5 GHz", _compress_runs(ch_5, 4)))
    return out
