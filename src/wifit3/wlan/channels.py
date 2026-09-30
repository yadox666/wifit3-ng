"""802.11 channel helpers: scan-hop ordering and per-band label/range compression."""
from __future__ import annotations

import math
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


# 1/6/11 are where most 2.4 GHz routers sit. The cycle opens on the first of these
# that the card can tune, then keeps going through every other channel.
_PRIORITY_2G = (1, 6, 11)


def _cycle_gaps(order: list[int]) -> list[int]:
    count = len(order)
    return [abs(order[index] - order[(index + 1) % count]) for index in range(count)]


def _spread(channels: list[int]) -> list[int]:
    """Order one band so the next hop is as far as possible from the one just visited.

    A 2.4 GHz AP is 20 MHz wide on centers only 5 MHz apart, so it is still decodable
    a few channel numbers away. Walking 1, 2, 3, 4 re-hears that same AP. A coprime
    stride visits every channel exactly once per cycle and keeps consecutive dwells
    (including the wrap back to the start) on non-overlapping spectrum.
    """
    chans = sorted(set(channels))
    count = len(chans)
    if count <= 2:
        return chans
    best = chans
    best_key: tuple | None = None
    for step in range(1, count):
        if math.gcd(step, count) != 1:
            continue
        order = [chans[(index * step) % count] for index in range(count)]
        pivot = order.index(chans[0])
        order = order[pivot:] + order[:pivot]
        gaps = _cycle_gaps(order)
        key = (min(gaps), sum(gaps), tuple(sorted(gaps, reverse=True)))
        if best_key is None or key > best_key:
            best_key = key
            best = order
    return best


def _rotate_to_priority(order: list[int]) -> list[int]:
    for channel in _PRIORITY_2G:
        if channel in order:
            index = order.index(channel)
            return order[index:] + order[:index]
    return order


def scan_hop_order(channels: list[int]) -> list[int]:
    """Visit every channel, but not in number order.

    2.4 GHz hops jump across the band so each dwell hears a different slice; the
    cycle still returns to every channel, because a weak AP may only decode on its
    own channel. 5 GHz follows, spread the same way across its own grid. Same
    channels in as out.
    """
    if not channels:
        return []
    band_24 = _rotate_to_priority(_spread([channel for channel in channels if channel <= 14]))
    band_5 = _spread([channel for channel in channels if channel > 14])
    return band_24 + band_5


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


# Passive monitor hop / channel-lock UI: every 5 GHz primary the stack can tune to.
# DFS slots (52–144) are included - scanning is RX-only and does not need radar CAC.
CHANNELS_5G_NON_DFS: tuple[int, ...] = (36, 40, 44, 48, 149, 153, 157, 161, 165)
CHANNELS_5G_DFS: tuple[int, ...] = (
    52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
)
CHANNELS_5G: tuple[int, ...] = CHANNELS_5G_NON_DFS + CHANNELS_5G_DFS
CHANNELS_2G: tuple[int, ...] = tuple(range(1, 15))
DUAL_BAND_SCAN_CHANNELS: list[int] = list(CHANNELS_2G) + list(CHANNELS_5G)


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
