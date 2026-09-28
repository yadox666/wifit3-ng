from __future__ import annotations

from collections.abc import Iterable

from wifit3.models.location import SignalPosition


def latest_position(
    positions: Iterable[SignalPosition],
) -> SignalPosition | None:
    return max(positions, key=lambda position: position.observed_at, default=None)


def format_position(positions: Iterable[SignalPosition]) -> str:
    position = latest_position(positions)
    if position is None:
        return "·"
    return (
        f"{position.latitude:.5f}, {position.longitude:.5f} "
        f"±{position.accuracy_m:.0f}m"
    )
