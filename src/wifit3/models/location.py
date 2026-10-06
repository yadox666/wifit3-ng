from __future__ import annotations

import math
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LocationFix:
    latitude: float
    longitude: float
    altitude_m: float | None
    accuracy_m: float
    observed_at: float
    source: str
    satellites: int | None = None
    fix_quality: int | None = None

    def is_usable(
        self,
        *,
        now: float | None = None,
        max_accuracy_m: float = 20.0,
    ) -> bool:
        now = time.time() if now is None else now
        return (
            -90.0 <= self.latitude <= 90.0
            and -180.0 <= self.longitude <= 180.0
            and 0.0 < self.accuracy_m <= max_accuracy_m
            and 0.0 <= now - self.observed_at <= 10.0
        )


def positions_digest(positions: list[SignalPosition]) -> str:
    """Stable signature for the latest fix (history write coalescing)."""
    if not positions:
        return ""
    latest = max(positions, key=lambda item: item.observed_at)
    return (
        f"{latest.latitude:.7f}:{latest.longitude:.7f}:"
        f"{latest.accuracy_m:.2f}:{latest.observed_at:.3f}"
    )


@dataclass(frozen=True, slots=True)
class SignalPosition:
    latitude: float
    longitude: float
    altitude_m: float | None
    accuracy_m: float
    observed_at: float
    source: str
    rssi: int | None


def distance_m(a: LocationFix | SignalPosition, b: LocationFix | SignalPosition) -> float:
    radius_m = 6_371_008.8
    lat1 = math.radians(a.latitude)
    lat2 = math.radians(b.latitude)
    delta_lat = lat2 - lat1
    delta_lon = math.radians(b.longitude - a.longitude)
    haversine = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * radius_m * math.asin(min(1.0, math.sqrt(haversine)))
