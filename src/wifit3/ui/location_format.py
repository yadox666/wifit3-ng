from __future__ import annotations

import math
from collections.abc import Iterable
from urllib.parse import quote

from rich.text import Text

from wifit3.models.location import SignalPosition


def latest_position(
    positions: Iterable[SignalPosition],
) -> SignalPosition | None:
    return max(positions, key=lambda position: position.observed_at, default=None)


def _quality_key(position: SignalPosition) -> tuple[float, float, float]:
    """Rank a fix best-first: strongest signal, then smallest error radius,
    then most recent. Missing RSSI counts as the weakest signal."""
    rssi = float("-inf") if position.rssi is None else float(position.rssi)
    return (rssi, -position.accuracy_m, position.observed_at)


def best_position(
    positions: Iterable[SignalPosition],
) -> SignalPosition | None:
    """Highest-quality fix for a stationary entity (e.g. an AP): the strongest
    RSSI, breaking ties by better GPS accuracy and then recency. For moving
    entities prefer ``latest_position`` (where the device was last seen)."""
    return max(positions, key=_quality_key, default=None)


def format_position(positions: Iterable[SignalPosition]) -> str:
    position = latest_position(positions)
    if position is None:
        return "·"
    return (
        f"{position.latitude:.5f}, {position.longitude:.5f} "
        f"±{position.accuracy_m:.0f}m"
    )


def format_position_globe(positions: Iterable[SignalPosition]) -> str:
    """Compact GPS column: globe only (accuracy is shown in the Maps link query)."""
    position = latest_position(positions)
    if position is None:
        return "·"
    return "🌐"


def _maps_zoom_for_accuracy(latitude: float, accuracy_m: float) -> int:
    """Pick a street-level zoom so the accuracy radius is visible on screen."""
    if accuracy_m <= 0:
        return 18
    # ~512 px wide; aim to fit ~4× the error radius across the view.
    meters_per_pixel = max(accuracy_m * 4 / 256, 0.25)
    cos_lat = max(0.05, math.cos(math.radians(latitude)))
    zoom = math.log2(156543.03392 * cos_lat / meters_per_pixel)
    return int(max(10, min(21, round(zoom))))


def google_maps_search_url(
    positions: Iterable[SignalPosition],
    *,
    prefer_best: bool = False,
) -> str | None:
    """Open Google Maps with a dropped pin and label at the exact fix.

    Only a geocodable ``/place/`` segment makes Maps drop a marker and show a
    label. Free text (e.g. ``±6m``) or ``lat,lng (±Nm)`` is discarded, leaving
    ``/place//@…`` with no pin. Putting the bare ``lat,lng`` in the place
    segment resolves to the exact point: Maps pins it and labels it with the
    coordinates. Accuracy only drives the zoom level.

    With ``prefer_best`` (stationary entities such as APs) the strongest,
    most precise fix is pinned; otherwise the most recent fix is used.
    """
    position = (
        best_position(positions) if prefer_best else latest_position(positions)
    )
    if position is None:
        return None
    lat = position.latitude
    lng = position.longitude
    coords = quote(f"{lat:.7f},{lng:.7f}", safe="")
    zoom = _maps_zoom_for_accuracy(lat, position.accuracy_m)
    return f"https://www.google.com/maps/place/{coords}/@{lat:.7f},{lng:.7f},{zoom}z"


def location_globe_cell(
    positions: Iterable[SignalPosition],
    *,
    dim: bool = False,
) -> Text:
    position = latest_position(positions)
    if position is None:
        return Text("·", style="dim")
    prefix = "dim " if dim else ""
    return Text(
        format_position_globe(positions),
        style=f"{prefix}cyan",
        no_wrap=True,
    )
