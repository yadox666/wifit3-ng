from wifit3.models import SignalPosition
from wifit3.ui.location_format import (
    format_position_globe,
    google_maps_search_url,
)


def test_format_position_globe_is_icon_only():
    positions = [
        SignalPosition(51.502, -0.143, None, 12.0, 10, "gps", -48),
    ]
    assert format_position_globe(positions) == "🌐"
    assert format_position_globe(()) == "·"


def test_google_maps_search_url_uses_latest_fix_and_accuracy_label():
    positions = [
        SignalPosition(51.501, -0.142, None, 4.0, 10, "gps", -40),
        SignalPosition(51.502, -0.143, None, 6.0, 11, "gps", -48),
    ]
    url = google_maps_search_url(positions)
    assert url is not None
    assert url.startswith("https://www.google.com/maps/place/")
    # Bare coordinates in the place segment so Maps drops a pin + label.
    assert url.startswith(
        "https://www.google.com/maps/place/51.5020000%2C-0.1430000/@"
    )
    assert "/@51.5020000,-0.1430000," in url
    assert url.endswith("z")
    assert google_maps_search_url(()) is None


def test_prefer_best_uses_strongest_fix_not_latest():
    # Latest fix is weaker and less precise; best fix is the earlier strong one.
    positions = [
        SignalPosition(51.500, -0.140, None, 3.0, 100, "gps", -42),
        SignalPosition(51.900, -0.900, None, 18.0, 200, "gps", -80),
    ]
    latest = google_maps_search_url(positions)
    best = google_maps_search_url(positions, prefer_best=True)
    assert latest is not None and best is not None
    # Default follows recency (the weak, imprecise last fix).
    assert "/@51.9000000,-0.9000000," in latest
    # prefer_best pins the strongest, most precise fix.
    assert "place/51.5000000%2C-0.1400000/@" in best
    assert "/@51.5000000,-0.1400000," in best


def test_client_art_uses_dongle_not_router():
    from wifit3.ui.screens.focus_v2.art import client_art_name

    assert client_art_name("7c:1c:68:5a:5d:e6") == "focus-card.ans"
