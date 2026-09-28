import time

from wifit3.models import LocationFix
from wifit3.persist.locations import LocationStore


def _fix(latitude: float, longitude: float, accuracy: float = 5.0) -> LocationFix:
    return LocationFix(
        latitude=latitude,
        longitude=longitude,
        altitude_m=10.0,
        accuracy_m=accuracy,
        observed_at=time.time(),
        source="nmea:gga",
    )


def test_fixed_entity_keeps_strongest_signal_position(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe("wifi_ap", "AA", _fix(51.0, 0.0), -60, mobile=False, movement_m=20)
    store.observe("wifi_ap", "AA", _fix(51.1, 0.1), -70, mobile=False, movement_m=20)
    positions = store.observe(
        "wifi_ap", "AA", _fix(51.2, 0.2), -40, mobile=False, movement_m=20,
    )

    assert len(positions) == 1
    assert positions[0].latitude == 51.2
    assert positions[0].rssi == -40


def test_mobile_entity_adds_position_after_movement_threshold(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe("bluetooth", "AA", _fix(51.0, 0.0), -50, mobile=True, movement_m=20)
    nearby = store.observe(
        "bluetooth", "AA", _fix(51.00005, 0.0), -60, mobile=True, movement_m=20,
    )
    moved = store.observe(
        "bluetooth", "AA", _fix(51.00030, 0.0), -60, mobile=True, movement_m=20,
    )

    assert len(nearby) == 1
    assert len(moved) == 2


def test_rejects_stale_or_inaccurate_fix(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    stale = LocationFix(51.0, 0.0, None, 5.0, time.time() - 20, "nmea:gga")
    inaccurate = _fix(51.0, 0.0, 25.0)

    assert store.observe("wifi_ap", "AA", stale, -40, mobile=False, movement_m=20) == []
    assert store.observe(
        "wifi_ap", "AA", inaccurate, -40, mobile=False, movement_m=20,
    ) == []
    accepted = store.observe(
        "wifi_ap", "AA", inaccurate, -40, mobile=False, movement_m=20,
        max_accuracy_m=30,
    )
    assert len(accepted) == 1
