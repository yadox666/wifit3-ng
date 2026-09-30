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
    assert store.positions_for_kind("wifi_ap")["aa"][0].longitude == 0.2


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


def test_stronger_signal_with_worse_precision_does_not_overwrite(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe(
        "wifi_ap", "AA", _fix(51.0, 0.0, accuracy=4.0), -70,
        mobile=False, movement_m=20,
    )
    # Stronger signal (-40 > -70) but a much larger GPS error radius (12 > 4):
    # it must NOT replace the more precise stored fix.
    positions = store.observe(
        "wifi_ap", "AA", _fix(51.5, 0.5, accuracy=12.0), -40,
        mobile=False, movement_m=20,
    )

    assert len(positions) == 1
    assert positions[0].latitude == 51.0
    assert positions[0].accuracy_m == 4.0
    assert positions[0].rssi == -70


def test_better_precision_at_equal_signal_updates(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe(
        "wifi_ap", "AA", _fix(51.0, 0.0, accuracy=8.0), -55,
        mobile=False, movement_m=20,
    )
    positions = store.observe(
        "wifi_ap", "AA", _fix(51.2, 0.2, accuracy=3.0), -55,
        mobile=False, movement_m=20,
    )

    assert len(positions) == 1
    assert positions[0].latitude == 51.2
    assert positions[0].accuracy_m == 3.0


def test_higher_signal_and_better_precision_updates(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe(
        "wifi_ap", "AA", _fix(51.0, 0.0, accuracy=8.0), -60,
        mobile=False, movement_m=20,
    )
    positions = store.observe(
        "wifi_ap", "AA", _fix(51.2, 0.2, accuracy=5.0), -45,
        mobile=False, movement_m=20,
    )

    assert len(positions) == 1
    assert positions[0].latitude == 51.2
    assert positions[0].rssi == -45
    assert positions[0].accuracy_m == 5.0


def test_sub_margin_jitter_does_not_rewrite(tmp_path):
    store = LocationStore(tmp_path / "locations.sqlite3")
    store.observe(
        "wifi_ap", "AA", _fix(51.0, 0.0, accuracy=5.0), -55,
        mobile=False, movement_m=20,
    )
    # +1 dB and 0.5 m more precise: both below the hysteresis margins, so the
    # stored fix must stay put instead of churning on noise.
    positions = store.observe(
        "wifi_ap", "AA", _fix(51.9, 0.9, accuracy=4.5), -54,
        mobile=False, movement_m=20,
    )

    assert len(positions) == 1
    assert positions[0].latitude == 51.0
    assert positions[0].rssi == -55
    assert positions[0].accuracy_m == 5.0


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
