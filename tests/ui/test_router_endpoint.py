from wifit3.ui.screens.focus_v2.router_endpoint import RouterEndpoint


def test_router_uptime_formats_compactly():
    router = RouterEndpoint(uptime_us=45_000_000)
    assert router._uptime_label() == "uptime 45s"

    router._uptime_us = 754_000_000
    assert router._uptime_label() == "uptime 12m 34s"

    router._uptime_us = 11_580_000_000
    assert router._uptime_label() == "uptime 3h 13m"

    router._uptime_us = 270_000_000_000
    assert router._uptime_label() == "uptime 3d 03h"


def test_router_uptime_is_unknown_before_a_beacon_timestamp():
    assert RouterEndpoint()._uptime_label() == "uptime unknown"


def test_router_uptime_includes_advertised_country():
    router = RouterEndpoint(uptime_us=270_000_000_000, country_code="US")
    assert router._uptime_label() == "uptime 3d 03h · US"

    router = RouterEndpoint(country_code="DE")
    assert router._uptime_label() == "uptime unknown · DE"


def test_router_shows_plain_operating_channel_summary():
    router = RouterEndpoint(channel=36, channel_label="channel 36 · 80 MHz")
    assert router._identity_label() == "channel 36 · 80 MHz"


def test_historical_ssid_is_marked_yellow_without_modifying_name():
    markup = RouterEndpoint._essid_markup("Seen Before", note="history")

    assert "on yellow" in markup
    assert "Seen Before" in markup
    assert "history" in markup
    assert "Seen Before?" not in markup
