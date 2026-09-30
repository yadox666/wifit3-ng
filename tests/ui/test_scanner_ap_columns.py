"""Scan table country + uptime column helpers."""
from wifit3.ui.screens.scanner import format_ap_uptime


def test_format_ap_uptime_compact():
    assert format_ap_uptime(None) == ""
    assert format_ap_uptime(45_000_000) == "45s"
    assert format_ap_uptime(754_000_000) == "12m 34s"
    assert format_ap_uptime(11_580_000_000) == "3h 13m"
    assert format_ap_uptime(270_000_000_000) == "3d 03h"
