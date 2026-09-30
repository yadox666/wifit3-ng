from types import SimpleNamespace

from wifit3.ui.screens.focus_v2.card_endpoint import (
    campaign_expected_channel,
    format_iface_channel,
)
from wifit3.ui.screens.focus_v2.cards_column import _iface_role, _ordered_members


def test_format_iface_channel_shows_locked_channel():
    iface = SimpleNamespace(
        current_channel=5,
        current_channel_spec=SimpleNamespace(width_mhz=20),
        _is_hopping=False,
    )
    assert format_iface_channel(iface, claimed=True) == "CH 5 · lock"


def test_format_iface_channel_hopping():
    iface = SimpleNamespace(current_channel=11, _is_hopping=True)
    assert format_iface_channel(iface) == "CH 11 · hop"


def test_iface_role_for_portal_twin():
    twin = object()
    punt = object()
    active = SimpleNamespace(twin_iface=twin, punt_iface=punt)
    assert _iface_role(twin, active) == " · AP"
    assert _iface_role(punt, active) == " · deauth"


def test_format_iface_channel_shows_live_vs_campaign_mismatch():
    iface = SimpleNamespace(
        current_channel=8,
        current_channel_spec=SimpleNamespace(width_mhz=20),
        _is_hopping=False,
    )
    assert format_iface_channel(iface, expected=4) == "CH 8 ≠ 4"


def test_campaign_expected_channel_portal_twin_legs():
    twin = object()
    punt = object()
    active = SimpleNamespace(twin_iface=twin, punt_iface=punt, twin_channel=4, target_channel=8)
    assert campaign_expected_channel(twin, active) == 4
    assert campaign_expected_channel(punt, active) == 8


def test_ordered_members_puts_primary_first():
    a = SimpleNamespace(name="wlan0")
    b = SimpleNamespace(name="wlan1")
    assert _ordered_members([a, b], b) == [b, a]
