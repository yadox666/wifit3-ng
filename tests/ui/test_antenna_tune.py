"""AntennaTune sample providers."""
from collections import deque
from types import SimpleNamespace

from wifit3.models import AccessPoint, Client
from wifit3.ui.antenna_tune import (
    ap_sample_provider,
    card_signal,
    client_sample_provider,
    resolve_tune_iface,
)
from wifit3.ui.antenna_tune_probe import AntennaTuneSession


def test_ap_sample_provider_reads_target():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Lab", channel=6, beacons=100,
        signal_by_card={"card0": -55},
    )
    array = SimpleNamespace(
        access_points={ap.bssid: ap},
        packet_stats=SimpleNamespace(snapshot=lambda _b: {"beacon": 10, "data": 3}),
        select_iface=lambda _ch: SimpleNamespace(
            transmitted_frames=5,
            product_name="TestCard",
            acks_seen=lambda _m: 0,
        ),
        forged_macs=set(),
    )
    app = SimpleNamespace(target_ap=ap, array=array)
    sample = ap_sample_provider(app, deque(), None)()
    assert sample is not None
    assert sample.heading == "AntennaTune"
    assert "Lab" in sample.subheading
    assert sample.dbm == -55
    assert sample.packet_totals["beacon"] == 10


def test_client_sample_provider_unassociated():
    client = Client(mac="11:22:33:44:55:66", signal_by_card={"a": -60})
    array = SimpleNamespace(
        access_points={},
        packet_stats=SimpleNamespace(snapshot=lambda _b: {"data": 1}),
        select_iface=lambda _ch: None,
        forged_macs=set(),
    )
    app = SimpleNamespace(target_client=client, array=array)
    sample = client_sample_provider(app)()
    assert sample is not None
    assert "unassociated" in sample.subheading


def test_resolve_tune_iface_prefers_session_card():
    chosen = SimpleNamespace(name="wlan1", supported_channels=[6], product_name="Alfa")
    other = SimpleNamespace(name="wlan0", supported_channels=[6], product_name="Other")
    array = SimpleNamespace(
        members=[other, chosen],
        select_iface=lambda _ch: other,
    )
    session = AntennaTuneSession(iface=chosen)
    assert resolve_tune_iface(array, 6, session) is chosen
    assert resolve_tune_iface(array, 36, session) is other


def test_card_signal_reads_named_adapter():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        signal_by_card={"wlan1": -42, "wlan0": -70},
    )
    iface = SimpleNamespace(name="wlan1", chipset="rtl8812au")
    assert card_signal(ap, iface) == -42
