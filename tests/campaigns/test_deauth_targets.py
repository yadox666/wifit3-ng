"""Deauth target ordering: strongest associated client first."""
from types import SimpleNamespace

from wifit3.campaigns.deauth_targets import associated_client_macs, sort_macs_by_signal


def _client(*, bssid, signal=-50, last_seen=1000.0, is_fake=False):
    return SimpleNamespace(
        bssid=bssid,
        signal=signal,
        last_seen=last_seen,
        is_fake=is_fake,
    )


def test_associated_client_macs_sorts_by_signal():
    array = SimpleNamespace(
        forged_macs=set(),
        clients={
            "aa:aa:aa:aa:aa:01": _client(bssid="bb:bb:bb:bb:bb:bb", signal=-70),
            "aa:aa:aa:aa:aa:02": _client(bssid="bb:bb:bb:bb:bb:bb", signal=-40),
            "aa:aa:aa:aa:aa:03": _client(bssid="cc:cc:cc:cc:cc:cc", signal=-30),
        },
    )
    assert associated_client_macs(array, "bb:bb:bb:bb:bb:bb") == [
        "aa:aa:aa:aa:aa:02",
        "aa:aa:aa:aa:aa:01",
    ]


def test_associated_client_macs_respects_live_window():
    now = 1_000_000.0
    array = SimpleNamespace(
        forged_macs=set(),
        clients={
            "aa:aa:aa:aa:aa:01": _client(
                bssid="bb:bb:bb:bb:bb:bb", signal=-40, last_seen=now - 5.0,
            ),
            "aa:aa:aa:aa:aa:02": _client(
                bssid="bb:bb:bb:bb:bb:bb", signal=-60, last_seen=now - 30.0,
            ),
        },
    )
    assert associated_client_macs(
        array, "bb:bb:bb:bb:bb:bb", live_within_sec=10.0, now=now,
    ) == ["aa:aa:aa:aa:aa:01"]


def test_sort_macs_by_signal():
    array = SimpleNamespace(
        clients={
            "11:11:11:11:11:11": _client(bssid="x", signal=-55),
            "22:22:22:22:22:22": _client(bssid="x", signal=-35),
        },
    )
    assert sort_macs_by_signal(array, ["11:11:11:11:11:11", "22:22:22:22:22:22"]) == [
        "22:22:22:22:22:22",
        "11:11:11:11:11:11",
    ]
