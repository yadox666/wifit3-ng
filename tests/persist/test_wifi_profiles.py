import json

from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.probe import wpa2_beacon
from wifit3.dot11.parser import WlanFrameParser
from wifit3.persist.wifi_profiles import WifiProfileStore
from wifit3.wlan.sink import WlanSink


def test_wifi_profile_store_round_trips_public_beacon_profile(tmp_path):
    path = tmp_path / "wifi_profiles.json"
    store = WifiProfileStore(path)
    beacon = wpa2_beacon(
        bytes.fromhex("001122334455"),
        "Test Network",
        6,
    )

    store.remember(
        bssid="00:11:22:33:44:55",
        ssid="Test Network",
        channel=6,
        beacon=beacon,
        rsn_ie=GENERIC_RSN_IE,
        akm_suites=[2],
        pmf_capable=True,
        pmf_required=False,
        now=100,
    )

    payload = json.loads(path.read_text("utf-8"))
    assert payload["version"] == 1
    assert len(payload["profiles"]) == 1
    assert path.stat().st_mode & 0o777 == 0o600

    restored = WifiProfileStore(path).profiles_for_ssid("Test Network")
    assert len(restored) == 1
    assert restored[0].rsn_ie == GENERIC_RSN_IE
    assert restored[0].akm_suites == [2]
    assert restored[0].pmf_capable is True


def test_wifi_profile_store_rejects_invalid_rsn(tmp_path):
    path = tmp_path / "wifi_profiles.json"
    store = WifiProfileStore(path)

    store.remember(
        bssid="00:11:22:33:44:55",
        ssid="Test Network",
        channel=6,
        beacon=b"\x00" * 64,
        rsn_ie=b"\x30\x10bad",
        akm_suites=[2],
        pmf_capable=False,
        pmf_required=False,
    )

    assert store.records == {}
    assert not path.exists()


def test_sink_automatically_persists_observed_psk_profile(tmp_path):
    store = WifiProfileStore(tmp_path / "wifi_profiles.json")
    sink = WlanSink(wifi_profiles=store)
    beacon = wpa2_beacon(
        bytes.fromhex("001122334455"),
        "Observed Network",
        6,
    )

    sink.update(
        WlanFrameParser.parse_80211_frame(beacon, -40),
        "card0",
        6,
    )

    profiles = store.profiles_for_ssid("Observed Network")
    assert len(profiles) == 1
    assert profiles[0].bssid == "00:11:22:33:44:55"
    assert profiles[0].akm_suites == [2]
