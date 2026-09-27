import csv
import json

from wifit3.models import AccessPoint, Client, ProbeObservation
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.probe import wpa2_beacon
from wifit3.persist.config import Config
from wifit3.persist.rsn_profiles import load_scan_rsn_profiles
from wifit3.ui.scan_export import export_scan_snapshot


def test_scan_export_writes_json_and_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    ap = AccessPoint(
        bssid="00:11:22:33:44:55",
        ssid="Test Network",
        channel=6,
        encryption="WPA2",
        country_code="US",
    )
    ap.signal_by_card = {"card0": -42}
    ap.akms = ["PSK"]
    ap.akm_suites = [2]
    ap.last_beacon_frame = wpa2_beacon(
        bytes.fromhex("001122334455"), ap.ssid, ap.channel,
    )
    ap.capabilities.phy_modes.add("802.11ax")
    client = Client(
        mac="66:77:88:99:AA:BB",
        bssid=ap.bssid,
        packets=12,
        probed_ssids={"Coffee", "Home"},
        probe_observations={
            "Coffee": ProbeObservation(
                channel=6, first_seen=100, last_seen=120, count=3,
            ),
        },
    )
    client.signal_by_card = {"card0": -55}

    json_path, csv_path = export_scan_snapshot([ap], [client])

    report = json.loads(json_path.read_text("utf-8"))
    assert report["access_points"][0]["country"] == "US"
    assert report["access_points"][0]["rsn_ie_hex"] == GENERIC_RSN_IE.hex()
    assert report["access_points"][0]["capabilities"]["phy_modes"] == ["802.11ax"]
    assert report["clients"][0]["connected_ssid"] == "Test Network"
    assert report["clients"][0]["probe_requests"] == ["Coffee", "Home"]
    assert report["clients"][0]["probe_observations"]["Coffee"]["channel"] == 6
    assert report["clients"][0]["probe_observations"]["Coffee"]["count"] == 3

    with csv_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["type"] for row in rows] == ["access_point", "client"]
    assert rows[0]["name"] == "Test Network"
    assert rows[1]["activity"] == "12"

    profiles = load_scan_rsn_profiles("Test Network")
    assert len(profiles) == 1
    assert profiles[0].rsn_ie == GENERIC_RSN_IE
    assert profiles[0].akm_suites == (2,)
