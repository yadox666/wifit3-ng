import csv
import json

from wifit3.models import AccessPoint, Client
from wifit3.persist.config import Config
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
    ap.capabilities.phy_modes.add("802.11ax")
    client = Client(
        mac="66:77:88:99:AA:BB",
        bssid=ap.bssid,
        packets=12,
        probed_ssids={"Coffee", "Home"},
    )
    client.signal_by_card = {"card0": -55}

    json_path, csv_path = export_scan_snapshot([ap], [client])

    report = json.loads(json_path.read_text("utf-8"))
    assert report["access_points"][0]["country"] == "US"
    assert report["access_points"][0]["capabilities"]["phy_modes"] == ["802.11ax"]
    assert report["clients"][0]["connected_ssid"] == "Test Network"
    assert report["clients"][0]["probe_requests"] == ["Coffee", "Home"]

    with csv_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["type"] for row in rows] == ["access_point", "client"]
    assert rows[0]["name"] == "Test Network"
    assert rows[1]["activity"] == "12"
