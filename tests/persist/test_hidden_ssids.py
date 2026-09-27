import json

from wifit3.persist.hidden_ssids import HiddenSsidStore


def test_hidden_ssid_store_round_trips_and_updates_record(tmp_path):
    path = tmp_path / "hidden_ssids.json"
    store = HiddenSsidStore(path)
    store.remember("AA:BB:CC:DD:EE:FF", "Old Name", "probe_resp")
    first_revealed = store.records["aa:bb:cc:dd:ee:ff"].first_revealed_at
    store.remember("aa:bb:cc:dd:ee:ff", "New Name", "assoc_req")

    loaded = HiddenSsidStore(path)
    record = loaded.records["aa:bb:cc:dd:ee:ff"]
    assert loaded.lookup("AA:BB:CC:DD:EE:FF") == "New Name"
    assert record.first_revealed_at == first_revealed
    assert record.reveal_method == "assoc_req"
    assert json.loads(path.read_text("utf-8"))["version"] == 1


def test_hidden_ssid_store_ignores_invalid_names(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.json")
    store.remember("aa:bb:cc:dd:ee:ff", "<hidden>", "beacon")
    store.remember("", "Network", "beacon")
    assert store.records == {}


def test_client_probes_round_trip_without_becoming_bssid_mappings(tmp_path):
    path = tmp_path / "hidden_ssids.json"
    store = HiddenSsidStore(path)
    store.remember_probe(
        "02:11:22:33:44:55", "DefaultSSID", 1, now=100,
    )
    store.remember_probe(
        "02:11:22:33:44:55", "DefaultSSID", 6, now=106,
    )

    loaded = HiddenSsidStore(path)
    record = loaded.probes_for_client("02:11:22:33:44:55")[0]
    assert record.ssid == "DefaultSSID"
    assert record.channels == [1, 6]
    assert record.last_channel == 6
    assert record.first_seen == 100
    assert record.last_seen == 106
    assert record.count == 2
    assert loaded.records == {}
    payload = json.loads(path.read_text("utf-8"))
    assert payload["client_probes"][0]["ssid"] == "DefaultSSID"
