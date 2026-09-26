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
