import json
import sqlite3

from wifit3.persist.hidden_ssids import HiddenSsidStore


def test_hidden_ssid_store_round_trips_and_updates_record(tmp_path):
    path = tmp_path / "hidden_ssids.sqlite3"
    store = HiddenSsidStore(path)
    store.remember("AA:BB:CC:DD:EE:FF", "Old Name", "probe_resp")
    first_revealed = store.records["aa:bb:cc:dd:ee:ff"].first_revealed_at
    store.remember("aa:bb:cc:dd:ee:ff", "New Name", "assoc_req")

    loaded = HiddenSsidStore(path)
    record = loaded.records["aa:bb:cc:dd:ee:ff"]
    assert loaded.lookup("AA:BB:CC:DD:EE:FF") == "New Name"
    assert record.first_revealed_at == first_revealed
    assert record.reveal_method == "assoc_req"
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM hidden_networks"
        ).fetchone()[0] == 1


def test_hidden_ssid_store_ignores_invalid_names(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.sqlite3")
    store.remember("aa:bb:cc:dd:ee:ff", "<hidden>", "beacon")
    store.remember("", "Network", "beacon")
    assert store.records == {}


def test_client_probes_round_trip_without_becoming_bssid_mappings(tmp_path):
    path = tmp_path / "hidden_ssids.sqlite3"
    store = HiddenSsidStore(path)
    store.remember_probe(
        "18:7f:88:33:44:55", "DefaultSSID", 1, now=100,
    )
    store.remember_probe(
        "18:7f:88:33:44:55", "DefaultSSID", 6, now=106,
    )

    loaded = HiddenSsidStore(path)
    record = loaded.probes_for_client("18:7f:88:33:44:55")[0]
    assert record.ssid == "DefaultSSID"
    assert record.channels == [1, 6]
    assert record.last_channel == 6
    assert record.first_seen == 100
    assert record.last_seen == 106
    assert record.count == 2
    assert loaded.records == {}
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT ssid FROM client_probes"
        ).fetchone()[0] == "DefaultSSID"


def test_randomized_and_unknown_probe_macs_are_not_persisted(tmp_path):
    path = tmp_path / "hidden_ssids.sqlite3"
    store = HiddenSsidStore(path)

    store.remember_probe("02:11:22:33:44:55", "Randomized", 1)
    store.remember_probe("10:12:34:56:78:9a", "Unknown vendor", 1)

    assert store.client_probes == {}
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM client_probes").fetchone()[0] == 0


def test_existing_randomized_probe_rows_are_pruned_on_open(tmp_path):
    path = tmp_path / "hidden_ssids.sqlite3"
    store = HiddenSsidStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO client_probes VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("02:11:22:33:44:55", "Old random probe", "[1]", 1, 1, 2, 1),
        )

    reopened = HiddenSsidStore(path)

    assert reopened.client_probes == {}
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM client_probes").fetchone()[0] == 0


def test_hidden_ssid_store_migrates_and_removes_legacy_json(tmp_path):
    legacy = tmp_path / "hidden_ssids.json"
    legacy.write_text(json.dumps({
        "version": 1,
        "networks": [{
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "Migrated",
            "first_revealed_at": 1,
            "last_revealed_at": 2,
            "reveal_method": "probe_resp",
        }],
        "client_probes": [],
    }))

    store = HiddenSsidStore(
        tmp_path / "hidden_ssids.sqlite3", legacy_path=legacy,
    )

    assert store.lookup("aa:bb:cc:dd:ee:ff") == "Migrated"
    assert not legacy.exists()
