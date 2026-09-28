import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from wifit3.models import AccessPoint, IdKey, IdSource
from wifit3.persist.ap_history import ApHistoryStore, SCHEMA_VERSION


BSSID = "aa:bb:cc:dd:ee:ff"


def test_creates_versioned_private_database(tmp_path):
    path = tmp_path / "private" / "history.sqlite3"
    store = ApHistoryStore(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert store.count() == 0
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o077 == 0


def test_migrates_version_one_database(tmp_path):
    path = tmp_path / "history.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE access_points (bssid TEXT PRIMARY KEY)")
        connection.execute("PRAGMA user_version = 1")

    store = ApHistoryStore(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
            )
        }
    assert "ap_relationships" in tables
    store.close()


def test_remember_and_enrich_observed_ap_without_creating_rows(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    learned = AccessPoint(
        bssid=BSSID, ssid="Remembered", channel=44, encryption="WPA2",
    )
    learned.country_code = "ES"
    learned.akms = ["PSK"]
    learned.capabilities.phy_modes = {"802.11ac"}
    learned.capabilities.operating_width_mhz = 80
    assert store.remember(learned, force=True)

    observed = AccessPoint(
        bssid=BSSID, ssid=None, channel=44, encryption="Unknown",
    )
    assert store.enrich(observed)
    assert observed.ssid == "Remembered"
    assert observed.decloak_method == "history"
    assert observed.encryption == "WPA2"
    assert observed.country_code == "ES"
    assert observed.akms == ["PSK"]
    assert observed.capabilities.phy_modes == {"802.11ac"}
    assert observed.capabilities.operating_width_mhz == 80
    assert store.count() == 1


def test_live_radio_and_security_evidence_wins_over_history(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    old = AccessPoint(bssid=BSSID, ssid="AP", encryption="WPA2")
    old.akms = ["PSK"]
    old.capabilities.operating_width_mhz = 40
    store.remember(old, force=True)

    live = AccessPoint(bssid=BSSID, ssid="AP", encryption="WPA3")
    live.akms = ["SAE"]
    live.capabilities.operating_width_mhz = 80
    store.enrich(live)

    assert live.encryption == "WPA3"
    assert live.akms == ["SAE"]
    assert live.capabilities.operating_width_mhz == 80


def test_identity_evidence_is_restored_per_source(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    learned = AccessPoint(bssid=BSSID, ssid="AP")
    learned.identity.set(IdSource.OUI, IdKey.MANUFACTURER, "OUI vendor")
    learned.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "Beacon vendor")
    learned.identity.set(IdSource.WSC_M1, IdKey.MODEL_NAME, "Router 9000")
    store.remember(learned, force=True)

    observed = AccessPoint(bssid=BSSID)
    store.enrich(observed)

    assert observed.identity.get_source_value(
        IdKey.MANUFACTURER, IdSource.OUI,
    ) == "OUI vendor"
    assert observed.identity.get_source_value(
        IdKey.MANUFACTURER, IdSource.WSC_BEACON,
    ) == "Beacon vendor"
    assert observed.identity.get_source_value(
        IdKey.MODEL_NAME, IdSource.WSC_M1,
    ) == "Router 9000"


def test_sibling_relationships_are_restored_without_synthetic_aps(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    learned = AccessPoint(bssid=BSSID, ssid="AP")
    learned.siblings = ["aa:bb:cc:dd:ee:fe"]
    store.remember(learned, force=True)

    observed = AccessPoint(bssid=BSSID)
    store.enrich(observed)

    assert observed.siblings == ["aa:bb:cc:dd:ee:fe"]
    assert store.count() == 1


def test_client_associations_are_bidirectional_and_survive_reopen(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = ApHistoryStore(path)
    store.remember(
        AccessPoint(bssid=BSSID, ssid="Remembered", channel=6, encryption="WPA2"),
        force=True,
    )
    assert store.remember_client_association(
        BSSID, "12:34:56:78:9a:bc", observed_at=100, force=True,
    )
    store.close()

    reopened = ApHistoryStore(path)
    clients = reopened.clients_for_ap(BSSID)
    aps = reopened.aps_for_client("12:34:56:78:9a:bc")

    assert [(row.client_mac, row.last_seen) for row in clients] == [
        ("12:34:56:78:9a:bc", 100),
    ]
    assert [(row.bssid, row.ssid, row.channel) for row in aps] == [
        (BSSID, "Remembered", 6),
    ]


def test_offline_records_include_full_ap_and_client_relationships(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    ap = AccessPoint(
        bssid=BSSID, ssid="Remembered", channel=6, encryption="WPA2",
    )
    ap.akms = ["PSK"]
    ap.siblings = ["aa:bb:cc:dd:ee:00"]
    ap.identity.set(IdSource.OUI, IdKey.MANUFACTURER, "Example")
    store.remember(ap, force=True)
    store.remember_client_association(
        BSSID, "12:34:56:78:9a:bc", observed_at=100, force=True,
    )

    access_points = store.offline_access_points()
    clients = store.offline_clients()

    assert access_points[0]["security"]["akms"] == ["PSK"]
    assert access_points[0]["identity_evidence"][0]["value"] == "Example"
    assert access_points[0]["relationships"][0]["related_bssid"] == (
        "aa:bb:cc:dd:ee:00"
    )
    assert access_points[0]["clients"][0]["client_mac"] == "12:34:56:78:9a:bc"
    assert clients[0]["client_mac"] == "12:34:56:78:9a:bc"
    assert clients[0]["access_points"][0]["ssid"] == "Remembered"


def test_imports_legacy_json_once_and_moves_network_metadata_into_database(tmp_path):
    hidden = tmp_path / "hidden.json"
    profiles = tmp_path / "profiles.json"
    enterprise = tmp_path / "enterprise.json"
    captures = tmp_path / "captures"
    captures.mkdir()
    hidden.write_text(json.dumps({
        "version": 1,
        "networks": [{
            "bssid": BSSID, "ssid": "Legacy", "reveal_method": "client",
            "first_revealed_at": 1, "last_revealed_at": 2,
        }],
    }))
    profiles.write_text(json.dumps({"version": 1, "profiles": []}))
    enterprise.write_text(json.dumps({"version": 1, "profiles": []}))
    network = captures / "legacy_network.json"
    network.write_text(json.dumps({"bssid": BSSID, "ssid": "Legacy"}))
    store = ApHistoryStore(tmp_path / "history.sqlite3")

    assert store.import_legacy(
        hidden, profiles, enterprise, captures,
    ) == 2
    assert store.import_legacy(
        hidden, profiles, enterprise, captures,
    ) == 0
    assert not network.exists()
    assert store.network_metadata_payload(BSSID)["ssid"] == "Legacy"


def test_clear_does_not_allow_legacy_files_to_repopulate_history(tmp_path):
    hidden = tmp_path / "hidden.json"
    hidden.write_text(json.dumps({
        "version": 1,
        "networks": [{"bssid": BSSID, "ssid": "Legacy"}],
    }))
    missing = tmp_path / "missing.json"
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    assert store.import_legacy(hidden, missing, missing, tmp_path / "captures") == 1

    store.clear()

    assert store.count() == 0
    assert store.import_legacy(hidden, missing, missing, tmp_path / "captures") == 0


def test_malformed_legacy_json_is_ignored(tmp_path):
    malformed = tmp_path / "broken.json"
    malformed.write_text("{not-json")
    store = ApHistoryStore(tmp_path / "history.sqlite3")

    assert store.import_legacy(
        malformed, malformed, malformed, tmp_path / "captures",
    ) == 0
    assert store.count() == 0


def test_shared_store_serializes_writes_from_rx_threads(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")

    def remember(index: int) -> bool:
        ap = AccessPoint(
            bssid=f"02:00:00:00:00:{index:02x}",
            ssid=f"AP {index}",
        )
        return store.remember(ap, force=True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(remember, range(20)))

    assert store.count() == 20
