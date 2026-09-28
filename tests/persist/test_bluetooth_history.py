import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

from wifit3.models import BluetoothDevice
from wifit3.persist.bluetooth_history import (
    BluetoothHistoryStore,
    SCHEMA_VERSION,
)


IDENTIFIER = "AA:BB:CC:DD:EE:FF"


def _device(
    identifier: str = IDENTIFIER,
    *,
    name: str = "Headphones",
) -> BluetoothDevice:
    now = time.time()
    return BluetoothDevice(
        identifier=identifier,
        name=name,
        rssi=-50,
        service_uuids=("180f",),
        service_data_uuids=("180a",),
        manufacturer_ids=(76,),
        manufacturer_data_bytes=4,
        service_data_bytes=2,
        tx_power=-8,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        radio_types=("BLE", "BT"),
        class_of_device=0x240404,
    )


def test_creates_private_versioned_database(tmp_path):
    path = tmp_path / "private" / "bluetooth.sqlite3"
    store = BluetoothHistoryStore(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o077 == 0
    store.close()


def test_migrates_v4_database_to_structured_analysis_and_protocol(tmp_path):
    path = tmp_path / "bluetooth.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE devices (
                identifier TEXT PRIMARY KEY COLLATE NOCASE,
                name TEXT,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                service_uuids_json TEXT NOT NULL DEFAULT '[]',
                service_data_uuids_json TEXT NOT NULL DEFAULT '[]',
                manufacturer_ids_json TEXT NOT NULL DEFAULT '[]',
                tx_power INTEGER,
                radio_types_json TEXT NOT NULL DEFAULT '[]',
                class_of_device INTEGER,
                address_type TEXT NOT NULL DEFAULT 'unknown',
                profile_fingerprint TEXT NOT NULL DEFAULT '',
                payload_fingerprint TEXT NOT NULL DEFAULT '',
                appearance INTEGER
            );
            PRAGMA user_version = 4;
            """
        )

    store = BluetoothHistoryStore(path)

    with sqlite3.connect(path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(devices)")
        }
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert "analysis_json" in columns
    assert "protocol_json" in columns
    assert "modalias" in columns
    assert "hardware_vendor" in columns
    assert "hardware_product" in columns
    assert "hardware_source" in columns
    store.close()


def test_remember_and_enrich_only_a_live_device(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    saved = _device()
    saved.appearance = 0x0943
    saved.modalias = "bluetooth:v054Cp0CE6d0100"
    saved.hardware_vendor = "Sony Corp."
    saved.hardware_product = "WH-1000XM5 Headphones"
    saved.hardware_source = "BlueZ Device ID / systemd hwdb"
    assert store.remember(saved, force=True)

    observed = _device(name="<Unknown>")
    observed.service_uuids = ()
    observed.service_data_uuids = ()
    observed.manufacturer_ids = ()
    observed.tx_power = None
    observed.radio_types = ("BLE",)
    observed.class_of_device = None

    assert store.enrich(observed)
    assert observed.name == "Headphones"
    assert observed.service_uuids == ("180f",)
    assert observed.service_data_uuids == ("180a",)
    assert observed.manufacturer_ids == (76,)
    assert observed.tx_power == -8
    assert observed.radio_types == ("BLE", "BT")
    assert observed.class_of_device == 0x240404
    assert observed.appearance == 0x0943
    assert observed.modalias == "bluetooth:v054Cp0CE6d0100"
    assert observed.hardware_vendor == "Sony Corp."
    assert observed.hardware_product == "WH-1000XM5 Headphones"
    assert observed.hardware_source == "BlueZ Device ID / systemd hwdb"
    assert store.count() == 1


def test_history_rejects_rotating_synthetic_and_empty_observations(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")

    private = _device(identifier="40:11:22:33:44:55")
    private.address_type = "resolvable-private"
    assert not store.remember(private, force=True)

    opaque = _device(identifier="11111111-1111-1111-1111-111111111111")
    opaque.address_type = "platform-opaque"
    assert not store.remember(opaque, force=True)

    empty = _device(identifier="00:11:22:33:44:55", name="<Unknown>")
    empty.service_uuids = ()
    empty.service_data_uuids = ()
    empty.manufacturer_ids = ()
    empty.class_of_device = None
    assert not store.remember(empty, force=True)

    stable = _device(identifier="00:11:22:33:44:66")
    stable.address_type = "public"
    assert store.remember(stable, force=True)
    assert store.count() == 1


def test_live_name_and_radio_values_win_while_sets_are_merged(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    store.remember(_device(), force=True)
    observed = _device(name="Current name")
    observed.service_uuids = ("184e",)
    observed.tx_power = -2
    observed.class_of_device = 1

    store.enrich(observed)

    assert observed.name == "Current name"
    assert observed.service_uuids == ("180f", "184e")
    assert observed.tx_power == -2
    assert observed.class_of_device == 1


def test_live_device_is_classified_against_prior_profile(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    stored = _device()
    stored.address_type = "public"
    store.remember(stored, force=True)

    returning = _device()
    returning.address_type = "public"
    assert not store.enrich(returning)
    assert returning.baseline_status == "returning"
    assert not returning.profile_changed

    changed = _device(name="Unexpected name")
    changed.address_type = "public"
    assert not store.enrich(changed)
    assert changed.baseline_status == "changed"
    assert changed.profile_changed

    new = _device(identifier="00:11:22:33:44:55")
    assert not store.enrich(new)
    assert new.baseline_status == "new"


def test_remember_persists_classification_signal_and_activity_analysis(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    device = _device()
    device.appearance = 0x0943
    device.address_type = "public"
    device.payload_fingerprint = "payload"
    device.profile_fingerprint = "profile"
    device.baseline_status = "changed"
    device.profile_changed = True
    device.rssi_average = -52.5
    device.rssi_min = -60
    device.rssi_max = -45
    device.rssi_samples = 8
    device.rssi_trend = "approaching"
    device.advertisement_count = 12
    device.advertisement_interval = 0.25

    assert store.remember(device, force=True)

    analysis = store.analysis(device.identifier)
    assert analysis["classification"] == {
        "category": "Audio",
        "detail": "Headphones",
        "source": "Appearance",
        "confidence": "high",
        "ambiguous": False,
    }
    assert analysis["signal"]["average_rssi"] == -52.5
    assert analysis["signal"]["trend"] == "approaching"
    assert analysis["activity"]["advertisement_count"] == 12
    assert analysis["activity"]["latest_interval"] == 0.25
    assert analysis["baseline"]["status"] == "changed"
    assert analysis["baseline"]["profile_changed"] is True
    assert analysis["discovery_source"] == "system"


def test_protocol_classification_evidence_round_trips(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    device = _device()
    device.protocol_category = "Audio"
    device.protocol_type = "Apple Proximity Pairing audio"
    device.protocol_source = "Manufacturer protocol"
    device.protocol_confidence = "high"
    assert store.remember(device, force=True)

    observed = _device()
    assert store.enrich(observed)

    assert observed.protocol_category == "Audio"
    assert observed.protocol_type == "Apple Proximity Pairing audio"
    assert observed.protocol_source == "Manufacturer protocol"
    assert observed.protocol_confidence == "high"


def test_offline_devices_include_all_json_fields_and_capture_summaries(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    device = _device()
    device.address_type = "public"
    device.protocol_type = "Example protocol"
    store.remember(device, force=True)
    capture_id = store.start_event_capture(
        device.identifier, "Headphones", max_bytes=1024,
    )
    store.append_event(capture_id, "advertisement", {"sample": True})
    store.finish_event_capture(capture_id)

    records = store.offline_devices()

    assert records[0]["service_uuids"] == ["180f"]
    assert records[0]["analysis"]["activity"]["advertisement_count"] == 1
    assert records[0]["protocol"]["type"] == "Example protocol"
    assert records[0]["event_captures"][0]["event_count"] == 1


def test_clear_and_cross_thread_writes(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")

    def remember(index: int) -> bool:
        return store.remember(
            _device(identifier=f"02:00:00:00:00:{index:02x}"),
            force=True,
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(remember, range(20)))
    assert store.count() == 20

    store.clear()

    assert store.count() == 0


def test_bluetooth_events_are_bounded_and_cleared_with_history(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    capture_id = store.start_event_capture(IDENTIFIER, "Watch", max_bytes=20)

    assert store.append_event(capture_id, "advertisement", {"small": 1})
    assert not store.append_event(capture_id, "gatt", {"too_large": "x" * 100})
    store.finish_event_capture(capture_id)

    assert store.event_capture_stats(capture_id) == (1, 1)
    assert store.events_for_capture(capture_id)[0]["event"] == "advertisement"

    store.clear()

    assert store.events_for_capture(capture_id) == []


def test_migrates_and_removes_bluetooth_event_jsonl(tmp_path):
    directory = tmp_path / "bluetooth_targets"
    directory.mkdir()
    legacy = directory / "target_events_watch_20260101.jsonl"
    legacy.write_text(json.dumps({
        "timestamp": 10,
        "event": "advertisement",
        "data": {"identifier": IDENTIFIER, "name": "Watch"},
    }) + "\n")
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")

    assert store.migrate_event_files(directory) == 1
    assert not legacy.exists()
    connection = store._connection  # noqa: SLF001 - verify migrated capture
    capture_id = connection.execute(
        "SELECT capture_id FROM event_captures"
    ).fetchone()[0]
    assert store.events_for_capture(capture_id)[0]["data"]["name"] == "Watch"
