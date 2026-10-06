import json
import sqlite3

import pytest

from wifit3.persist.targets import TargetStore, TargetStoreError


def test_v2_rows_migrate_to_single_member_groups(tmp_path):
    path = tmp_path / "targets.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE targets (
                id TEXT PRIMARY KEY,
                alias TEXT NOT NULL,
                medium TEXT NOT NULL,
                kind TEXT NOT NULL,
                identifier TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_locked_at REAL,
                priority INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'target',
                match_mode TEXT NOT NULL DEFAULT 'id'
            );
            INSERT INTO targets VALUES (
                'legacy-id', 'Phone', 'wifi', 'client',
                '02:11:22:33:44:55', '{}', 1, 2, NULL, 0, 1,
                'target', 'id'
            );
            PRAGMA user_version = 2;
            """
        )

    store = TargetStore(path)
    target = store.get("legacy-id")

    assert target is not None
    assert len(target.members) == 1
    assert target.members[0].identifier == "02:11:22:33:44:55"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_target_store_round_trips_and_updates_only_missing_fields(tmp_path):
    path = tmp_path / "targets.sqlite3"
    store = TargetStore(path)
    target = store.upsert(
        alias="Office router",
        medium="wifi",
        kind="ap",
        identifier="AA:BB:CC:DD:EE:FF",
        details={"ssid": None, "channel": 6, "identity": {"model": None}},
    )

    store.update_missing(target, {
        "ssid": "Office",
        "channel": 11,
        "identity": {"model": "Router X"},
    })

    loaded = TargetStore(path)
    restored = loaded.find("wifi", "ap", "aa:bb:cc:dd:ee:ff")
    assert restored is not None
    assert restored.alias == "Office router"
    assert restored.details["ssid"] == "Office"
    assert restored.details["channel"] == 6
    assert restored.details["identity"]["model"] == "Router X"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 1


def test_target_store_merges_known_client_macs(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    target = store.upsert(
        alias="Phone",
        medium="wifi",
        kind="client",
        identifier="02:11:22:33:44:55",
        details={"known_macs": ["02:11:22:33:44:55"]},
    )

    store.update_missing(target, {
        "known_macs": [
            "02:11:22:33:44:55",
            "02:11:22:33:44:66",
        ],
    })

    assert target.details["known_macs"] == [
        "02:11:22:33:44:55",
        "02:11:22:33:44:66",
    ]


def test_same_alias_groups_wifi_and_bluetooth_members(tmp_path):
    path = tmp_path / "targets.sqlite3"
    store = TargetStore(path)
    phone = store.upsert(
        alias="yadox",
        medium="wifi",
        kind="client",
        identifier="02:11:22:33:44:55",
        details={"known_macs": ["02:11:22:33:44:55"]},
    )
    access_point = store.upsert(
        alias="yadox",
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        details={"ssid": "Home"},
    )
    bluetooth = store.upsert(
        alias="yadox",
        medium="bluetooth",
        kind="device",
        identifier="ble-device-id",
        details={"name": "Phone BLE"},
    )

    assert phone.id == access_point.id == bluetooth.id
    assert len(phone.members) == 3
    assert store.find("wifi", "ap", "aa:bb:cc:dd:ee:ff") == phone
    assert store.find("bluetooth", "device", "ble-device-id") == phone

    restored = TargetStore(path).get(phone.id)
    assert restored is not None
    assert len(restored.members) == 3
    assert {
        (member.medium, member.kind, member.identifier)
        for member in restored.members
    } == {
        ("wifi", "client", "02:11:22:33:44:55"),
        ("wifi", "ap", "aa:bb:cc:dd:ee:ff"),
        ("bluetooth", "device", "ble-device-id"),
    }


def test_renaming_member_to_existing_alias_merges_target_groups(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    person = store.upsert(
        alias="yadox",
        medium="wifi",
        kind="client",
        identifier="02:11:22:33:44:55",
        details={},
    )
    router = store.upsert(
        alias="Home router",
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        details={"ssid": "Home"},
    )

    merged = store.upsert(
        alias="yadox",
        medium="wifi",
        kind="ap",
        identifier=router.identifier,
        details={"country_code": "ES"},
    )

    assert merged.id == person.id
    assert store.get(router.id) is None
    assert len(merged.members) == 2
    assert store.find("wifi", "ap", router.identifier) == merged


def test_target_store_requires_alias_and_supports_mixed_target_types(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    with pytest.raises(TargetStoreError, match="Alias is required"):
        store.upsert(
            alias=" ",
            medium="wifi",
            kind="client",
            identifier="11:22:33:44:55:66",
            details={},
        )

    wifi = store.upsert(
        alias="Phone",
        medium="wifi",
        kind="client",
        identifier="11:22:33:44:55:66",
        details={},
    )
    bluetooth = store.upsert(
        alias="Watch",
        medium="bluetooth",
        kind="device",
        identifier="ble-id",
        details={},
    )
    assert [target.id for target in store.ordered()] == [wifi.id, bluetooth.id]
    bluetooth.enabled = False
    store.save()
    assert TargetStore(store.path).get(bluetooth.id).enabled is False


def test_target_store_whitelist_and_name_match(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    entry = store.upsert(
        alias="Do not touch",
        medium="wifi",
        kind="client",
        identifier="11:22:33:44:55:66",
        details={},
        role="whitelist",
        match_mode="id",
    )
    assert entry.role == "whitelist"
    assert store.find("wifi", "client", "11:22:33:44:55:66") == entry


def test_target_store_delete_reorders_priorities(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    first = store.upsert(
        alias="First", medium="wifi", kind="ap", identifier="a", details={},
    )
    second = store.upsert(
        alias="Second", medium="bluetooth", kind="device", identifier="b", details={},
    )

    assert store.delete(first.id)
    assert store.ordered() == [second]
    assert second.priority == 0


def test_target_store_reports_invalid_legacy_document_without_crashing(tmp_path):
    legacy = tmp_path / "targets.json"
    legacy.write_text("[]", encoding="utf-8")
    store = TargetStore(tmp_path / "targets.sqlite3", legacy_path=legacy)
    assert store.targets == []
    assert store.errors == ["Unsupported targets.json version"]


def test_target_store_migrates_json_and_clears_one_medium(tmp_path):
    legacy = tmp_path / "targets.json"
    legacy.write_text(json.dumps({
        "version": 1,
        "targets": [
            {
                "id": "wifi-id", "alias": "Router", "medium": "wifi",
                "kind": "ap", "identifier": "aa:bb:cc:dd:ee:ff",
                "details": {}, "created_at": 1, "updated_at": 1,
                "last_locked_at": None, "priority": 0, "enabled": True,
            },
            {
                "id": "bt-id", "alias": "Watch", "medium": "bluetooth",
                "kind": "device", "identifier": "ble-id", "details": {},
                "created_at": 2, "updated_at": 2, "last_locked_at": None,
                "priority": 1, "enabled": True,
            },
        ],
    }))
    path = tmp_path / "targets.sqlite3"
    store = TargetStore(path, legacy_path=legacy)

    assert not legacy.exists()
    assert [target.id for target in store.ordered()] == ["wifi-id", "bt-id"]

    store.clear_medium("wifi")

    assert [target.id for target in TargetStore(path).ordered()] == ["bt-id"]
