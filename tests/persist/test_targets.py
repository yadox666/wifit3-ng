import json
import sqlite3

import pytest

from wifit3.persist.targets import TargetStore, TargetStoreError


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
