from __future__ import annotations

import json
import stat

from wifit3.persist.bluetooth_bonds import BluetoothBondStore, StoredBond


LINK_KEY = bytes(range(16))
IDENTIFIER = "00:12:6F:FF:2A:F2"


def _store(tmp_path):
    return BluetoothBondStore(tmp_path / "bonds.json")


def test_save_and_load_roundtrip(tmp_path):
    store = _store(tmp_path)
    saved = store.save_bond(IDENTIFIER, LINK_KEY, key_type=0, name="stonmore 2")
    assert isinstance(saved, StoredBond)

    reloaded = store.get(IDENTIFIER)
    assert reloaded is not None
    assert reloaded.link_key == LINK_KEY
    assert reloaded.key_type == 0
    assert reloaded.name == "stonmore 2"


def test_lookup_is_case_insensitive(tmp_path):
    store = _store(tmp_path)
    store.save_bond(IDENTIFIER, LINK_KEY)
    assert store.get(IDENTIFIER.lower()) is not None


def test_file_is_hardened_to_0600(tmp_path):
    store = _store(tmp_path)
    store.save_bond(IDENTIFIER, LINK_KEY)
    mode = stat.S_IMODE(store.path.stat().st_mode)
    assert mode == 0o600


def test_link_key_is_stored_as_hex_not_plaintext(tmp_path):
    store = _store(tmp_path)
    store.save_bond(IDENTIFIER, LINK_KEY)
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    entry = raw["bonds"][IDENTIFIER]
    assert entry["link_key"] == LINK_KEY.hex()


def test_missing_file_loads_empty(tmp_path):
    store = _store(tmp_path)
    assert store.load() == {}
    assert store.get(IDENTIFIER) is None


def test_corrupt_file_loads_empty(tmp_path):
    store = _store(tmp_path)
    store.path.write_text("{ not valid json", encoding="utf-8")
    assert store.load() == {}


def test_invalid_key_length_is_rejected(tmp_path):
    store = _store(tmp_path)
    assert store.save_bond(IDENTIFIER, b"\x00" * 8) is None
    assert store.get(IDENTIFIER) is None


def test_entry_with_bad_key_length_is_ignored_on_load(tmp_path):
    store = _store(tmp_path)
    store.path.write_text(
        json.dumps({"version": 1, "bonds": {IDENTIFIER: {"link_key": "00" * 8}}}),
        encoding="utf-8",
    )
    assert store.load() == {}


def test_forget_removes_bond(tmp_path):
    store = _store(tmp_path)
    store.save_bond(IDENTIFIER, LINK_KEY)
    assert store.forget(IDENTIFIER) is True
    assert store.get(IDENTIFIER) is None
    assert store.forget(IDENTIFIER) is False


def test_save_preserves_created_at_on_refresh(tmp_path):
    store = _store(tmp_path)
    first = store.save_bond(IDENTIFIER, LINK_KEY)
    second = store.save_bond(IDENTIFIER, bytes(reversed(LINK_KEY)))
    assert second.created_at == first.created_at
    assert second.updated_at >= first.updated_at
    assert store.get(IDENTIFIER).link_key == bytes(reversed(LINK_KEY))
