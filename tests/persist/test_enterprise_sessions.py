import json
import sqlite3

from wifit3.persist.enterprise_sessions import EnterpriseSessionStore


BSSID = "aa:bb:cc:dd:ee:ff"


def test_migrates_enterprise_json_and_removes_source_file(tmp_path):
    salt = "01" * 16
    legacy = tmp_path / "enterprise_sessions.json"
    legacy.write_text(json.dumps({
        "version": 1,
        "client_salt": salt,
        "profiles": [{
            "bssid": BSSID,
            "ssid": "Corp",
            "channel": 36,
            "last_seen": 10,
            "profile": {},
        }],
    }))
    path = tmp_path / "enterprise_sessions.sqlite3"

    store = EnterpriseSessionStore(path, legacy_path=legacy)

    assert store.profile_for(BSSID) is not None
    assert not legacy.exists()
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM enterprise_profiles"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT value FROM enterprise_metadata WHERE key = 'client_salt'"
        ).fetchone()[0] == salt


def test_clear_rotates_pseudonym_salt_and_removes_profiles(tmp_path):
    path = tmp_path / "enterprise_sessions.sqlite3"
    store = EnterpriseSessionStore(path)
    before = store.client_id(BSSID, "02:00:00:00:00:01")

    store.clear()

    after = store.client_id(BSSID, "02:00:00:00:00:01")
    assert before != after
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM enterprise_profiles"
        ).fetchone()[0] == 0
