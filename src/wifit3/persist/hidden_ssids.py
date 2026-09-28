from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

from wifit3.id import is_manufacturer_mac
from wifit3.persist.private_files import ensure_private_directory


HIDDEN_SSIDS_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "hidden_ssids.sqlite3"
)
LEGACY_HIDDEN_SSIDS_PATH = (
    Path(user_config_dir("wifit3", appauthor=False)) / "hidden_ssids.json"
)
HIDDEN_SSIDS_VERSION = 1


class HiddenSsidStoreError(RuntimeError):
    pass


@dataclass
class HiddenSsidRecord:
    bssid: str
    ssid: str
    first_revealed_at: float
    last_revealed_at: float
    reveal_method: str


@dataclass
class ClientProbeRecord:
    client_mac: str
    ssid: str
    channels: list[int]
    last_channel: int
    first_seen: float
    last_seen: float
    count: int


class HiddenSsidStore:
    def __init__(
        self,
        path: Path = HIDDEN_SSIDS_PATH,
        *,
        legacy_path: Path | None = None,
    ) -> None:
        self.path = path
        self.records: dict[str, HiddenSsidRecord] = {}
        self.client_probes: dict[tuple[str, str], ClientProbeRecord] = {}
        self._last_probe_save: dict[tuple[str, str], float] = {}
        self.errors: list[str] = []
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._open()
        if self._connection is not None and legacy_path is not None:
            self._migrate_legacy(legacy_path)
        self.load()
        self._drop_nonmanufacturer_probes()

    def _open(self) -> None:
        try:
            ensure_private_directory(self.path.parent)
            connection = sqlite3.connect(
                self.path, timeout=5.0, check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            self._connection = connection
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA secure_delete = ON")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > 1:
                raise HiddenSsidStoreError(
                    f"Hidden SSID database schema {version} is newer than supported 1",
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS hidden_networks (
                    bssid TEXT PRIMARY KEY COLLATE NOCASE,
                    ssid TEXT NOT NULL,
                    first_revealed_at REAL NOT NULL,
                    last_revealed_at REAL NOT NULL,
                    reveal_method TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_probes (
                    client_mac TEXT NOT NULL COLLATE NOCASE,
                    ssid TEXT NOT NULL,
                    channels_json TEXT NOT NULL,
                    last_channel INTEGER NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    count INTEGER NOT NULL,
                    PRIMARY KEY (client_mac, ssid)
                );
                """
            )
            if version == 0:
                connection.execute("PRAGMA user_version = 1")
            connection.commit()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error, HiddenSsidStoreError) as exc:
            self.errors.append(f"Could not open hidden SSID database: {exc}")
            self.close()

    def load(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            networks = connection.execute("SELECT * FROM hidden_networks").fetchall()
            probes = connection.execute("SELECT * FROM client_probes").fetchall()
        except sqlite3.Error as exc:
            self.errors.append(f"Could not load hidden SSIDs: {exc}")
            return
        self.records.clear()
        self.client_probes.clear()
        self._last_probe_save.clear()
        for row in networks:
            try:
                record = HiddenSsidRecord(
                    bssid=str(row["bssid"]),
                    ssid=str(row["ssid"]),
                    first_revealed_at=float(row["first_revealed_at"]),
                    last_revealed_at=float(row["last_revealed_at"]),
                    reveal_method=str(row["reveal_method"]),
                )
            except (TypeError, ValueError):
                continue
            if record.bssid and record.ssid:
                self.records[record.bssid.casefold()] = record
        for row in probes:
            try:
                record = ClientProbeRecord(
                    client_mac=str(row["client_mac"]).casefold(),
                    ssid=str(row["ssid"]),
                    channels=json.loads(row["channels_json"]),
                    last_channel=int(row["last_channel"]),
                    first_seen=float(row["first_seen"]),
                    last_seen=float(row["last_seen"]),
                    count=max(1, int(row["count"])),
                )
                record.client_mac = record.client_mac.casefold()
                record.channels = sorted({int(channel) for channel in record.channels})
                record.last_channel = int(record.last_channel)
                record.count = max(1, int(record.count))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if record.client_mac and record.ssid:
                key = (record.client_mac, record.ssid)
                self.client_probes[key] = record
                self._last_probe_save[key] = record.last_seen

    def lookup(self, bssid: str) -> str | None:
        record = self.records.get(bssid.casefold())
        return record.ssid if record is not None else None

    def probes_for_client(self, client_mac: str) -> list[ClientProbeRecord]:
        client_mac = client_mac.casefold()
        return [
            record
            for (mac, _ssid), record in self.client_probes.items()
            if mac == client_mac
        ]

    def remember(self, bssid: str, ssid: str, reveal_method: str) -> None:
        bssid = bssid.casefold().strip()
        ssid = ssid.strip()
        if not bssid or not ssid or ssid == "<hidden>":
            return
        now = time.time()
        record = self.records.get(bssid)
        if record is None:
            record = HiddenSsidRecord(
                bssid=bssid,
                ssid=ssid,
                first_revealed_at=now,
                last_revealed_at=now,
                reveal_method=reveal_method,
            )
            self.records[bssid] = record
        else:
            record.ssid = ssid
            record.last_revealed_at = now
            record.reveal_method = reveal_method
        self.save()

    def remember_probe(
        self,
        client_mac: str,
        ssid: str,
        channel: int,
        *,
        now: float | None = None,
    ) -> None:
        """Persist a directed probe without inventing a BSSID-to-SSID mapping."""
        client_mac = client_mac.casefold().strip()
        ssid = ssid.strip()
        if (
            not client_mac
            or not is_manufacturer_mac(client_mac)
            or not ssid
            or ssid == "<hidden>"
        ):
            return
        now = time.time() if now is None else now
        key = (client_mac, ssid)
        record = self.client_probes.get(key)
        is_new = record is None
        if record is None:
            record = ClientProbeRecord(
                client_mac=client_mac,
                ssid=ssid,
                channels=[int(channel)],
                last_channel=int(channel),
                first_seen=now,
                last_seen=now,
                count=1,
            )
            self.client_probes[key] = record
        else:
            if channel not in record.channels:
                record.channels.append(int(channel))
                record.channels.sort()
            record.last_channel = int(channel)
            record.last_seen = now
            record.count += 1
        if is_new or now - self._last_probe_save.get(key, 0) >= 5:
            self.save()
            self._last_probe_save[key] = now

    def _drop_nonmanufacturer_probes(self) -> None:
        """Remove legacy probe rows created by randomized or unknown STA MACs."""
        connection = self._connection
        stale = [
            key
            for key in self.client_probes
            if not is_manufacturer_mac(key[0])
        ]
        if connection is None or not stale:
            return
        try:
            with self._lock, connection:
                connection.executemany(
                    "DELETE FROM client_probes WHERE client_mac = ? AND ssid = ?",
                    stale,
                )
        except sqlite3.Error as exc:
            self.errors.append(f"Could not prune randomized client probes: {exc}")
            return
        for key in stale:
            self.client_probes.pop(key, None)
            self._last_probe_save.pop(key, None)

    def save(self) -> None:
        connection = self._connection
        if connection is None:
            raise HiddenSsidStoreError("Hidden SSID database is unavailable")
        try:
            with self._lock, connection:
                connection.execute("DELETE FROM hidden_networks")
                connection.execute("DELETE FROM client_probes")
                connection.executemany(
                    """
                    INSERT INTO hidden_networks VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            record.bssid, record.ssid, record.first_revealed_at,
                            record.last_revealed_at, record.reveal_method,
                        )
                        for record in self.records.values()
                    ],
                )
                connection.executemany(
                    """
                    INSERT INTO client_probes VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            record.client_mac, record.ssid,
                            json.dumps(record.channels), record.last_channel,
                            record.first_seen, record.last_seen, record.count,
                        )
                        for record in self.client_probes.values()
                    ],
                )
        except sqlite3.Error as exc:
            raise HiddenSsidStoreError(
                f"Could not save hidden SSIDs: {exc}",
            ) from exc

    def _migrate_legacy(self, legacy_path: Path | None) -> None:
        if legacy_path is None or not legacy_path.exists():
            return
        try:
            payload = json.loads(legacy_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not migrate hidden_ssids.json: {exc}")
            return
        if not isinstance(payload, dict) or payload.get("version") != HIDDEN_SSIDS_VERSION:
            self.errors.append("Unsupported hidden_ssids.json version")
            return
        connection = self._connection
        if connection is not None:
            existing = sum(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("hidden_networks", "client_probes")
            )
            if existing:
                self._remove_legacy(legacy_path)
                return
        for raw in payload.get("networks", []):
            try:
                record = HiddenSsidRecord(**raw)
            except (TypeError, ValueError):
                continue
            if record.bssid and record.ssid:
                self.records[record.bssid.casefold()] = record
        for raw in payload.get("client_probes", []):
            try:
                record = ClientProbeRecord(**raw)
                record.client_mac = record.client_mac.casefold()
                record.channels = sorted({int(channel) for channel in record.channels})
                record.last_channel = int(record.last_channel)
                record.count = max(1, int(record.count))
            except (TypeError, ValueError):
                continue
            if record.client_mac and record.ssid:
                key = (record.client_mac, record.ssid)
                self.client_probes[key] = record
                self._last_probe_save[key] = record.last_seen
        self.save()
        self._remove_legacy(legacy_path)

    def _remove_legacy(self, path: Path) -> None:
        try:
            path.unlink()
        except OSError as exc:
            self.errors.append(f"Could not remove migrated hidden_ssids.json: {exc}")

    def clear(self) -> None:
        """Forget persisted network and directed-probe history."""
        self.records.clear()
        self.client_probes.clear()
        self._last_probe_save.clear()
        self.save()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
