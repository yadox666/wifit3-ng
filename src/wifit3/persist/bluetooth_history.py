from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

from wifit3.models import BluetoothDevice
from wifit3.models.bluetooth_device import has_coherent_persistent_identity
from wifit3.persist.private_files import ensure_private_directory
from wifit3.persist.scan_sessions import ScanSession, merge_session_metadata


BLUETOOTH_HISTORY_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "bluetooth_history.sqlite3"
)
SCHEMA_VERSION = 11
_MAX_DEVICES = 50_000
_WRITE_INTERVAL_SECONDS = 5.0


class BluetoothHistoryStoreError(RuntimeError):
    pass


def _locked(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class BluetoothHistoryStore:
    """Private Bluetooth/BLE observations, loaded only for devices seen live."""

    def __init__(self, path: Path = BLUETOOTH_HISTORY_PATH) -> None:
        self.path = path
        self.errors: list[str] = []
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._last_write: dict[str, float] = {}
        self._active_session_id: str | None = None
        self._open()

    def _open(self) -> None:
        try:
            ensure_private_directory(self.path.parent)
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA secure_delete = ON")
            self._connection = connection
            self._migrate()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error, BluetoothHistoryStoreError) as exc:
            self.errors.append(f"Could not open Bluetooth history: {exc}")
            self.close()

    def _migrate(self) -> None:
        connection = self._require_connection()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise BluetoothHistoryStoreError(
                f"Bluetooth history schema {version} is newer than supported "
                f"{SCHEMA_VERSION}",
            )
        if version == 0:
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
                    class_of_device INTEGER
                );
                CREATE INDEX devices_last_seen_idx
                    ON devices(last_seen DESC);
                PRAGMA user_version = 1;
                """
            )
            connection.commit()
            version = 1
        if version == 1:
            connection.executescript(
                """
                CREATE TABLE event_captures (
                    capture_id TEXT PRIMARY KEY,
                    identifier TEXT NOT NULL COLLATE NOCASE,
                    alias TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL,
                    max_bytes INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL DEFAULT 0,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    dropped INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE bluetooth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capture_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    FOREIGN KEY (capture_id) REFERENCES event_captures(capture_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX bluetooth_events_capture_idx
                    ON bluetooth_events(capture_id, id);
                PRAGMA user_version = 2;
                """
            )
            connection.commit()
            version = 2
        if version == 2:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN address_type TEXT NOT NULL DEFAULT 'unknown';
                ALTER TABLE devices
                    ADD COLUMN profile_fingerprint TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN payload_fingerprint TEXT NOT NULL DEFAULT '';
                PRAGMA user_version = 3;
                """
            )
            connection.commit()
            version = 3
        if version == 3:
            connection.executescript(
                """
                ALTER TABLE devices ADD COLUMN appearance INTEGER;
                PRAGMA user_version = 4;
                """
            )
            connection.commit()
            version = 4
        if version == 4:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN analysis_json TEXT NOT NULL DEFAULT '{}';
                PRAGMA user_version = 5;
                """
            )
            connection.commit()
            version = 5
        if version == 5:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN protocol_json TEXT NOT NULL DEFAULT '{}';
                PRAGMA user_version = 6;
                """
            )
            connection.commit()
            version = 6
        if version == 6:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN modalias TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN hardware_vendor TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN hardware_product TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN hardware_source TEXT NOT NULL DEFAULT '';
                PRAGMA user_version = 7;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 7:
            connection.executescript(
                """
                CREATE TABLE scan_sessions (
                    session_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL,
                    mode TEXT NOT NULL
                );
                CREATE INDEX scan_sessions_started_idx
                    ON scan_sessions(started_at DESC);
                CREATE TABLE device_session_sightings (
                    session_id TEXT NOT NULL,
                    identifier TEXT NOT NULL COLLATE NOCASE,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    sighting_count INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (session_id, identifier),
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY (identifier) REFERENCES devices(identifier)
                        ON DELETE CASCADE
                );
                CREATE INDEX device_session_sightings_session_idx
                    ON device_session_sightings(session_id, last_seen DESC);
                PRAGMA user_version = 8;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 8:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN model_number TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN serial_number TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN firmware_revision TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN hardware_revision TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN software_revision TEXT NOT NULL DEFAULT '';
                PRAGMA user_version = 9;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 9:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN manufacturer_name TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN gatt_device_name TEXT NOT NULL DEFAULT '';
                ALTER TABLE devices
                    ADD COLUMN pnp_id TEXT NOT NULL DEFAULT '';
                PRAGMA user_version = 10;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 10:
            connection.executescript(
                """
                ALTER TABLE scan_sessions
                    ADD COLUMN description TEXT NOT NULL DEFAULT '';
                ALTER TABLE scan_sessions
                    ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
                PRAGMA user_version = 11;
                """
            )
            connection.commit()
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS legacy_event_imports (
                path TEXT PRIMARY KEY,
                imported_at REAL NOT NULL
            )
            """
        )
        connection.commit()

    @_locked
    def start_scan_session(self, session: ScanSession) -> None:
        connection = self._connection
        if connection is None or "bluetooth" not in session.media:
            return
        with connection:
            connection.execute(
                """
                UPDATE scan_sessions
                SET ended_at = ?
                WHERE ended_at IS NULL AND session_id != ?
                """,
                (session.started_at, session.id),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO scan_sessions (
                    session_id, name, started_at, ended_at, mode,
                    description, metadata_json
                ) VALUES (?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    session.id,
                    session.name,
                    session.started_at,
                    session.mode,
                    session.description,
                    session.metadata_json,
                ),
            )
        self._active_session_id = session.id
        self._last_write.clear()

    @_locked
    def end_scan_session(
        self,
        session_id: str,
        *,
        ended_at: float | None = None,
        metadata_patch: dict[str, Any] | None = None,
    ) -> None:
        connection = self._connection
        if connection is None:
            return
        ended = time.time() if ended_at is None else ended_at
        with connection:
            if metadata_patch:
                row = connection.execute(
                    "SELECT metadata_json FROM scan_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                prior = row[0] if row is not None else "{}"
                merged = merge_session_metadata(prior, metadata_patch)
                connection.execute(
                    """
                    UPDATE scan_sessions
                    SET ended_at = ?, metadata_json = ?
                    WHERE session_id = ?
                    """,
                    (ended, merged, session_id),
                )
            else:
                connection.execute(
                    "UPDATE scan_sessions SET ended_at = ? WHERE session_id = ?",
                    (ended, session_id),
                )
        if self._active_session_id == session_id:
            self._active_session_id = None

    @_locked
    def scan_sessions(self) -> list[dict]:
        connection = self._connection
        if connection is None:
            return []
        return [
            dict(row)
            for row in connection.execute(
                """
                SELECT session_id, name, started_at, ended_at, mode,
                       description, metadata_json
                FROM scan_sessions
                ORDER BY started_at DESC
                """
            )
        ]

    @_locked
    def enrich(self, device: BluetoothDevice, *, classify: bool = True) -> bool:
        connection = self._connection
        if connection is None:
            return False
        row = connection.execute(
            "SELECT * FROM devices WHERE identifier = ?",
            (device.identifier.casefold(),),
        ).fetchone()
        if row is None:
            if classify:
                device.baseline_status = "new"
            return False
        if classify:
            device.profile_changed = _profile_changed(device, row)
            device.baseline_status = "changed" if device.profile_changed else "returning"
        changed = False
        if device.name == "<Unknown>" and row["name"]:
            device.name = str(row["name"])
            changed = True
        changed |= _merge_tuple(device, "service_uuids", row["service_uuids_json"])
        changed |= _merge_tuple(
            device, "service_data_uuids", row["service_data_uuids_json"],
        )
        changed |= _merge_tuple(
            device, "manufacturer_ids", row["manufacturer_ids_json"], integers=True,
        )
        changed |= _merge_tuple(device, "radio_types", row["radio_types_json"])
        if device.tx_power is None and row["tx_power"] is not None:
            device.tx_power = int(row["tx_power"])
            changed = True
        if device.class_of_device is None and row["class_of_device"] is not None:
            device.class_of_device = int(row["class_of_device"])
            changed = True
        if device.appearance is None and row["appearance"] is not None:
            device.appearance = int(row["appearance"])
            changed = True
        if device.address_type == "unknown" and row["address_type"] != "unknown":
            device.address_type = str(row["address_type"])
            changed = True
        for field in (
            "modalias", "hardware_vendor", "hardware_product", "hardware_source",
            "model_number", "serial_number", "firmware_revision",
            "hardware_revision", "software_revision",
            "manufacturer_name", "gatt_device_name", "pnp_id",
        ):
            if not getattr(device, field) and row[field]:
                setattr(device, field, str(row[field]))
                changed = True
        if not device.protocol_type:
            try:
                protocol = json.loads(row["protocol_json"])
            except (TypeError, json.JSONDecodeError):
                protocol = {}
            if isinstance(protocol, dict) and protocol.get("type"):
                device.protocol_category = str(protocol.get("category", ""))
                device.protocol_type = str(protocol["type"])
                device.protocol_source = str(protocol.get("source", ""))
                device.protocol_confidence = str(protocol.get("confidence", ""))
                if not device.decode_state and protocol.get("decode_state"):
                    device.decode_state = str(protocol["decode_state"])
                changed = True
        return changed

    @_locked
    def remember(self, device: BluetoothDevice, *, force: bool = False) -> bool:
        from wifit3.bluetooth.classification import device_classification

        connection = self._connection
        if connection is None or not has_coherent_persistent_identity(device):
            return False
        identifier = device.identifier.casefold()
        classification = device_classification(device)
        analysis = {
            "classification": {
                "category": classification.category,
                "detail": classification.detail,
                "source": classification.source,
                "confidence": classification.confidence,
                "ambiguous": classification.ambiguous,
            },
            "signal": {
                "last_rssi": device.rssi,
                "average_rssi": device.rssi_average,
                "minimum_rssi": device.rssi_min,
                "maximum_rssi": device.rssi_max,
                "samples": device.rssi_samples,
                "trend": device.rssi_trend,
            },
            "activity": {
                "advertisement_count": device.advertisement_count,
                "latest_interval": device.advertisement_interval,
                "manufacturer_data_bytes": device.manufacturer_data_bytes,
                "service_data_bytes": device.service_data_bytes,
                "similar_identifier_count": device.similar_identifier_count,
            },
            "baseline": {
                "status": device.baseline_status,
                "profile_changed": device.profile_changed,
            },
            "hardware_identity": {
                "modalias": device.modalias,
                "vendor": device.hardware_vendor,
                "product": device.hardware_product,
                "source": device.hardware_source,
            },
            "discovery_source": device.discovery_source,
        }
        snapshot = {
            "name": device.name if device.name != "<Unknown>" else None,
            "service_uuids": sorted(set(device.service_uuids)),
            "service_data_uuids": sorted(set(device.service_data_uuids)),
            "manufacturer_ids": sorted(set(device.manufacturer_ids)),
            "tx_power": device.tx_power,
            "radio_types": sorted(set(device.radio_types)),
            "class_of_device": device.class_of_device,
            "appearance": device.appearance,
            "address_type": device.address_type,
            "profile_fingerprint": device.profile_fingerprint,
            "payload_fingerprint": device.payload_fingerprint,
            "modalias": device.modalias,
            "hardware_vendor": device.hardware_vendor,
            "hardware_product": device.hardware_product,
            "hardware_source": device.hardware_source,
            "model_number": device.model_number,
            "serial_number": device.serial_number,
            "firmware_revision": device.firmware_revision,
            "hardware_revision": device.hardware_revision,
            "software_revision": device.software_revision,
            "manufacturer_name": device.manufacturer_name,
            "gatt_device_name": device.gatt_device_name,
            "pnp_id": device.pnp_id,
            "analysis": analysis,
            "protocol": {
                "category": device.protocol_category,
                "type": device.protocol_type,
                "source": device.protocol_source,
                "confidence": device.protocol_confidence,
                "decode_state": device.decode_state,
            },
        }
        now = time.time()
        if (
            not force
            and now - self._last_write.get(identifier, 0.0) < _WRITE_INTERVAL_SECONDS
        ):
            return False
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO devices (
                        identifier, name, first_seen, last_seen,
                        service_uuids_json, service_data_uuids_json,
                        manufacturer_ids_json, tx_power, radio_types_json,
                        class_of_device, address_type, profile_fingerprint,
                        payload_fingerprint, appearance, analysis_json,
                        protocol_json, modalias, hardware_vendor,
                        hardware_product, hardware_source,
                        model_number, serial_number, firmware_revision,
                        hardware_revision, software_revision,
                        manufacturer_name, gatt_device_name, pnp_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(identifier) DO UPDATE SET
                        name = COALESCE(excluded.name, devices.name),
                        first_seen = MIN(devices.first_seen, excluded.first_seen),
                        last_seen = MAX(devices.last_seen, excluded.last_seen),
                        service_uuids_json = excluded.service_uuids_json,
                        service_data_uuids_json = excluded.service_data_uuids_json,
                        manufacturer_ids_json = excluded.manufacturer_ids_json,
                        tx_power = COALESCE(excluded.tx_power, devices.tx_power),
                        radio_types_json = excluded.radio_types_json,
                        class_of_device = COALESCE(
                            excluded.class_of_device, devices.class_of_device
                        ),
                        address_type = CASE
                            WHEN excluded.address_type = 'unknown'
                            THEN devices.address_type
                            ELSE excluded.address_type
                        END,
                        profile_fingerprint = excluded.profile_fingerprint,
                        payload_fingerprint = CASE
                            WHEN excluded.payload_fingerprint = ''
                            THEN devices.payload_fingerprint
                            ELSE excluded.payload_fingerprint
                        END,
                        appearance = COALESCE(excluded.appearance, devices.appearance),
                        analysis_json = excluded.analysis_json,
                        protocol_json = CASE
                            WHEN excluded.protocol_json = '{}'
                            THEN devices.protocol_json
                            ELSE excluded.protocol_json
                        END,
                        modalias = CASE
                            WHEN excluded.modalias = '' THEN devices.modalias
                            ELSE excluded.modalias
                        END,
                        hardware_vendor = CASE
                            WHEN excluded.hardware_vendor = ''
                            THEN devices.hardware_vendor
                            ELSE excluded.hardware_vendor
                        END,
                        hardware_product = CASE
                            WHEN excluded.hardware_product = ''
                            THEN devices.hardware_product
                            ELSE excluded.hardware_product
                        END,
                        hardware_source = CASE
                            WHEN excluded.hardware_source = ''
                            THEN devices.hardware_source
                            ELSE excluded.hardware_source
                        END,
                        model_number = CASE
                            WHEN excluded.model_number = ''
                            THEN devices.model_number
                            ELSE excluded.model_number
                        END,
                        serial_number = CASE
                            WHEN excluded.serial_number = ''
                            THEN devices.serial_number
                            ELSE excluded.serial_number
                        END,
                        firmware_revision = CASE
                            WHEN excluded.firmware_revision = ''
                            THEN devices.firmware_revision
                            ELSE excluded.firmware_revision
                        END,
                        hardware_revision = CASE
                            WHEN excluded.hardware_revision = ''
                            THEN devices.hardware_revision
                            ELSE excluded.hardware_revision
                        END,
                        software_revision = CASE
                            WHEN excluded.software_revision = ''
                            THEN devices.software_revision
                            ELSE excluded.software_revision
                        END,
                        manufacturer_name = CASE
                            WHEN excluded.manufacturer_name = ''
                            THEN devices.manufacturer_name
                            ELSE excluded.manufacturer_name
                        END,
                        gatt_device_name = CASE
                            WHEN excluded.gatt_device_name = ''
                            THEN devices.gatt_device_name
                            ELSE excluded.gatt_device_name
                        END,
                        pnp_id = CASE
                            WHEN excluded.pnp_id = ''
                            THEN devices.pnp_id
                            ELSE excluded.pnp_id
                        END
                    """,
                    (
                        identifier,
                        snapshot["name"],
                        float(device.first_seen),
                        float(device.last_seen),
                        json.dumps(snapshot["service_uuids"]),
                        json.dumps(snapshot["service_data_uuids"]),
                        json.dumps(snapshot["manufacturer_ids"]),
                        snapshot["tx_power"],
                        json.dumps(snapshot["radio_types"]),
                        snapshot["class_of_device"],
                        snapshot["address_type"],
                        snapshot["profile_fingerprint"],
                        snapshot["payload_fingerprint"],
                        snapshot["appearance"],
                        json.dumps(
                            snapshot["analysis"], sort_keys=True, separators=(",", ":"),
                        ),
                        json.dumps(
                            snapshot["protocol"], sort_keys=True, separators=(",", ":"),
                        ) if device.protocol_type else "{}",
                        snapshot["modalias"],
                        snapshot["hardware_vendor"],
                        snapshot["hardware_product"],
                        snapshot["hardware_source"],
                        snapshot["model_number"],
                        snapshot["serial_number"],
                        snapshot["firmware_revision"],
                        snapshot["hardware_revision"],
                        snapshot["software_revision"],
                        snapshot["manufacturer_name"],
                        snapshot["gatt_device_name"],
                        snapshot["pnp_id"],
                    ),
                )
                if self._active_session_id is not None:
                    observed_at = float(device.last_seen)
                    connection.execute(
                        """
                        INSERT INTO device_session_sightings (
                            session_id, identifier, first_seen, last_seen,
                            sighting_count
                        ) VALUES (?, ?, ?, ?, 1)
                        ON CONFLICT(session_id, identifier) DO UPDATE SET
                            first_seen = MIN(
                                device_session_sightings.first_seen,
                                excluded.first_seen
                            ),
                            last_seen = MAX(
                                device_session_sightings.last_seen,
                                excluded.last_seen
                            ),
                            sighting_count =
                                device_session_sightings.sighting_count + 1
                        """,
                        (
                            self._active_session_id,
                            identifier,
                            observed_at,
                            observed_at,
                        ),
                    )
                self._prune(connection)
        except sqlite3.Error as exc:
            self.errors.append(
                f"Could not save Bluetooth history for {identifier}: {exc}",
            )
            return False
        self._last_write[identifier] = now
        return True

    def _prune(self, connection: sqlite3.Connection) -> None:
        count = int(connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        if count <= _MAX_DEVICES:
            return
        connection.execute(
            """
            DELETE FROM devices
            WHERE identifier IN (
                SELECT identifier FROM devices
                ORDER BY last_seen ASC
                LIMIT (SELECT COUNT(*) - ? FROM devices)
            )
            """,
            (_MAX_DEVICES,),
        )

    @_locked
    def start_event_capture(
        self,
        identifier: str,
        alias: str,
        *,
        max_bytes: int,
    ) -> str:
        connection = self._require_connection()
        capture_id = str(uuid.uuid4())
        with connection:
            connection.execute(
                """
                INSERT INTO event_captures (
                    capture_id, identifier, alias, started_at, max_bytes
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    capture_id, identifier.casefold(), alias.strip() or identifier,
                    time.time(), max(0, int(max_bytes)),
                ),
            )
        return capture_id

    @_locked
    def append_event(
        self,
        capture_id: str,
        event_type: str,
        data: dict,
        *,
        timestamp: float | None = None,
    ) -> bool:
        connection = self._require_connection()
        encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        size = len(encoded.encode("utf-8"))
        row = connection.execute(
            """
            SELECT max_bytes, total_bytes, ended_at
            FROM event_captures WHERE capture_id = ?
            """,
            (capture_id,),
        ).fetchone()
        if row is None or row["ended_at"] is not None:
            return False
        if row["max_bytes"] > 0 and row["total_bytes"] + size > row["max_bytes"]:
            with connection:
                connection.execute(
                    """
                    UPDATE event_captures SET dropped = dropped + 1
                    WHERE capture_id = ?
                    """,
                    (capture_id,),
                )
            return False
        with connection:
            connection.execute(
                """
                INSERT INTO bluetooth_events (
                    capture_id, timestamp, event_type, data_json, size_bytes
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    capture_id,
                    time.time() if timestamp is None else float(timestamp),
                    event_type,
                    encoded,
                    size,
                ),
            )
            connection.execute(
                """
                UPDATE event_captures
                SET total_bytes = total_bytes + ?, event_count = event_count + 1
                WHERE capture_id = ?
                """,
                (size, capture_id),
            )
        return True

    @_locked
    def finish_event_capture(self, capture_id: str) -> None:
        connection = self._require_connection()
        with connection:
            connection.execute(
                """
                UPDATE event_captures
                SET ended_at = COALESCE(ended_at, ?)
                WHERE capture_id = ?
                """,
                (time.time(), capture_id),
            )

    @_locked
    def event_capture_stats(self, capture_id: str) -> tuple[int, int]:
        connection = self._require_connection()
        row = connection.execute(
            """
            SELECT event_count, dropped
            FROM event_captures WHERE capture_id = ?
            """,
            (capture_id,),
        ).fetchone()
        return (int(row["event_count"]), int(row["dropped"])) if row else (0, 0)

    @_locked
    def events_for_capture(self, capture_id: str) -> list[dict]:
        connection = self._require_connection()
        rows = connection.execute(
            """
            SELECT timestamp, event_type, data_json
            FROM bluetooth_events WHERE capture_id = ? ORDER BY id
            """,
            (capture_id,),
        ).fetchall()
        return [
            {
                "timestamp": float(row["timestamp"]),
                "event": str(row["event_type"]),
                "data": json.loads(row["data_json"]),
            }
            for row in rows
        ]

    @_locked
    def migrate_event_files(self, directory: Path) -> int:
        """Move valid legacy Bluetooth target JSONL captures into SQLite."""
        if not directory.is_dir():
            return 0
        migrated = 0
        for path in directory.glob("target_events_*.jsonl"):
            connection = self._require_connection()
            imported = connection.execute(
                "SELECT 1 FROM legacy_event_imports WHERE path = ?",
                (str(path),),
            ).fetchone()
            if imported is not None:
                try:
                    path.unlink()
                except OSError as exc:
                    self.errors.append(
                        f"Could not remove migrated Bluetooth events {path.name}: {exc}",
                    )
                continue
            try:
                identifier = None
                with path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        raw = _parse_legacy_event(line)
                        identifier = identifier or _legacy_event_identifier(raw)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                self.errors.append(
                    f"Could not migrate Bluetooth events {path.name}: {exc}",
                )
                continue
            identifier = identifier or f"legacy:{path.stem}"
            capture_id = self.start_event_capture(
                identifier, path.stem, max_bytes=0,
            )
            try:
                with path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        record = _parse_legacy_event(line)
                        self.append_event(
                            capture_id,
                            record["event"],
                            record["data"],
                            timestamp=float(record.get("timestamp", time.time())),
                        )
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                with connection:
                    connection.execute(
                        "DELETE FROM event_captures WHERE capture_id = ?",
                        (capture_id,),
                    )
                self.errors.append(
                    f"Could not migrate Bluetooth events {path.name}: {exc}",
                )
                continue
            self.finish_event_capture(capture_id)
            with connection:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO legacy_event_imports(path, imported_at)
                    VALUES (?, ?)
                    """,
                    (str(path), time.time()),
                )
            try:
                path.unlink()
            except OSError as exc:
                self.errors.append(
                    f"Could not remove migrated Bluetooth events {path.name}: {exc}",
                )
                continue
            migrated += 1
        return migrated

    @_locked
    def clear(self) -> None:
        connection = self._require_connection()
        with connection:
            connection.execute("DELETE FROM scan_sessions")
            connection.execute("DELETE FROM event_captures")
            connection.execute("DELETE FROM devices")
        self._last_write.clear()

    @_locked
    def count(self) -> int:
        connection = self._connection
        if connection is None:
            return 0
        return int(connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0])

    @_locked
    def offline_devices(self) -> list[dict]:
        connection = self._connection
        if connection is None:
            return []
        records: list[dict] = []
        for row in connection.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC, identifier",
        ):
            identifier = str(row["identifier"])
            record = dict(row)
            for field in (
                "service_uuids_json", "service_data_uuids_json",
                "manufacturer_ids_json", "radio_types_json",
                "analysis_json", "protocol_json",
            ):
                record[field.removesuffix("_json")] = _json_value(record.pop(field))
            record["event_captures"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT capture_id, alias, started_at, ended_at, max_bytes,
                           total_bytes, event_count, dropped
                    FROM event_captures
                    WHERE identifier = ?
                    ORDER BY started_at DESC
                    """,
                    (identifier,),
                )
            ]
            record["scan_sessions"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT session.session_id, session.name, session.started_at,
                           session.ended_at, session.mode,
                           sighting.first_seen, sighting.last_seen,
                           sighting.sighting_count
                    FROM device_session_sightings AS sighting
                    JOIN scan_sessions AS session
                      ON session.session_id = sighting.session_id
                    WHERE sighting.identifier = ?
                    ORDER BY sighting.last_seen DESC
                    """,
                    (identifier,),
                )
            ]
            record["session_name"] = (
                record["scan_sessions"][0]["name"]
                if record["scan_sessions"] else "Legacy"
            )
            record["session_count"] = len(record["scan_sessions"])
            records.append(record)
        return records

    @_locked
    def analysis(self, identifier: str) -> dict:
        connection = self._connection
        if connection is None:
            return {}
        row = connection.execute(
            "SELECT analysis_json FROM devices WHERE identifier = ?",
            (identifier.casefold(),),
        ).fetchone()
        if row is None:
            return {}
        try:
            analysis = json.loads(row["analysis_json"])
        except (TypeError, json.JSONDecodeError):
            return {}
        return analysis if isinstance(analysis, dict) else {}

    @_locked
    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise BluetoothHistoryStoreError(
                "Bluetooth history database is unavailable",
            )
        return self._connection


def _merge_tuple(
    device: BluetoothDevice,
    field: str,
    raw: str,
    *,
    integers: bool = False,
) -> bool:
    try:
        values = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(values, list):
        return False
    historical = set()
    for value in values:
        if not isinstance(value, (int, str)):
            continue
        try:
            historical.add(int(value) if integers else str(value))
        except ValueError:
            continue
    current = set(getattr(device, field))
    merged = tuple(sorted(current | historical))
    if merged == getattr(device, field):
        return False
    setattr(device, field, merged)
    return True


def _json_value(value: object):
    if not isinstance(value, str) or not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _profile_changed(device: BluetoothDevice, row: sqlite3.Row) -> bool:
    if (
        device.name != "<Unknown>"
        and row["name"]
        and device.name != str(row["name"])
    ):
        return True
    if (
        device.address_type != "unknown"
        and row["address_type"] != "unknown"
        and device.address_type != row["address_type"]
    ):
        return True
    if (
        device.class_of_device is not None
        and row["class_of_device"] is not None
        and device.class_of_device != int(row["class_of_device"])
    ):
        return True
    if (
        device.appearance is not None
        and row["appearance"] is not None
        and device.appearance != int(row["appearance"])
    ):
        return True
    if device.protocol_type:
        try:
            historical_protocol = json.loads(row["protocol_json"])
        except (TypeError, json.JSONDecodeError):
            historical_protocol = {}
        if (
            isinstance(historical_protocol, dict)
            and historical_protocol.get("type")
            and historical_protocol["type"] != device.protocol_type
        ):
            return True
    for field in ("modalias", "hardware_vendor", "hardware_product"):
        value = getattr(device, field)
        if value and value != row[field]:
            return True
    historical_fields = (
        ("service_uuids", "service_uuids_json"),
        ("service_data_uuids", "service_data_uuids_json"),
        ("manufacturer_ids", "manufacturer_ids_json"),
    )
    for device_field, row_field in historical_fields:
        try:
            historical = set(json.loads(row[row_field]))
        except (TypeError, json.JSONDecodeError):
            continue
        if set(getattr(device, device_field)) - historical:
            return True
    return False


def _parse_legacy_event(line: str) -> dict:
    if len(line.encode("utf-8")) > 8 * 1024 * 1024:
        raise ValueError("event line exceeds 8 MiB")
    raw = json.loads(line)
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("data"), dict)
        or not isinstance(raw.get("event"), str)
    ):
        raise ValueError("invalid event record")
    return raw


def _legacy_event_identifier(record: dict) -> str | None:
    data = record.get("data", {})
    identifier = data.get("identifier")
    if not identifier and isinstance(data.get("device"), dict):
        identifier = data["device"].get("identifier")
    if isinstance(identifier, str) and identifier:
        return identifier.casefold()
    return None
