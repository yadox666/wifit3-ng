from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import replace
import threading
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

from wifit3.models import BluetoothDevice
from wifit3.observe.product_catalog import (
    CatalogHit,
    bluetooth_catalog_hit_from_history,
    catalog_blob,
    catalog_json_from_hit,
    match_bluetooth,
    prepare_device_catalog,
    restore_catalog,
    supplement_catalog_hit,
    with_protocol_live,
)
from wifit3.models.bluetooth_device import (
    BLE_RADIO,
    should_persist_bluetooth_observation,
)
from wifit3.models.location import positions_digest
from wifit3.persist.private_files import ensure_private_directory
from wifit3.persist.scan_sessions import ScanSession, merge_session_metadata


BLUETOOTH_HISTORY_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "bluetooth_history.sqlite3"
)
SCHEMA_VERSION = 16
_MAX_DEVICES = 50_000
_WRITE_INTERVAL_SECONDS = 5.0

# Keep in sync with ``gatt_metadata.GATT_IDENTITY_STORAGE_FIELDS`` (no import: cycle).
_GATT_IDENTITY_DB_FIELDS: tuple[str, ...] = (
    "model_number",
    "serial_number",
    "firmware_revision",
    "hardware_revision",
    "software_revision",
    "manufacturer_name",
    "gatt_device_name",
    "pnp_id",
)


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
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 11:
            connection.executescript(
                """
                ALTER TABLE devices
                    ADD COLUMN catalog_json TEXT NOT NULL DEFAULT '{}';
                PRAGMA user_version = 12;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 12:
            # Product-family matching landed after many devices were already
            # stored with an empty catalog. Recompute labels for historical rows
            # from the identity fields we retain (name, OUI, company id, service
            # UUIDs, protocol) so upgrades surface them without a re-sighting.
            _backfill_catalog(connection)
            connection.execute("PRAGMA user_version = 13")
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 13:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS bluetooth_observation_links (
                    identifier_a TEXT NOT NULL COLLATE NOCASE,
                    identifier_b TEXT NOT NULL COLLATE NOCASE,
                    confidence TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    method TEXT NOT NULL DEFAULT 'passive-radio-correlation',
                    PRIMARY KEY (identifier_a, identifier_b)
                );
                CREATE INDEX IF NOT EXISTS bluetooth_observation_links_lookup_idx
                    ON bluetooth_observation_links(identifier_b, last_seen DESC);
                PRAGMA user_version = 14;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 14:
            connection.executescript(
                """
                DROP TABLE IF EXISTS bluetooth_observation_links_v15;
                CREATE TABLE bluetooth_observation_links_v15 (
                    identifier_a TEXT NOT NULL COLLATE NOCASE,
                    identifier_b TEXT NOT NULL COLLATE NOCASE,
                    confidence TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    method TEXT NOT NULL DEFAULT 'passive-radio-correlation',
                    PRIMARY KEY (identifier_a, identifier_b),
                    FOREIGN KEY (identifier_a) REFERENCES devices(identifier)
                        ON DELETE CASCADE,
                    FOREIGN KEY (identifier_b) REFERENCES devices(identifier)
                        ON DELETE CASCADE
                );
                INSERT OR REPLACE INTO bluetooth_observation_links_v15
                SELECT link.identifier_a, link.identifier_b, link.confidence,
                       link.evidence_json, link.last_seen, link.method
                FROM bluetooth_observation_links AS link
                JOIN devices AS first
                  ON first.identifier = link.identifier_a
                JOIN devices AS second
                  ON second.identifier = link.identifier_b;
                DROP TABLE bluetooth_observation_links;
                ALTER TABLE bluetooth_observation_links_v15
                    RENAME TO bluetooth_observation_links;
                CREATE INDEX IF NOT EXISTS bluetooth_observation_links_lookup_idx
                    ON bluetooth_observation_links(identifier_b, last_seen DESC);
                PRAGMA user_version = 15;
                """
            )
            connection.commit()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 15:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(devices)")
            }
            if "ble_mac" not in columns:
                connection.execute(
                    "ALTER TABLE devices ADD COLUMN ble_mac TEXT NOT NULL DEFAULT ''"
                )
            connection.execute("PRAGMA user_version = 16")
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
    def patch_scan_session(
        self,
        session_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        metadata_patch: dict[str, Any] | None = None,
    ) -> None:
        connection = self._connection
        if connection is None:
            return
        sets: list[str] = []
        params: list[Any] = []
        if name is not None:
            sets.append("name = ?")
            params.append(name)
        if description is not None:
            sets.append("description = ?")
            params.append(description)
        if metadata_patch:
            row = connection.execute(
                "SELECT metadata_json FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            prior = row[0] if row is not None else "{}"
            merged = merge_session_metadata(prior, metadata_patch)
            sets.append("metadata_json = ?")
            params.append(merged)
        if not sets:
            return
        params.append(session_id)
        with connection:
            connection.execute(
                f"UPDATE scan_sessions SET {', '.join(sets)} WHERE session_id = ?",
                params,
            )

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
            "ble_mac",
            *_GATT_IDENTITY_DB_FIELDS,
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
        if "catalog_json" in row.keys() and restore_catalog(device, row["catalog_json"]):
            changed = True
        links = connection.execute(
            """
            SELECT identifier_a, identifier_b, confidence, evidence_json
            FROM bluetooth_observation_links
            WHERE identifier_a = ? OR identifier_b = ?
            ORDER BY last_seen DESC
            """,
            (device.identifier.casefold(), device.identifier.casefold()),
        ).fetchall()
        if links:
            related: set[str] = set(device.related_identifiers)
            evidence: set[str] = set(device.correlation_evidence)
            confidence = device.correlation_confidence
            correlation_links = {
                identifier: (level, link_evidence)
                for identifier, level, link_evidence in device.correlation_links
            }
            for link in links:
                left = str(link["identifier_a"])
                right = str(link["identifier_b"])
                counterpart = (
                    right
                    if left.casefold() == device.identifier.casefold()
                    else left
                )
                related.add(counterpart)
                if str(link["confidence"]) == "high":
                    confidence = "high"
                elif not confidence:
                    confidence = "medium"
                raw_evidence = _json_value(link["evidence_json"])
                if isinstance(raw_evidence, list):
                    evidence.update(str(item) for item in raw_evidence)
                correlation_links[counterpart] = (
                    str(link["confidence"]),
                    tuple(
                        sorted(str(item) for item in raw_evidence)
                        if isinstance(raw_evidence, list)
                        else ()
                    ),
                )
            new_related = tuple(sorted(related))
            new_evidence = tuple(sorted(evidence))
            if new_related != device.related_identifiers:
                device.related_identifiers = new_related
                changed = True
            if new_evidence != device.correlation_evidence:
                device.correlation_evidence = new_evidence
                changed = True
            if confidence != device.correlation_confidence:
                device.correlation_confidence = confidence
                changed = True
            new_links = tuple(sorted(
                (
                    identifier,
                    level,
                    link_evidence,
                )
                for identifier, (level, link_evidence) in correlation_links.items()
            ))
            if new_links != device.correlation_links:
                device.correlation_links = new_links
                changed = True
        return changed

    @_locked
    def remember(
        self,
        device: BluetoothDevice,
        *,
        force: bool = False,
        manufacturer_data: dict[int, bytes] | None = None,
        service_data: dict[str, bytes] | None = None,
    ) -> bool:
        from wifit3.bluetooth.classification import device_classification

        connection = self._connection
        if connection is None or not should_persist_bluetooth_observation(device):
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
            "location": {
                "digest": positions_digest(device.positions),
            },
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
            "ble_mac": device.ble_mac,
            "analysis": analysis,
            "protocol": {
                "category": device.protocol_category,
                "type": device.protocol_type,
                "source": device.protocol_source,
                "confidence": device.protocol_confidence,
                "decode_state": device.decode_state,
            },
        }
        catalog_patch = prepare_device_catalog(
            device,
            manufacturer_data=manufacturer_data,
            service_data=service_data,
        )
        if catalog_patch:
            device = replace(device, **catalog_patch)
        now = time.time()
        pending_catalog = catalog_blob(device)
        if not force and now - self._last_write.get(identifier, 0.0) < _WRITE_INTERVAL_SECONDS:
            fingerprint_changed = False
            links_changed = self._observation_links_changed(connection, device)
            gatt_changed = self._gatt_identity_changed(connection, identifier, snapshot)
            ble_mac_changed = self._ble_mac_changed(connection, identifier, snapshot)
            location_changed = self._location_digest_changed(
                connection,
                identifier,
                positions_digest(device.positions),
            )
            row = connection.execute(
                "SELECT * FROM devices WHERE identifier = ?",
                (identifier,),
            ).fetchone()
            profile_changed = row is not None and _profile_changed(device, row)
            if (
                pending_catalog == "{}"
                and not fingerprint_changed
                and not links_changed
                and not gatt_changed
                and not ble_mac_changed
                and not location_changed
                and not profile_changed
            ):
                return False
            existing_catalog = (
                str(row["catalog_json"] or "{}") if row is not None else "{}"
            )
            catalog_changed = pending_catalog != existing_catalog
            if (
                not catalog_changed
                and not fingerprint_changed
                and not links_changed
                and not gatt_changed
                and not ble_mac_changed
                and not location_changed
                and not profile_changed
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
                        manufacturer_name, gatt_device_name, pnp_id,
                        ble_mac, catalog_json
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
                        END,
                        ble_mac = CASE
                            WHEN excluded.ble_mac = ''
                            THEN devices.ble_mac
                            ELSE excluded.ble_mac
                        END,
                        catalog_json = CASE
                            WHEN excluded.catalog_json = '{}'
                            THEN devices.catalog_json
                            ELSE excluded.catalog_json
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
                        snapshot["ble_mac"],
                        catalog_blob(device),
                    ),
                )
                self._remember_observation_links(connection, device)
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

    @staticmethod
    def _correlation_rows(
        device: BluetoothDevice,
    ) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
        if device.correlation_links:
            return device.correlation_links
        if len(device.related_identifiers) == 1:
            return (
                (
                    device.related_identifiers[0],
                    device.correlation_confidence or "medium",
                    tuple(sorted(device.correlation_evidence)),
                ),
            )
        return ()

    @staticmethod
    def _location_digest_changed(
        connection: sqlite3.Connection,
        identifier: str,
        digest: str,
    ) -> bool:
        if not digest:
            return False
        row = connection.execute(
            "SELECT analysis_json FROM devices WHERE identifier = ?",
            (identifier.casefold(),),
        ).fetchone()
        if row is None:
            return True
        analysis = _json_value(row[0])
        if not isinstance(analysis, dict):
            return True
        old = (analysis.get("location") or {}).get("digest", "")
        return digest != old

    @staticmethod
    def _gatt_identity_changed(
        connection: sqlite3.Connection,
        identifier: str,
        snapshot: dict[str, Any],
    ) -> bool:
        columns = ", ".join(_GATT_IDENTITY_DB_FIELDS)
        row = connection.execute(
            f"SELECT {columns} FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return any(
                str(snapshot.get(field) or "").strip()
                for field in _GATT_IDENTITY_DB_FIELDS
            )
        for field in _GATT_IDENTITY_DB_FIELDS:
            stored = str(row[field] or "").strip()
            incoming = str(snapshot.get(field) or "").strip()
            if incoming and incoming != stored:
                return True
        return False

    @staticmethod
    def _ble_mac_changed(
        connection: sqlite3.Connection,
        identifier: str,
        snapshot: dict[str, Any],
    ) -> bool:
        incoming = str(snapshot.get("ble_mac") or "").strip()
        if not incoming:
            return False
        row = connection.execute(
            "SELECT ble_mac FROM devices WHERE identifier = ?",
            (identifier.casefold(),),
        ).fetchone()
        if row is None:
            return True
        stored = str(row["ble_mac"] or "").strip()
        return incoming != stored

    def _observation_links_changed(
        self,
        connection: sqlite3.Connection,
        device: BluetoothDevice,
    ) -> bool:
        for related, confidence, evidence in self._correlation_rows(device):
            first, second = sorted(
                (device.identifier.casefold(), related.casefold()),
            )
            row = connection.execute(
                """
                SELECT confidence, evidence_json
                FROM bluetooth_observation_links
                WHERE identifier_a = ? AND identifier_b = ?
                """,
                (first, second),
            ).fetchone()
            if row is None:
                return True
            stored_evidence = _json_value(row["evidence_json"])
            if str(row["confidence"]) != confidence or set(
                stored_evidence if isinstance(stored_evidence, list) else []
            ) != set(evidence):
                return True
        return False

    def _remember_observation_links(
        self,
        connection: sqlite3.Connection,
        device: BluetoothDevice,
    ) -> None:
        for related, confidence, link_evidence in self._correlation_rows(device):
            if related.casefold() == device.identifier.casefold():
                continue
            first, second = sorted(
                (device.identifier.casefold(), related.casefold()),
            )
            evidence = json.dumps(
                sorted(set(link_evidence)),
                separators=(",", ":"),
            )
            connection.execute(
                """
                INSERT INTO bluetooth_observation_links (
                    identifier_a, identifier_b, confidence,
                    evidence_json, last_seen, method
                )
                SELECT ?, ?, ?, ?, ?, 'passive-radio-correlation'
                WHERE EXISTS (
                    SELECT 1 FROM devices WHERE identifier = ?
                )
                ON CONFLICT(identifier_a, identifier_b) DO UPDATE SET
                    confidence = CASE
                        WHEN excluded.confidence = 'high' THEN 'high'
                        ELSE bluetooth_observation_links.confidence
                    END,
                    evidence_json = excluded.evidence_json,
                    last_seen = MAX(
                        bluetooth_observation_links.last_seen,
                        excluded.last_seen
                    )
                """,
                (
                    first,
                    second,
                    confidence,
                    evidence,
                    float(device.last_seen),
                    related.casefold(),
                ),
            )

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
    def assign_catalog_family(
        self,
        identifier: str,
        family_id: str | None,
    ) -> tuple[bool, str]:
        """Pin or clear a manual product-catalog family on one stored device."""
        from wifit3.observe.product_catalog import (
            catalog_hit_for_family_id,
            catalog_json_from_hit,
        )

        connection = self._require_connection()
        row = connection.execute(
            "SELECT identifier FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return False, "Device is not in the offline database."
        pinned = (family_id or "").strip()
        if pinned:
            hit = catalog_hit_for_family_id(pinned)
            if not hit.present:
                return False, f"Unknown catalog family “{pinned}”."
            payload = catalog_json_from_hit(hit, family_id=pinned)
            message = f"Assigned {hit.labels[0]} ({hit.catalog_class})."
        else:
            row = connection.execute(
                "SELECT identifier, name, protocol_json, catalog_json, "
                "service_uuids_json, service_data_uuids_json, manufacturer_ids_json, "
                "model_number, manufacturer_name, gatt_device_name, pnp_id, "
                "hardware_vendor, hardware_product "
                "FROM devices WHERE identifier = ?",
                (identifier,),
            ).fetchone()
            protocol = _json_value(row["protocol_json"])
            protocol = protocol if isinstance(protocol, dict) else {}
            hit = bluetooth_catalog_hit_from_history(
                name=str(row["name"] or ""),
                identifier=str(row["identifier"] or ""),
                protocol=protocol,
                manufacturer_ids=_json_list(row["manufacturer_ids_json"]),
                service_data_uuids=_json_list(row["service_data_uuids_json"]),
                service_uuids=_json_list(row["service_uuids_json"]),
                gatt_source=_gatt_source_from_device_row(row),
            )
            payload = catalog_json_from_hit(hit, family_id="")
            message = "Cleared manual family; automatic rules re-applied."
        with connection:
            connection.execute(
                "UPDATE devices SET catalog_json = ? WHERE identifier = ?",
                (payload, identifier),
            )
        return True, message

    @_locked
    def reapply_product_catalog(self) -> int:
        """Re-run the current product catalog against every stored device row."""
        connection = self._require_connection()
        updated = 0
        rows = connection.execute(
            "SELECT identifier, name, protocol_json, catalog_json, "
            "service_uuids_json, service_data_uuids_json, manufacturer_ids_json "
            "FROM devices",
        ).fetchall()
        with connection:
            for row in rows:
                try:
                    existing_payload = json.loads(str(row["catalog_json"] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    existing_payload = {}
                pinned = ""
                if isinstance(existing_payload, dict):
                    pinned = str(existing_payload.get("family_id") or "").strip()
                hit = _catalog_hit_for_row(row)
                payload = catalog_json_from_hit(hit, family_id=pinned)
                existing = str(row["catalog_json"] or "{}")
                if payload == existing:
                    continue
                connection.execute(
                    "UPDATE devices SET catalog_json = ? WHERE identifier = ?",
                    (payload, str(row["identifier"] or "")),
                )
                updated += 1
        return updated

    @_locked
    def clear(self) -> None:
        connection = self._require_connection()
        with connection:
            connection.execute("DELETE FROM scan_sessions")
            connection.execute("DELETE FROM event_captures")
            connection.execute("DELETE FROM bluetooth_observation_links")
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
        links_by_identifier: dict[str, list[sqlite3.Row]] = {}
        for link in connection.execute(
            """
            SELECT identifier_a, identifier_b, confidence,
                   evidence_json, last_seen, method
            FROM bluetooth_observation_links
            ORDER BY last_seen DESC
            """
        ):
            links_by_identifier.setdefault(
                str(link["identifier_a"]).casefold(),
                [],
            ).append(link)
            links_by_identifier.setdefault(
                str(link["identifier_b"]).casefold(),
                [],
            ).append(link)
        records: list[dict] = []
        for row in connection.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC, identifier",
        ):
            identifier = str(row["identifier"])
            record = dict(row)
            for field in (
                "service_uuids_json", "service_data_uuids_json",
                "manufacturer_ids_json", "radio_types_json",
                "analysis_json", "protocol_json", "catalog_json",
            ):
                record[field.removesuffix("_json")] = _json_value(record.pop(field))
            catalog = record.get("catalog")
            if isinstance(catalog, dict) and not (
                catalog.get("labels") or catalog.get("live") or catalog.get("attention")
            ):
                protocol = record.get("protocol") if isinstance(record.get("protocol"), dict) else {}
                hit = with_protocol_live(
                    CatalogHit(),
                    str(protocol.get("type") or ""),
                    str(protocol.get("decode_state") or ""),
                )
                if not hit.present:
                    hit = supplement_catalog_hit(
                        hit,
                        bluetooth_device_from_offline_record(record),
                    )
                if hit.present:
                    record["catalog"] = {
                        "labels": list(hit.labels),
                        "class": hit.catalog_class,
                        "notes": hit.notes,
                        "attention": hit.attention,
                        "live": hit.live,
                        "live_strong": hit.live_strong,
                        "sentence": hit.sentence,
                    }
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
            links = links_by_identifier.get(identifier.casefold(), [])
            record["probable_links"] = [
                {
                    "identifier": (
                        str(link["identifier_b"])
                        if str(link["identifier_a"]).casefold()
                        == identifier.casefold()
                        else str(link["identifier_a"])
                    ),
                    "confidence": str(link["confidence"]),
                    "evidence": _json_value(link["evidence_json"]),
                    "last_seen": float(link["last_seen"]),
                    "method": str(link["method"]),
                }
                for link in links
            ]
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


def bluetooth_device_from_offline_record(record: dict[str, Any]) -> BluetoothDevice:
    """Rebuild a ``BluetoothDevice`` from one ``offline_devices()`` row."""
    analysis = record.get("analysis") if isinstance(record.get("analysis"), dict) else {}
    signal = analysis.get("signal") if isinstance(analysis.get("signal"), dict) else {}
    activity = analysis.get("activity") if isinstance(analysis.get("activity"), dict) else {}
    baseline = analysis.get("baseline") if isinstance(analysis.get("baseline"), dict) else {}
    hardware = (
        analysis.get("hardware_identity")
        if isinstance(analysis.get("hardware_identity"), dict)
        else {}
    )
    protocol = record.get("protocol") if isinstance(record.get("protocol"), dict) else {}
    catalog = record.get("catalog") if isinstance(record.get("catalog"), dict) else {}

    def _tuple_field(name: str) -> tuple:
        raw = record.get(name)
        if not isinstance(raw, list):
            return ()
        return tuple(raw)

    def _int_tuple(name: str) -> tuple[int, ...]:
        return tuple(int(item) for item in _tuple_field(name))

    links = record.get("probable_links") or []
    related: list[str] = []
    evidence: list[str] = []
    confidence = ""
    correlation_links: list[tuple[str, str, tuple[str, ...]]] = []
    for item in links:
        if not isinstance(item, dict):
            continue
        peer = str(item.get("identifier") or "").strip()
        if peer:
            related.append(peer)
        level = str(item.get("confidence") or "")
        if level and not confidence:
            confidence = level
        raw_evidence = item.get("evidence")
        if isinstance(raw_evidence, dict):
            for key, value in raw_evidence.items():
                evidence.append(f"{key}={value}")
        elif raw_evidence:
            evidence.append(str(raw_evidence))
        if peer and level:
            correlation_links.append((peer, level, tuple(evidence)))

    name = str(record.get("name") or "<Unknown>")
    return BluetoothDevice(
        identifier=str(record.get("identifier") or ""),
        name=name if name else "<Unknown>",
        rssi=int(signal.get("last_rssi") or -127),
        service_uuids=tuple(str(item) for item in _tuple_field("service_uuids")),
        service_data_uuids=tuple(str(item) for item in _tuple_field("service_data_uuids")),
        manufacturer_ids=_int_tuple("manufacturer_ids"),
        manufacturer_data_bytes=int(activity.get("manufacturer_data_bytes") or 0),
        service_data_bytes=int(activity.get("service_data_bytes") or 0),
        tx_power=(
            int(record["tx_power"])
            if record.get("tx_power") is not None
            else None
        ),
        advertisement_count=int(activity.get("advertisement_count") or 0),
        advertisement_interval=activity.get("latest_interval"),
        first_seen=float(record.get("first_seen") or 0.0),
        last_seen=float(record.get("last_seen") or 0.0),
        radio_types=tuple(str(item) for item in _tuple_field("radio_types")) or (BLE_RADIO,),
        class_of_device=record.get("class_of_device"),
        appearance=record.get("appearance"),
        address_type=str(record.get("address_type") or "unknown"),
        payload_fingerprint=str(record.get("payload_fingerprint") or ""),
        profile_fingerprint=str(record.get("profile_fingerprint") or ""),
        baseline_status=str(baseline.get("status") or "unavailable"),
        profile_changed=bool(baseline.get("profile_changed")),
        rssi_average=signal.get("average_rssi"),
        rssi_min=signal.get("minimum_rssi"),
        rssi_max=signal.get("maximum_rssi"),
        rssi_samples=int(signal.get("samples") or 0),
        rssi_trend=str(signal.get("trend") or "insufficient"),
        protocol_category=str(protocol.get("category") or ""),
        protocol_type=str(protocol.get("type") or ""),
        protocol_source=str(protocol.get("source") or ""),
        protocol_confidence=str(protocol.get("confidence") or ""),
        decode_state=str(protocol.get("decode_state") or ""),
        modalias=str(record.get("modalias") or hardware.get("modalias") or ""),
        hardware_vendor=str(record.get("hardware_vendor") or hardware.get("vendor") or ""),
        hardware_product=str(record.get("hardware_product") or hardware.get("product") or ""),
        hardware_source=str(record.get("hardware_source") or hardware.get("source") or ""),
        related_identifiers=tuple(related),
        correlation_confidence=confidence,
        correlation_evidence=tuple(evidence),
        correlation_links=tuple(correlation_links),
        model_number=str(record.get("model_number") or ""),
        serial_number=str(record.get("serial_number") or ""),
        firmware_revision=str(record.get("firmware_revision") or ""),
        hardware_revision=str(record.get("hardware_revision") or ""),
        software_revision=str(record.get("software_revision") or ""),
        manufacturer_name=str(record.get("manufacturer_name") or ""),
        gatt_device_name=str(record.get("gatt_device_name") or ""),
        pnp_id=str(record.get("pnp_id") or ""),
        ble_mac=str(record.get("ble_mac") or ""),
        catalog_labels=tuple(str(item) for item in (catalog.get("labels") or [])),
        catalog_class=str(catalog.get("class") or ""),
        catalog_notes=str(catalog.get("notes") or ""),
        catalog_attention=str(catalog.get("attention") or ""),
        catalog_live=str(catalog.get("live") or ""),
        catalog_live_strong=bool(catalog.get("live_strong")),
        catalog_sentence=str(catalog.get("sentence") or ""),
        catalog_family_id=str(catalog.get("family_id") or ""),
        discovery_source=str(analysis.get("discovery_source") or "system"),
    )


def _json_value(value: object):
    if not isinstance(value, str) or not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _json_list(value: object) -> list:
    parsed = _json_value(value)
    return parsed if isinstance(parsed, list) else []


def _catalog_hit_for_row(row: sqlite3.Row) -> CatalogHit:
    try:
        payload = json.loads(str(row["catalog_json"] or "{}"))
    except (TypeError, json.JSONDecodeError):
        payload = {}
    family_id = ""
    if isinstance(payload, dict):
        family_id = str(payload.get("family_id") or "").strip()
    if family_id:
        from wifit3.observe.product_catalog import catalog_hit_for_family_id

        manual = catalog_hit_for_family_id(family_id)
        if manual.present:
            return manual
    protocol = _json_value(row["protocol_json"])
    protocol = protocol if isinstance(protocol, dict) else {}
    return bluetooth_catalog_hit_from_history(
        name=str(row["name"] or ""),
        identifier=str(row["identifier"] or ""),
        protocol=protocol,
        manufacturer_ids=_json_list(row["manufacturer_ids_json"]),
        service_data_uuids=_json_list(row["service_data_uuids_json"]),
        service_uuids=_json_list(row["service_uuids_json"]),
        gatt_source=_gatt_source_from_device_row(row),
    )


def _gatt_source_from_device_row(row: sqlite3.Row) -> dict[str, str]:
    fields = (
        "model_number",
        "manufacturer_name",
        "gatt_device_name",
        "pnp_id",
        "hardware_vendor",
        "hardware_product",
    )
    keys = row.keys()
    return {field: str(row[field] or "") for field in fields if field in keys}


def _backfill_catalog(connection: sqlite3.Connection) -> None:
    """Recompute ``catalog_json`` for rows stored before product-family matching.

    Raw advertisement payloads are not retained, so byte-prefix rules cannot be
    re-evaluated. Name, OUI, company-id, service-UUID, and protocol rules are, so
    historical devices still gain their family labels on upgrade. Only rows with
    an empty catalog are touched, keeping the pass idempotent.
    """
    rows = connection.execute(
        "SELECT identifier, name, protocol_json, catalog_json, "
        "service_uuids_json, service_data_uuids_json, manufacturer_ids_json "
        "FROM devices"
    ).fetchall()
    for row in rows:
        try:
            current = json.loads(row["catalog_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            current = {}
        if isinstance(current, dict) and (
            current.get("labels") or current.get("live") or current.get("attention")
        ):
            continue
        hit = _catalog_hit_for_row(row)
        if not hit.present:
            continue
        connection.execute(
            "UPDATE devices SET catalog_json = ? WHERE identifier = ?",
            (catalog_json_from_hit(hit), str(row["identifier"] or "")),
        )
    connection.commit()


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
