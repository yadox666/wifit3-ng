from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

from wifit3.models import AccessPoint, AdvertisedCapabilities, IdKey, IdSource
from wifit3.persist.private_files import ensure_private_directory


AP_HISTORY_PATH = Path(user_data_dir("wifit3", appauthor=False)) / "ap_history.sqlite3"
SCHEMA_VERSION = 3
_WRITE_INTERVAL_SECONDS = 5.0
_MAX_APS = 20_000


class ApHistoryStoreError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ClientAssociationRecord:
    bssid: str
    client_mac: str
    first_seen: float
    last_seen: float
    ssid: str | None = None
    channel: int | None = None
    encryption: str | None = None


def _locked(method):
    """Serialize access to the shared SQLite connection across RX callbacks."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class ApHistoryStore:
    """Private SQLite history used to enrich APs that are observed again."""

    def __init__(self, path: Path = AP_HISTORY_PATH) -> None:
        self.path = path
        self.errors: list[str] = []
        self._last_write: dict[str, float] = {}
        self._last_client_write: dict[tuple[str, str], float] = {}
        self._signatures: dict[str, str] = {}
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
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
        except (OSError, sqlite3.Error, ApHistoryStoreError) as exc:
            self.errors.append(f"Could not open AP history: {exc}")
            self.close()

    def _migrate(self) -> None:
        connection = self._require_connection()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise ApHistoryStoreError(
                f"AP history schema {version} is newer than supported {SCHEMA_VERSION}",
            )
        if version == 0:
            connection.executescript(
                """
                CREATE TABLE access_points (
                    bssid TEXT PRIMARY KEY COLLATE NOCASE,
                    ssid TEXT,
                    ssid_source TEXT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    channel INTEGER,
                    encryption TEXT,
                    country_code TEXT,
                    security_json TEXT NOT NULL DEFAULT '{}',
                    capabilities_json TEXT NOT NULL DEFAULT '{}',
                    wps_json TEXT NOT NULL DEFAULT '{}',
                    enterprise_json TEXT,
                    network_json TEXT
                );
                CREATE INDEX access_points_last_seen_idx
                    ON access_points(last_seen DESC);
                CREATE INDEX access_points_ssid_idx
                    ON access_points(ssid COLLATE NOCASE);

                CREATE TABLE identity_evidence (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    field TEXT NOT NULL,
                    source TEXT NOT NULL,
                    value TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, field, source),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );

                CREATE TABLE artifacts (
                    path TEXT PRIMARY KEY,
                    bssid TEXT COLLATE NOCASE,
                    kind TEXT NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE INDEX artifacts_bssid_idx ON artifacts(bssid);

                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE ap_relationships (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    related_bssid TEXT NOT NULL COLLATE NOCASE,
                    kind TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, related_bssid, kind),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );
                CREATE INDEX ap_relationships_related_idx
                    ON ap_relationships(related_bssid);
                CREATE TABLE client_associations (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    client_mac TEXT NOT NULL COLLATE NOCASE,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, client_mac),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );
                CREATE INDEX client_associations_client_idx
                    ON client_associations(client_mac, last_seen DESC);
                PRAGMA user_version = 3;
                """,
            )
            connection.commit()
            version = SCHEMA_VERSION
        if version == 2:
            connection.executescript(
                """
                CREATE TABLE client_associations (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    client_mac TEXT NOT NULL COLLATE NOCASE,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, client_mac),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );
                CREATE INDEX client_associations_client_idx
                    ON client_associations(client_mac, last_seen DESC);
                PRAGMA user_version = 3;
                """
            )
            connection.commit()
            version = SCHEMA_VERSION
        if version == 1:
            connection.executescript(
                """
                CREATE TABLE ap_relationships (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    related_bssid TEXT NOT NULL COLLATE NOCASE,
                    kind TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, related_bssid, kind),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );
                CREATE INDEX ap_relationships_related_idx
                    ON ap_relationships(related_bssid);
                CREATE TABLE client_associations (
                    bssid TEXT NOT NULL COLLATE NOCASE,
                    client_mac TEXT NOT NULL COLLATE NOCASE,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (bssid, client_mac),
                    FOREIGN KEY (bssid) REFERENCES access_points(bssid)
                        ON DELETE CASCADE
                );
                CREATE INDEX client_associations_client_idx
                    ON client_associations(client_mac, last_seen DESC);
                PRAGMA user_version = 3;
                """
            )
            connection.commit()

    @_locked
    def enrich(self, ap: AccessPoint) -> bool:
        connection = self._connection
        if connection is None:
            return False
        row = connection.execute(
            "SELECT * FROM access_points WHERE bssid = ?",
            (ap.bssid.casefold(),),
        ).fetchone()
        if row is None:
            return False
        changed = False
        historical_ssid = _text(row["ssid"])
        if ap.is_hidden and historical_ssid:
            ap.ssid = historical_ssid
            ap.decloak_method = "history"
            changed = True
        if (not ap.encryption or ap.encryption == "Unknown") and row["encryption"]:
            ap.encryption = str(row["encryption"])
            changed = True
        if ap.country_code is None and row["country_code"]:
            ap.country_code = str(row["country_code"])
            changed = True
        changed |= _merge_security(ap, _json_object(row["security_json"]))
        changed |= _merge_capabilities(
            ap.capabilities,
            _json_object(row["capabilities_json"]),
        )
        for evidence in connection.execute(
            """
            SELECT field, source, value
            FROM identity_evidence
            WHERE bssid = ?
            ORDER BY first_seen
            """,
            (ap.bssid.casefold(),),
        ):
            try:
                key = IdKey[str(evidence["field"])]
                source = IdSource[str(evidence["source"])]
            except KeyError:
                continue
            if ap.identity.get_source_value(key, source) is None:
                ap.identity.set(source, key, str(evidence["value"]))
                changed = True
        historical_siblings = {
            str(item["related_bssid"])
            for item in connection.execute(
                """
                SELECT related_bssid
                FROM ap_relationships
                WHERE bssid = ? AND kind = 'sibling'
                """,
                (ap.bssid.casefold(),),
            )
        }
        if historical_siblings.difference(ap.siblings):
            ap.siblings = sorted(set(ap.siblings) | historical_siblings)
            changed = True
        enterprise = _json_object(row["enterprise_json"])
        if enterprise:
            try:
                from wifit3.persist.enterprise_sessions import enterprise_profile_from_payload

                profile = enterprise_profile_from_payload(enterprise)
            except (ImportError, TypeError, ValueError):
                profile = None
            if profile is not None and not _enterprise_has_data(ap.enterprise):
                ap.enterprise = profile
                changed = True
        return changed

    @_locked
    def remember(self, ap: AccessPoint, *, force: bool = False) -> bool:
        connection = self._connection
        if connection is None or ap.is_own_fake:
            return False
        bssid = ap.bssid.casefold()
        snapshot = _snapshot(ap)
        signature = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        now = time.time()
        if (
            not force
            and self._signatures.get(bssid) == signature
            and now - self._last_write.get(bssid, 0.0) < _WRITE_INTERVAL_SECONDS
        ):
            return False
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO access_points (
                        bssid, ssid, ssid_source, first_seen, last_seen, channel,
                        encryption, country_code, security_json, capabilities_json,
                        wps_json, enterprise_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = CASE
                            WHEN excluded.ssid IS NOT NULL AND excluded.ssid != ''
                            THEN excluded.ssid ELSE access_points.ssid END,
                        ssid_source = CASE
                            WHEN excluded.ssid IS NOT NULL AND excluded.ssid != ''
                            THEN excluded.ssid_source ELSE access_points.ssid_source END,
                        first_seen = MIN(access_points.first_seen, excluded.first_seen),
                        last_seen = MAX(access_points.last_seen, excluded.last_seen),
                        channel = excluded.channel,
                        encryption = CASE
                            WHEN excluded.encryption IS NOT NULL
                                 AND excluded.encryption NOT IN ('', 'Unknown')
                            THEN excluded.encryption ELSE access_points.encryption END,
                        country_code = COALESCE(excluded.country_code, access_points.country_code),
                        security_json = excluded.security_json,
                        capabilities_json = excluded.capabilities_json,
                        wps_json = excluded.wps_json,
                        enterprise_json = COALESCE(
                            excluded.enterprise_json, access_points.enterprise_json
                        )
                    """,
                    (
                        bssid,
                        snapshot["ssid"],
                        snapshot["ssid_source"],
                        float(ap.first_seen),
                        float(ap.last_seen),
                        int(ap.channel),
                        ap.encryption,
                        ap.country_code,
                        _dump(snapshot["security"]),
                        _dump(snapshot["capabilities"]),
                        _dump(snapshot["wps"]),
                        _dump(snapshot["enterprise"]) if snapshot["enterprise"] else None,
                    ),
                )
                self._remember_identity(connection, ap, now)
                self._remember_relationships(connection, ap, now)
                self._prune(connection)
        except sqlite3.Error as exc:
            self.errors.append(f"Could not save AP history for {bssid}: {exc}")
            return False
        self._signatures[bssid] = signature
        self._last_write[bssid] = now
        return True

    def _remember_identity(
        self,
        connection: sqlite3.Connection,
        ap: AccessPoint,
        now: float,
    ) -> None:
        for key in IdKey:
            for source in IdSource:
                value = ap.identity.get_source_value(key, source)
                if value is None:
                    continue
                connection.execute(
                    """
                    INSERT INTO identity_evidence (
                        bssid, field, source, value, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid, field, source) DO UPDATE SET
                        value = excluded.value,
                        last_seen = excluded.last_seen
                    """,
                    (
                        ap.bssid.casefold(), key.name, source.name, value, now, now,
                    ),
                )

    def _remember_relationships(
        self,
        connection: sqlite3.Connection,
        ap: AccessPoint,
        now: float,
    ) -> None:
        for related_bssid in ap.siblings:
            if related_bssid.casefold() == ap.bssid.casefold():
                continue
            connection.execute(
                """
                INSERT INTO ap_relationships (
                    bssid, related_bssid, kind, first_seen, last_seen
                ) VALUES (?, ?, 'sibling', ?, ?)
                ON CONFLICT(bssid, related_bssid, kind) DO UPDATE SET
                    last_seen = excluded.last_seen
                """,
                (ap.bssid.casefold(), related_bssid.casefold(), now, now),
            )

    @_locked
    def remember_client_association(
        self,
        bssid: str,
        client_mac: str,
        *,
        observed_at: float | None = None,
        force: bool = False,
    ) -> bool:
        """Persist exact AP↔station evidence without creating synthetic AP rows."""
        connection = self._connection
        bssid = bssid.casefold().strip()
        client_mac = client_mac.casefold().strip()
        if connection is None or not bssid or not client_mac:
            return False
        observed_at = time.time() if observed_at is None else observed_at
        key = (bssid, client_mac)
        if (
            not force
            and observed_at - self._last_client_write.get(key, 0.0)
            < _WRITE_INTERVAL_SECONDS
        ):
            return False
        try:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO client_associations (
                        bssid, client_mac, first_seen, last_seen
                    )
                    SELECT ?, ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM access_points WHERE bssid = ?
                    )
                    ON CONFLICT(bssid, client_mac) DO UPDATE SET
                        first_seen = MIN(
                            client_associations.first_seen, excluded.first_seen
                        ),
                        last_seen = MAX(
                            client_associations.last_seen, excluded.last_seen
                        )
                    """,
                    (bssid, client_mac, observed_at, observed_at, bssid),
                )
        except sqlite3.Error as exc:
            self.errors.append(
                f"Could not save client association {client_mac} → {bssid}: {exc}",
            )
            return False
        if cursor.rowcount <= 0:
            return False
        self._last_client_write[key] = observed_at
        return True

    @_locked
    def clients_for_ap(self, bssid: str) -> list[ClientAssociationRecord]:
        connection = self._connection
        if connection is None:
            return []
        rows = connection.execute(
            """
            SELECT bssid, client_mac, first_seen, last_seen
            FROM client_associations
            WHERE bssid = ?
            ORDER BY last_seen DESC
            """,
            (bssid.casefold(),),
        )
        return [
            ClientAssociationRecord(
                bssid=str(row["bssid"]),
                client_mac=str(row["client_mac"]),
                first_seen=float(row["first_seen"]),
                last_seen=float(row["last_seen"]),
            )
            for row in rows
        ]

    @_locked
    def aps_for_client(self, client_mac: str) -> list[ClientAssociationRecord]:
        connection = self._connection
        if connection is None:
            return []
        rows = connection.execute(
            """
            SELECT association.bssid, association.client_mac,
                   association.first_seen, association.last_seen,
                   ap.ssid, ap.channel, ap.encryption
            FROM client_associations AS association
            JOIN access_points AS ap ON ap.bssid = association.bssid
            WHERE association.client_mac = ?
            ORDER BY association.last_seen DESC
            """,
            (client_mac.casefold(),),
        )
        return [
            ClientAssociationRecord(
                bssid=str(row["bssid"]),
                client_mac=str(row["client_mac"]),
                first_seen=float(row["first_seen"]),
                last_seen=float(row["last_seen"]),
                ssid=_text(row["ssid"]),
                channel=_integer(row["channel"]),
                encryption=_text(row["encryption"]),
            )
            for row in rows
        ]

    @_locked
    def import_legacy(
        self,
        hidden_ssids_path: Path,
        wifi_profiles_path: Path,
        enterprise_sessions_path: Path,
        captures_dir: Path,
    ) -> int:
        connection = self._connection
        if connection is None:
            return 0
        imported_before = connection.execute(
            "SELECT value FROM metadata WHERE key = 'legacy_import_completed'"
        ).fetchone()
        if imported_before is not None:
            return 0
        imported = 0
        imported += self._import_hidden_ssids(hidden_ssids_path)
        imported += self._import_wifi_profiles(wifi_profiles_path)
        imported += self._import_enterprise(enterprise_sessions_path)
        imported += self._import_network_metadata(captures_dir)
        with connection:
            connection.execute(
                """
                INSERT INTO metadata(key, value)
                VALUES ('legacy_import_completed', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(time.time()),),
            )
        return imported

    def _import_hidden_ssids(self, path: Path) -> int:
        payload = _read_json(path)
        count = 0
        for raw in payload.get("networks", []) if payload else []:
            if not isinstance(raw, dict):
                continue
            bssid = _text(raw.get("bssid"))
            ssid = _text(raw.get("ssid"))
            if not bssid or not ssid:
                continue
            self._upsert_legacy_ap(
                bssid,
                ssid=ssid,
                ssid_source=str(raw.get("reveal_method", "history")),
                first_seen=_number(raw.get("first_revealed_at")),
                last_seen=_number(raw.get("last_revealed_at")),
            )
            count += 1
        return count

    def _import_wifi_profiles(self, path: Path) -> int:
        payload = _read_json(path)
        count = 0
        for raw in payload.get("profiles", []) if payload else []:
            if not isinstance(raw, dict):
                continue
            bssid = _text(raw.get("bssid"))
            if not bssid:
                continue
            security = {
                "akm_suites": raw.get("akm_suites", []),
                "pmf_capable": bool(raw.get("pmf_capable")),
                "pmf_required": bool(raw.get("pmf_required")),
                "rsn_ie_hex": raw.get("rsn_ie_hex"),
            }
            self._upsert_legacy_ap(
                bssid,
                ssid=_text(raw.get("ssid")),
                ssid_source="wifi_profile",
                first_seen=_number(raw.get("first_seen")),
                last_seen=_number(raw.get("last_seen")),
                channel=_integer(raw.get("channel")),
                security=security,
            )
            count += 1
        return count

    def _import_enterprise(self, path: Path) -> int:
        payload = _read_json(path)
        count = 0
        for raw in payload.get("profiles", []) if payload else []:
            if not isinstance(raw, dict):
                continue
            bssid = _text(raw.get("bssid"))
            profile = raw.get("profile")
            if not bssid or not isinstance(profile, dict):
                continue
            self._upsert_legacy_ap(
                bssid,
                ssid=_text(raw.get("ssid")),
                ssid_source="enterprise_profile",
                last_seen=_number(raw.get("last_seen")),
                channel=_integer(raw.get("channel")),
                enterprise=profile,
            )
            count += 1
        return count

    def _import_network_metadata(self, directory: Path) -> int:
        if not directory.is_dir():
            return 0
        count = 0
        paths = list(directory.glob("*_network.json"))
        try:
            paths.sort(key=lambda item: item.stat().st_mtime)
        except OSError:
            paths.sort(key=lambda item: item.name)
        for path in paths:
            payload = _read_json(path)
            bssid = _text(payload.get("bssid")) if payload else None
            if not bssid:
                continue
            try:
                modified = path.stat().st_mtime
            except OSError:
                modified = time.time()
            connection = self._require_connection()
            with connection:
                self._upsert_legacy_ap(
                    bssid,
                    ssid=_text(payload.get("ssid")),
                    ssid_source="network_metadata",
                    last_seen=modified,
                    network=payload,
                )
                connection.execute("DELETE FROM artifacts WHERE path = ?", (str(path),))
            try:
                path.unlink()
            except OSError as exc:
                self.errors.append(
                    f"Could not remove migrated network metadata {path.name}: {exc}",
                )
            count += 1
        return count

    @_locked
    def migrate_network_metadata_files(self, directory: Path) -> int:
        """Move any remaining per-AP network JSON into SQLite."""
        return self._import_network_metadata(directory)

    @_locked
    def network_metadata_payload(self, bssid: str) -> dict[str, Any] | None:
        connection = self._connection
        if connection is None:
            return None
        row = connection.execute(
            "SELECT network_json FROM access_points WHERE bssid = ?",
            (bssid.casefold(),),
        ).fetchone()
        if row is None:
            return None
        payload = _json_object(row["network_json"])
        return payload or None

    @_locked
    def save_network_metadata(
        self,
        bssid: str,
        ssid: str,
        payload: dict[str, Any],
    ) -> None:
        connection = self._require_connection()
        now = time.time()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO access_points (
                        bssid, ssid, ssid_source, first_seen, last_seen,
                        security_json, capabilities_json, wps_json, network_json
                    ) VALUES (?, ?, 'network_metadata', ?, ?, '{}', '{}', '{}', ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = CASE
                            WHEN access_points.ssid IS NULL OR access_points.ssid = ''
                            THEN excluded.ssid ELSE access_points.ssid END,
                        last_seen = MAX(access_points.last_seen, excluded.last_seen),
                        network_json = excluded.network_json
                    """,
                    (
                        bssid.casefold(), ssid or None, now, now,
                        _dump(payload),
                    ),
                )
        except sqlite3.Error as exc:
            raise ApHistoryStoreError(
                f"Could not save network metadata for {bssid}: {exc}",
            ) from exc

    def _upsert_legacy_ap(
        self,
        bssid: str,
        *,
        ssid: str | None = None,
        ssid_source: str | None = None,
        first_seen: float | None = None,
        last_seen: float | None = None,
        channel: int | None = None,
        security: dict | None = None,
        enterprise: dict | None = None,
        network: dict | None = None,
    ) -> None:
        connection = self._require_connection()
        now = time.time()
        first_seen = first_seen or last_seen or now
        last_seen = last_seen or first_seen
        with connection:
            connection.execute(
                """
                INSERT INTO access_points (
                    bssid, ssid, ssid_source, first_seen, last_seen, channel,
                    security_json, enterprise_json, network_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = COALESCE(excluded.ssid, access_points.ssid),
                    ssid_source = COALESCE(
                        excluded.ssid_source, access_points.ssid_source
                    ),
                    first_seen = MIN(access_points.first_seen, excluded.first_seen),
                    last_seen = MAX(access_points.last_seen, excluded.last_seen),
                    channel = COALESCE(excluded.channel, access_points.channel),
                    security_json = CASE
                        WHEN excluded.security_json != '{}'
                        THEN excluded.security_json ELSE access_points.security_json END,
                    enterprise_json = COALESCE(
                        excluded.enterprise_json, access_points.enterprise_json
                    ),
                    network_json = COALESCE(
                        excluded.network_json, access_points.network_json
                    )
                """,
                (
                    bssid.casefold(), ssid, ssid_source, first_seen, last_seen,
                    channel, _dump(security or {}),
                    _dump(enterprise) if enterprise else None,
                    _dump(network) if network else None,
                ),
            )

    @_locked
    def clear(self) -> None:
        connection = self._require_connection()
        with connection:
            connection.execute("DELETE FROM identity_evidence")
            connection.execute("DELETE FROM ap_relationships")
            connection.execute("DELETE FROM client_associations")
            connection.execute("DELETE FROM artifacts")
            connection.execute("DELETE FROM access_points")
            connection.execute("DELETE FROM metadata")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('legacy_import_completed', ?)",
                (str(time.time()),),
            )
        self._last_write.clear()
        self._last_client_write.clear()
        self._signatures.clear()

    @_locked
    def count(self) -> int:
        connection = self._connection
        if connection is None:
            return 0
        return int(connection.execute("SELECT COUNT(*) FROM access_points").fetchone()[0])

    @_locked
    def offline_access_points(self) -> list[dict[str, Any]]:
        connection = self._connection
        if connection is None:
            return []
        records: list[dict[str, Any]] = []
        for row in connection.execute(
            "SELECT * FROM access_points ORDER BY last_seen DESC, bssid",
        ):
            bssid = str(row["bssid"])
            record = dict(row)
            for field in (
                "security_json", "capabilities_json", "wps_json",
                "enterprise_json", "network_json",
            ):
                record[field.removesuffix("_json")] = _json_value(record.pop(field))
            record["identity_evidence"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT field, source, value, first_seen, last_seen
                    FROM identity_evidence
                    WHERE bssid = ?
                    ORDER BY field, source
                    """,
                    (bssid,),
                )
            ]
            record["relationships"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT related_bssid, kind, first_seen, last_seen
                    FROM ap_relationships
                    WHERE bssid = ?
                    ORDER BY kind, related_bssid
                    """,
                    (bssid,),
                )
            ]
            record["clients"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT client_mac, first_seen, last_seen
                    FROM client_associations
                    WHERE bssid = ?
                    ORDER BY last_seen DESC, client_mac
                    """,
                    (bssid,),
                )
            ]
            records.append(record)
        return records

    @_locked
    def offline_clients(self) -> list[dict[str, Any]]:
        connection = self._connection
        if connection is None:
            return []
        records: list[dict[str, Any]] = []
        clients = connection.execute(
            """
            SELECT client_mac, MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen, COUNT(*) AS access_point_count
            FROM client_associations
            GROUP BY client_mac
            ORDER BY last_seen DESC, client_mac
            """
        )
        for client in clients:
            record = dict(client)
            record["access_points"] = [
                dict(item) for item in connection.execute(
                    """
                    SELECT association.bssid, ap.ssid, ap.channel, ap.encryption,
                           association.first_seen, association.last_seen
                    FROM client_associations AS association
                    JOIN access_points AS ap ON ap.bssid = association.bssid
                    WHERE association.client_mac = ?
                    ORDER BY association.last_seen DESC, association.bssid
                    """,
                    (client["client_mac"],),
                )
            ]
            records.append(record)
        return records

    @_locked
    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _prune(self, connection: sqlite3.Connection) -> None:
        row = connection.execute("SELECT COUNT(*) FROM access_points").fetchone()
        if int(row[0]) <= _MAX_APS:
            return
        connection.execute(
            """
            DELETE FROM access_points
            WHERE bssid IN (
                SELECT bssid FROM access_points
                ORDER BY last_seen ASC
                LIMIT (SELECT COUNT(*) - ? FROM access_points)
            )
            """,
            (_MAX_APS,),
        )

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ApHistoryStoreError("AP history database is unavailable")
        return self._connection


def _snapshot(ap: AccessPoint) -> dict[str, Any]:
    enterprise: dict[str, Any] | None = None
    if _enterprise_has_data(ap.enterprise):
        try:
            from wifit3.persist.enterprise_sessions import enterprise_profile_payload

            enterprise = enterprise_profile_payload(ap.enterprise)
        except ImportError:
            pass
    return {
        "ssid": ap.ssid if not ap.is_hidden else None,
        "ssid_source": ap.decloak_method or "observed",
        "security": {
            "akms": list(ap.akms),
            "akm_suites": list(ap.akm_suites),
            "pairwise_cipher": ap.pairwise_cipher,
            "pairwise_ciphers": list(ap.pairwise_ciphers),
            "group_cipher": ap.group_cipher,
            "wpa3": ap.wpa3,
            "transition_mode": ap.transition_mode,
            "pmf_capable": ap.pmf_capable,
            "pmf_required": ap.pmf_required,
            "beacon_protection": ap.beacon_protection,
            "rsn_ie_hex": ap.rsn_ie.hex() if ap.rsn_ie else None,
        },
        "capabilities": _capabilities_payload(ap.capabilities),
        "wps": {
            "enabled": ap.wps,
            "locked": ap.wps_locked,
            "version": ap.wps_version,
            "config_methods": ap.wps_config_methods,
            "device_password_id": ap.wps_device_password_id,
        },
        "enterprise": enterprise,
        "siblings": sorted(item.casefold() for item in ap.siblings),
    }


def _enterprise_has_data(profile: Any) -> bool:
    return bool(
        profile.sessions
        or profile.server_eap_types
        or profile.client_eap_types
        or profile.certificates
        or profile.probe_history
        or profile.eap_packets
        or profile.probe_attempts
    )


def _capabilities_payload(caps: AdvertisedCapabilities) -> dict[str, Any]:
    raw = asdict(caps)
    for name in (
        "phy_modes", "channel_widths_mhz", "supported_rates_mbps",
        "capability_flags", "vendor_ouis",
    ):
        raw[name] = sorted(raw[name])
    return raw


def _merge_capabilities(caps: AdvertisedCapabilities, raw: dict[str, Any]) -> bool:
    if not raw:
        return False
    historical = AdvertisedCapabilities()
    for name in (
        "phy_modes", "channel_widths_mhz", "supported_rates_mbps",
        "capability_flags", "vendor_ouis",
    ):
        values = raw.get(name)
        if isinstance(values, list):
            getattr(historical, name).update(values)
    for name in (
        "max_spatial_streams", "operating_width_mhz", "secondary_channel_offset",
        "center_channel_0", "center_channel_1", "beacon_interval_tu",
        "listen_interval", "dtim_period", "station_count",
        "channel_utilization", "admission_capacity", "power_constraint_db",
        "power_min_dbm", "power_max_dbm", "country_environment",
        "wps_manufacturer", "wps_model", "wps_device_name", "wps_device_type",
    ):
        if name in raw:
            setattr(historical, name, raw[name])
    for name in (
        "channel_conflict", "radio_measurement", "fast_transition",
        "bss_transition", "wmm", "multi_bssid", "reduced_neighbor_report",
        "multi_link", "pmf_capable", "pmf_required",
    ):
        setattr(historical, name, bool(raw.get(name, False)))
    for name in ("country_channels", "supported_channel_ranges"):
        values = raw.get(name)
        if isinstance(values, list):
            setattr(
                historical,
                name,
                [tuple(item) for item in values if isinstance(item, list)],
            )
    before = _capabilities_payload(caps)
    for name in (
        "phy_modes", "channel_widths_mhz", "supported_rates_mbps",
        "capability_flags", "vendor_ouis",
    ):
        getattr(caps, name).update(getattr(historical, name))
    for name in (
        "max_spatial_streams", "operating_width_mhz", "secondary_channel_offset",
        "center_channel_0", "center_channel_1", "beacon_interval_tu",
        "listen_interval", "dtim_period", "station_count",
        "channel_utilization", "admission_capacity", "power_constraint_db",
        "power_min_dbm", "power_max_dbm", "country_environment",
        "wps_manufacturer", "wps_model", "wps_device_name", "wps_device_type",
    ):
        if getattr(caps, name) is None:
            setattr(caps, name, getattr(historical, name))
    for name in (
        "channel_conflict", "radio_measurement", "fast_transition",
        "bss_transition", "wmm", "multi_bssid", "reduced_neighbor_report",
        "multi_link", "pmf_capable", "pmf_required",
    ):
        setattr(caps, name, getattr(caps, name) or getattr(historical, name))
    if not caps.country_channels:
        caps.country_channels = list(historical.country_channels)
    if not caps.supported_channel_ranges:
        caps.supported_channel_ranges = list(historical.supported_channel_ranges)
    return before != _capabilities_payload(caps)


def _merge_security(ap: AccessPoint, raw: dict[str, Any]) -> bool:
    if not raw:
        return False
    changed = False
    for name in ("akms", "akm_suites", "pairwise_ciphers"):
        if not getattr(ap, name) and isinstance(raw.get(name), list):
            setattr(ap, name, list(raw[name]))
            changed = True
    for name in ("pairwise_cipher", "group_cipher"):
        if getattr(ap, name) is None and raw.get(name):
            setattr(ap, name, str(raw[name]))
            changed = True
    for name in (
        "wpa3", "transition_mode", "pmf_capable", "pmf_required",
        "beacon_protection",
    ):
        if not getattr(ap, name) and raw.get(name):
            setattr(ap, name, True)
            changed = True
    if ap.rsn_ie is None and isinstance(raw.get("rsn_ie_hex"), str):
        try:
            ap.rsn_ie = bytes.fromhex(raw["rsn_ie_hex"])
            changed = True
        except ValueError:
            pass
    return changed


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        return {}
    try:
        raw = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return raw if isinstance(raw, dict) else {}


def _json_value(value: object) -> Any:
    if not isinstance(value, str) or not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _text(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _number(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _integer(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
