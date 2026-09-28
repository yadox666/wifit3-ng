from __future__ import annotations

import json
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

from wifit3.models import (
    AccessPoint,
    EnterpriseCertificate,
    EnterpriseProbeEvent,
    EnterpriseProbeRun,
    EnterpriseProfile,
    EnterpriseSession,
)
from wifit3.persist.private_files import ensure_private_directory


ENTERPRISE_SESSIONS_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "enterprise_sessions.sqlite3"
)
LEGACY_ENTERPRISE_SESSIONS_PATH = (
    Path(user_config_dir("wifit3", appauthor=False)) / "enterprise_sessions.json"
)
ENTERPRISE_SESSIONS_VERSION = 1
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_PROFILES = 2048
_MAX_SESSIONS = 128
_MAX_CERTIFICATES = 16
_MAX_PROBE_RUNS = 32
_MAX_PROBE_EVENTS = 128
_SAVE_INTERVAL_SECONDS = 5.0


class EnterpriseSessionStoreError(RuntimeError):
    pass


class EnterpriseSessionStore:
    def __init__(
        self,
        path: Path = ENTERPRISE_SESSIONS_PATH,
        *,
        legacy_path: Path | None = None,
    ) -> None:
        self.path = path
        self.errors: list[str] = []
        self._records: dict[str, dict] = {}
        self._client_salt = secrets.token_hex(16)
        self._last_save = 0.0
        self._dirty = False
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._open()
        if self._connection is not None and legacy_path is not None:
            self._migrate_legacy(legacy_path)
        self.load()

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
                raise EnterpriseSessionStoreError(
                    "Enterprise session database schema "
                    f"{version} is newer than supported 1",
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS enterprise_profiles (
                    bssid TEXT PRIMARY KEY COLLATE NOCASE,
                    ssid TEXT,
                    channel INTEGER,
                    last_seen REAL NOT NULL,
                    profile_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS enterprise_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            if version == 0:
                connection.execute("PRAGMA user_version = 1")
            salt = connection.execute(
                "SELECT value FROM enterprise_metadata WHERE key = 'client_salt'"
            ).fetchone()
            if salt is None:
                connection.execute(
                    """
                    INSERT INTO enterprise_metadata(key, value)
                    VALUES ('client_salt', ?)
                    """,
                    (self._client_salt,),
                )
            else:
                self._client_salt = str(salt["value"])
            connection.commit()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error, EnterpriseSessionStoreError) as exc:
            self.errors.append(f"Could not open Enterprise session database: {exc}")
            self.close()

    def load(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            rows = connection.execute("SELECT * FROM enterprise_profiles").fetchall()
        except sqlite3.Error as exc:
            self.errors.append(f"Could not load Enterprise sessions: {exc}")
            return
        self._records.clear()
        for row in rows[:_MAX_PROFILES]:
            try:
                raw_profile = json.loads(row["profile_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            bssid = str(row["bssid"]).casefold()
            profile = _profile_from_dict(raw_profile)
            if bssid and profile is not None:
                self._records[bssid] = {
                    "bssid": bssid,
                    "ssid": str(row["ssid"] or ""),
                    "channel": int(row["channel"] or 0),
                    "last_seen": float(row["last_seen"]),
                    "profile": raw_profile,
                }

    def profile_for(self, bssid: str) -> EnterpriseProfile | None:
        record = self._records.get(bssid.casefold())
        return _profile_from_dict(record.get("profile")) if record is not None else None

    def client_id(self, bssid: str, client_mac: str) -> str:
        return hmac.new(
            bytes.fromhex(self._client_salt),
            f"{bssid.casefold()}|{client_mac.casefold()}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()[:16]

    def remember(self, ap: AccessPoint, *, force: bool = False, now: float | None = None) -> None:
        now = time.time() if now is None else now
        bssid = ap.bssid.casefold()
        profile = _profile_to_dict(ap.enterprise)
        record = {
            "bssid": bssid,
            "ssid": ap.ssid or "",
            "channel": int(ap.channel),
            "last_seen": now,
            "profile": profile,
        }
        previous = self._records.get(bssid)
        changed = previous is None or previous.get("profile") != profile
        self._records[bssid] = record
        if len(self._records) > _MAX_PROFILES:
            oldest = min(self._records.values(), key=lambda item: float(item.get("last_seen", 0)))
            self._records.pop(str(oldest.get("bssid", "")).casefold(), None)
        self._dirty = self._dirty or changed
        if self._dirty and (force or now - self._last_save >= _SAVE_INTERVAL_SECONDS):
            self.save()

    def save(self) -> None:
        connection = self._connection
        if not self._dirty and connection is not None:
            return
        if connection is None:
            raise EnterpriseSessionStoreError(
                "Enterprise session database is unavailable",
            )
        try:
            with self._lock, connection:
                connection.execute("DELETE FROM enterprise_profiles")
                connection.executemany(
                    """
                    INSERT INTO enterprise_profiles (
                        bssid, ssid, channel, last_seen, profile_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            record["bssid"], record.get("ssid", ""),
                            int(record.get("channel", 0)),
                            float(record.get("last_seen", 0)),
                            json.dumps(record["profile"], ensure_ascii=False),
                        )
                        for record in self._records.values()
                    ],
                )
                connection.execute(
                    """
                    INSERT INTO enterprise_metadata(key, value)
                    VALUES ('client_salt', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (self._client_salt,),
                )
        except sqlite3.Error as exc:
            raise EnterpriseSessionStoreError(
                f"Could not save Enterprise sessions: {exc}",
            ) from exc
        self._last_save = time.time()
        self._dirty = False

    def _migrate_legacy(self, legacy_path: Path | None) -> None:
        if legacy_path is None or not legacy_path.exists():
            return
        try:
            if legacy_path.stat().st_size > _MAX_FILE_BYTES:
                self.errors.append("Enterprise session store exceeds the size limit")
                return
            payload = json.loads(legacy_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not migrate Enterprise sessions: {exc}")
            return
        if (
            not isinstance(payload, dict)
            or payload.get("version") != ENTERPRISE_SESSIONS_VERSION
        ):
            self.errors.append("Unsupported enterprise_sessions.json version")
            return
        connection = self._connection
        if connection is not None and int(connection.execute(
            "SELECT COUNT(*) FROM enterprise_profiles"
        ).fetchone()[0]) > 0:
            self._remove_legacy(legacy_path)
            return
        salt = payload.get("client_salt")
        if (
            isinstance(salt, str)
            and len(salt) == 32
            and all(char in "0123456789abcdef" for char in salt)
        ):
            self._client_salt = salt
        for raw in payload.get("profiles", [])[:_MAX_PROFILES]:
            if not isinstance(raw, dict):
                continue
            bssid = str(raw.get("bssid", "")).casefold()
            profile = _profile_from_dict(raw.get("profile"))
            if bssid and profile is not None:
                record = dict(raw)
                record["bssid"] = bssid
                self._records[bssid] = record
        self._dirty = True
        self.save()
        self._remove_legacy(legacy_path)

    def _remove_legacy(self, path: Path) -> None:
        try:
            path.unlink()
        except OSError as exc:
            self.errors.append(
                f"Could not remove migrated enterprise_sessions.json: {exc}",
            )

    def clear(self) -> None:
        """Forget persisted Enterprise observations without exposing identities."""
        self._records.clear()
        self._client_salt = secrets.token_hex(16)
        self._dirty = True
        self._last_save = 0.0
        self.save()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None


def _profile_to_dict(profile: EnterpriseProfile) -> dict:
    sessions = sorted(profile.sessions, key=lambda item: item.last_seen)[-_MAX_SESSIONS:]
    # Dict insertion order follows the observed TLS Certificate message and is
    # semantically significant for leaf-to-root chain checks.
    certificates = list(profile.certificates.values())[:_MAX_CERTIFICATES]
    return {
        "server_eap_types": sorted(profile.server_eap_types),
        "client_eap_types": sorted(profile.client_eap_types),
        "nak_eap_types": sorted(profile.nak_eap_types),
        "tls_versions": sorted(profile.tls_versions),
        "tls_client_versions": sorted(profile.tls_client_versions),
        "tls_cipher_suites": sorted(profile.tls_cipher_suites),
        "tls_client_cipher_suites": sorted(profile.tls_client_cipher_suites),
        "tls_server_names": sorted(profile.tls_server_names),
        "tls_supported_groups": sorted(profile.tls_supported_groups),
        "tls_signature_algorithms": sorted(profile.tls_signature_algorithms),
        "certificates": [asdict(certificate) for certificate in certificates],
        "sessions": [_session_to_dict(session) for session in sessions],
        "eap_packets": profile.eap_packets,
        "eap_requests": profile.eap_requests,
        "eap_responses": profile.eap_responses,
        "eap_successes": profile.eap_successes,
        "eap_failures": profile.eap_failures,
        "probe_attempts": profile.probe_attempts,
        "probe_last_status": profile.probe_last_status,
        "probe_last_detail": profile.probe_last_detail,
        "probe_last_seen": profile.probe_last_seen,
        "probe_history": [
            _probe_run_to_dict(run)
            for run in profile.probe_history[-_MAX_PROBE_RUNS:]
        ],
        "first_seen": profile.first_seen,
        "last_seen": profile.last_seen,
    }


def enterprise_profile_payload(profile: EnterpriseProfile) -> dict:
    """Return a sanitized, JSON-compatible Enterprise profile."""
    return _profile_to_dict(profile)


def enterprise_profile_from_payload(payload: object) -> EnterpriseProfile | None:
    """Restore a sanitized Enterprise profile payload."""
    return _profile_from_dict(payload)


def _session_to_dict(session: EnterpriseSession) -> dict:
    raw = asdict(session)
    for name in (
        "server_eap_types",
        "client_eap_types",
        "nak_eap_types",
        "tls_versions",
        "tls_client_versions",
        "tls_cipher_suites",
        "tls_client_cipher_suites",
        "certificate_fingerprints",
    ):
        raw[name] = sorted(raw[name])
    return raw


def _profile_from_dict(raw: object) -> EnterpriseProfile | None:
    if not isinstance(raw, dict):
        return None
    try:
        profile = EnterpriseProfile(
            server_eap_types=_int_set(raw.get("server_eap_types")),
            client_eap_types=_int_set(raw.get("client_eap_types")),
            nak_eap_types=_int_set(raw.get("nak_eap_types")),
            tls_versions=_str_set(raw.get("tls_versions")),
            tls_client_versions=_str_set(raw.get("tls_client_versions")),
            tls_cipher_suites=_int_set(raw.get("tls_cipher_suites")),
            tls_client_cipher_suites=_int_set(raw.get("tls_client_cipher_suites")),
            tls_server_names=_str_set(raw.get("tls_server_names")),
            tls_supported_groups=_int_set(raw.get("tls_supported_groups")),
            tls_signature_algorithms=_int_set(raw.get("tls_signature_algorithms")),
            eap_packets=max(0, int(raw.get("eap_packets", 0))),
            eap_requests=max(0, int(raw.get("eap_requests", 0))),
            eap_responses=max(0, int(raw.get("eap_responses", 0))),
            eap_successes=max(0, int(raw.get("eap_successes", 0))),
            eap_failures=max(0, int(raw.get("eap_failures", 0))),
            probe_attempts=max(0, int(raw.get("probe_attempts", 0))),
            probe_last_status=_optional_str(raw.get("probe_last_status")),
            probe_last_detail=_optional_str(raw.get("probe_last_detail")),
            probe_last_seen=_optional_float(raw.get("probe_last_seen")),
            first_seen=_optional_float(raw.get("first_seen")),
            last_seen=_optional_float(raw.get("last_seen")),
        )
    except (TypeError, ValueError):
        return None
    raw_certificates = raw.get("certificates", [])
    if not isinstance(raw_certificates, list):
        raw_certificates = []
    for item in raw_certificates[:_MAX_CERTIFICATES]:
        certificate = _certificate_from_dict(item)
        if certificate is not None:
            profile.certificates[certificate.fingerprint] = certificate
    raw_sessions = raw.get("sessions", [])
    if not isinstance(raw_sessions, list):
        raw_sessions = []
    for item in raw_sessions[-_MAX_SESSIONS:]:
        session = _session_from_dict(item)
        if session is not None:
            profile.sessions.append(session)
    raw_runs = raw.get("probe_history", [])
    if not isinstance(raw_runs, list):
        raw_runs = []
    for item in raw_runs[-_MAX_PROBE_RUNS:]:
        run = _probe_run_from_dict(item)
        if run is not None:
            profile.probe_history.append(run)
    return profile


def _probe_run_to_dict(run: EnterpriseProbeRun) -> dict:
    return {
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "status": run.status,
        "detail": run.detail[:512],
        "association_ok": run.association_ok,
        "eap_method": run.eap_method,
        "events": [
            asdict(event)
            for event in run.events[-_MAX_PROBE_EVENTS:]
        ],
    }


def _probe_run_from_dict(raw: object) -> EnterpriseProbeRun | None:
    if not isinstance(raw, dict):
        return None
    try:
        status = str(raw["status"])
        if status not in {"complete", "partial", "failed", "timeout", "unsupported", "cancelled"}:
            return None
        events = []
        raw_events = raw.get("events", [])
        if isinstance(raw_events, list):
            for item in raw_events[-_MAX_PROBE_EVENTS:]:
                event = _probe_event_from_dict(item)
                if event is not None:
                    events.append(event)
        eap_method = raw.get("eap_method")
        return EnterpriseProbeRun(
            started_at=float(raw["started_at"]),
            ended_at=float(raw["ended_at"]),
            status=status,
            detail=str(raw.get("detail", ""))[:512],
            association_ok=bool(raw.get("association_ok", False)),
            eap_method=int(eap_method) if eap_method is not None else None,
            events=events,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _probe_event_from_dict(raw: object) -> EnterpriseProbeEvent | None:
    if not isinstance(raw, dict):
        return None
    try:
        identifier = raw.get("eap_identifier")
        eap_type = raw.get("eap_type")
        direction = raw.get("direction")
        if direction not in {None, "tx", "rx", "local"}:
            return None
        return EnterpriseProbeEvent(
            timestamp=float(raw["timestamp"]),
            phase=str(raw.get("phase", ""))[:64],
            detail=str(raw.get("detail", ""))[:256],
            direction=direction,
            eap_identifier=int(identifier) if identifier is not None else None,
            eap_type=int(eap_type) if eap_type is not None else None,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _certificate_from_dict(raw: object) -> EnterpriseCertificate | None:
    if not isinstance(raw, dict):
        return None
    try:
        fingerprint = str(raw["fingerprint"])
        if len(fingerprint) != 64:
            return None
        return EnterpriseCertificate(
            fingerprint=fingerprint,
            not_before=_optional_float(raw.get("not_before")),
            not_after=_optional_float(raw.get("not_after")),
            signature_algorithm=_optional_str(raw.get("signature_algorithm")),
            public_key_algorithm=_optional_str(raw.get("public_key_algorithm")),
            public_key_bits=(
                int(raw["public_key_bits"]) if raw.get("public_key_bits") is not None else None
            ),
            subject=_optional_str(raw.get("subject")),
            issuer=_optional_str(raw.get("issuer")),
            san_dns=tuple(sorted(_str_set(raw.get("san_dns")))),
            extended_key_usage=tuple(sorted(_str_set(raw.get("extended_key_usage")))),
            is_ca=raw.get("is_ca") if isinstance(raw.get("is_ca"), bool) else None,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _session_from_dict(raw: object) -> EnterpriseSession | None:
    if not isinstance(raw, dict):
        return None
    try:
        client_id = str(raw["client_id"])
        if len(client_id) != 16 or any(char not in "0123456789abcdef" for char in client_id):
            return None
        outcome = str(raw.get("outcome", "in_progress"))
        if outcome not in {
            "in_progress", "success", "failure", "probe_complete", "probe_partial",
        }:
            return None
        source = str(raw.get("source", "passive"))
        if source not in {"passive", "active_probe"}:
            return None
        return EnterpriseSession(
            client_id=client_id,
            first_seen=float(raw["first_seen"]),
            last_seen=float(raw["last_seen"]),
            source=source,
            eap_packets=max(0, int(raw.get("eap_packets", 0))),
            server_eap_types=_int_set(raw.get("server_eap_types")),
            client_eap_types=_int_set(raw.get("client_eap_types")),
            nak_eap_types=_int_set(raw.get("nak_eap_types")),
            tls_versions=_str_set(raw.get("tls_versions")),
            tls_client_versions=_str_set(raw.get("tls_client_versions")),
            tls_cipher_suites=_int_set(raw.get("tls_cipher_suites")),
            tls_client_cipher_suites=_int_set(raw.get("tls_client_cipher_suites")),
            certificate_fingerprints=_str_set(raw.get("certificate_fingerprints")),
            outcome=outcome,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _int_set(value: object) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {int(item) for item in value}


def _str_set(value: object) -> set[str]:
    if not isinstance(value, (list, tuple)):
        return set()
    return {str(item) for item in value if isinstance(item, str)}


def _optional_float(value: object) -> float | None:
    return float(value) if value is not None else None


def _optional_str(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None
