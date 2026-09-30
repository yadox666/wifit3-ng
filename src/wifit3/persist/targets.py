from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir, user_data_dir

from wifit3.persist.private_files import ensure_private_directory


TARGETS_PATH = Path(user_data_dir("wifit3", appauthor=False)) / "targets.sqlite3"
LEGACY_TARGETS_PATH = (
    Path(user_config_dir("wifit3", appauthor=False)) / "targets.json"
)
TARGETS_VERSION = 2
_VALID_MEDIA = {"wifi", "bluetooth"}
_VALID_KINDS = {"ap", "client", "device"}
_VALID_ROLES = {"target", "whitelist"}
_VALID_MATCH_MODES = {"id", "name", "probe"}


class TargetStoreError(RuntimeError):
    pass


@dataclass
class SavedTarget:
    id: str
    alias: str
    medium: str
    kind: str
    identifier: str
    details: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_locked_at: float | None = None
    priority: int = 0
    enabled: bool = True
    role: str = "target"
    match_mode: str = "id"


def _fill_empty(existing: dict[str, Any], incoming: dict[str, Any]) -> bool:
    changed = False
    for key, value in incoming.items():
        current = existing.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            changed |= _fill_empty(current, value)
        elif key not in existing or current is None or current == "" or current == []:
            if value is not None and value != "" and value != []:
                existing[key] = value
                changed = True
    return changed


class TargetStore:
    def __init__(
        self,
        path: Path = TARGETS_PATH,
        *,
        legacy_path: Path | None = None,
    ) -> None:
        self.path = path
        self.targets: list[SavedTarget] = []
        self.errors: list[str] = []
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
            if version > 2:
                raise TargetStoreError(
                    f"Targets database schema {version} is newer than supported 2",
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
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
                )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS targets_identity_idx
                ON targets(medium, kind, identifier COLLATE NOCASE)
                """
            )
            if version == 0:
                connection.execute("PRAGMA user_version = 2")
            elif version == 1:
                columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(targets)").fetchall()
                }
                if "role" not in columns:
                    connection.execute(
                        "ALTER TABLE targets ADD COLUMN role TEXT NOT NULL DEFAULT 'target'"
                    )
                if "match_mode" not in columns:
                    connection.execute(
                        "ALTER TABLE targets ADD COLUMN match_mode TEXT NOT NULL DEFAULT 'id'"
                    )
                connection.execute("PRAGMA user_version = 2")
            connection.commit()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (OSError, sqlite3.Error, TargetStoreError) as exc:
            self.errors.append(f"Could not open targets database: {exc}")
            self.close()

    def load(self) -> None:
        connection = self._connection
        if connection is None:
            self.targets = []
            return
        try:
            rows = connection.execute(
                """
                SELECT * FROM targets
                ORDER BY priority, created_at
                """
            ).fetchall()
        except sqlite3.Error as exc:
            self.targets = []
            self.errors.append(f"Could not load targets: {exc}")
            return
        loaded: list[SavedTarget] = []
        for row in rows:
            try:
                details = json.loads(row["details_json"])
                target = SavedTarget(
                    id=str(row["id"]),
                    alias=str(row["alias"]),
                    medium=str(row["medium"]),
                    kind=str(row["kind"]),
                    identifier=str(row["identifier"]),
                    details=details,
                    created_at=float(row["created_at"]),
                    updated_at=float(row["updated_at"]),
                    last_locked_at=(
                        float(row["last_locked_at"])
                        if row["last_locked_at"] is not None else None
                    ),
                    priority=int(row["priority"]),
                    enabled=bool(row["enabled"]),
                    role=str(row["role"]) if "role" in row.keys() else "target",
                    match_mode=(
                        str(row["match_mode"])
                        if "match_mode" in row.keys() else "id"
                    ),
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if target.role not in _VALID_ROLES:
                target.role = "target"
            if target.match_mode not in _VALID_MATCH_MODES:
                target.match_mode = "id"
            if (
                target.medium in _VALID_MEDIA
                and target.kind in _VALID_KINDS
                and isinstance(target.identifier, str)
                and target.identifier
                and isinstance(target.details, dict)
            ):
                loaded.append(target)
        self.targets = loaded

    def save(self) -> None:
        connection = self._connection
        if connection is None:
            raise TargetStoreError("Targets database is unavailable")
        try:
            with self._lock, connection:
                connection.execute("DELETE FROM targets")
                connection.executemany(
                    """
                    INSERT INTO targets (
                        id, alias, medium, kind, identifier, details_json,
                        created_at, updated_at, last_locked_at, priority, enabled,
                        role, match_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            target.id, target.alias, target.medium, target.kind,
                            target.identifier,
                            json.dumps(target.details, ensure_ascii=False),
                            target.created_at, target.updated_at,
                            target.last_locked_at, target.priority,
                            int(target.enabled),
                            target.role, target.match_mode,
                        )
                        for target in self.targets
                    ],
                )
        except sqlite3.Error as exc:
            raise TargetStoreError(f"Could not save targets: {exc}") from exc

    def _migrate_legacy(self, legacy_path: Path | None) -> None:
        if legacy_path is None or not legacy_path.exists():
            return
        try:
            payload = json.loads(legacy_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not migrate targets.json: {exc}")
            return
        legacy_version = payload.get("version") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or legacy_version not in (1, TARGETS_VERSION):
            self.errors.append("Unsupported targets.json version")
            return
        connection = self._connection
        if connection is not None and int(
            connection.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        ) > 0:
            try:
                legacy_path.unlink()
            except OSError as exc:
                self.errors.append(f"Could not remove migrated targets.json: {exc}")
            return
        migrated: list[SavedTarget] = []
        for raw in payload.get("targets", []):
            try:
                target = SavedTarget(**raw)
            except (TypeError, ValueError):
                continue
            if (
                target.medium in _VALID_MEDIA
                and target.kind in _VALID_KINDS
                and target.identifier
                and isinstance(target.details, dict)
            ):
                migrated.append(target)
        self.targets = migrated
        self.save()
        try:
            legacy_path.unlink()
        except OSError as exc:
            self.errors.append(f"Could not remove migrated targets.json: {exc}")

    def find(self, medium: str, kind: str, identifier: str) -> SavedTarget | None:
        normalized = identifier.casefold()
        return next(
            (
                target for target in self.targets
                if target.medium == medium
                and target.kind == kind
                and target.match_mode == "id"
                and target.identifier.casefold() == normalized
            ),
            None,
        )

    def find_by_name(self, medium: str, kind: str, name: str) -> SavedTarget | None:
        normalized = name.strip().casefold()
        if not normalized:
            return None
        return next(
            (
                target for target in self.targets
                if target.medium == medium
                and target.kind == kind
                and target.match_mode == "name"
                and target.identifier.casefold() == normalized
            ),
            None,
        )

    def find_by_probe(self, ssid: str) -> SavedTarget | None:
        normalized = ssid.strip().casefold()
        if not normalized:
            return None
        return next(
            (
                target for target in self.targets
                if target.medium == "wifi"
                and target.kind == "client"
                and target.match_mode == "probe"
                and target.identifier.casefold() == normalized
            ),
            None,
        )

    def get(self, target_id: str | None) -> SavedTarget | None:
        return next(
            (target for target in self.targets if target.id == target_id),
            None,
        )

    def upsert(
        self,
        *,
        alias: str,
        medium: str,
        kind: str,
        identifier: str,
        details: dict[str, Any],
        role: str = "target",
        match_mode: str = "id",
    ) -> SavedTarget:
        alias = alias.strip()
        if not alias:
            raise TargetStoreError("Alias is required")
        if len(alias) > 64:
            raise TargetStoreError("Alias must be 64 characters or fewer")
        if medium not in _VALID_MEDIA or kind not in _VALID_KINDS:
            raise TargetStoreError("Unsupported target type")
        if role not in _VALID_ROLES:
            raise TargetStoreError("Unsupported target role")
        if match_mode not in _VALID_MATCH_MODES:
            raise TargetStoreError("Unsupported match mode")
        if not identifier.strip():
            raise TargetStoreError("Target identifier is required")
        identifier = identifier.strip()
        if match_mode == "id":
            target = self.find(medium, kind, identifier)
        elif match_mode == "name":
            target = self.find_by_name(medium, kind, identifier)
        elif match_mode == "probe":
            if medium != "wifi" or kind != "client":
                raise TargetStoreError("Probe match applies only to Wi-Fi STA entries")
            target = self.find_by_probe(identifier)
        else:
            raise TargetStoreError("Unsupported match mode")
        now = time.time()
        if target is None:
            target = SavedTarget(
                id=str(uuid.uuid4()),
                alias=alias,
                medium=medium,
                kind=kind,
                identifier=identifier,
                details=dict(details),
                created_at=now,
                updated_at=now,
                priority=len(self.targets),
                role=role,
                match_mode=match_mode,
            )
            self.targets.append(target)
        else:
            target.alias = alias
            target.role = role
            target.match_mode = match_mode
            if _fill_empty(target.details, details):
                target.updated_at = now
            else:
                target.updated_at = now
        self.save()
        return target

    def update_missing(self, target: SavedTarget, details: dict[str, Any]) -> bool:
        changed = _fill_empty(target.details, details)
        if changed:
            target.updated_at = time.time()
            self.save()
        return changed

    def mark_locked(self, target: SavedTarget) -> None:
        target.last_locked_at = time.time()
        self.save()

    def delete(self, target_id: str) -> bool:
        before = len(self.targets)
        self.targets = [target for target in self.targets if target.id != target_id]
        if len(self.targets) == before:
            return False
        for priority, target in enumerate(self.targets):
            target.priority = priority
        self.save()
        return True

    def ordered(self, medium: str | None = None) -> list[SavedTarget]:
        targets = (
            self.targets
            if medium is None
            else [target for target in self.targets if target.medium == medium]
        )
        return sorted(targets, key=lambda target: (target.priority, target.created_at))

    def clear_medium(self, medium: str) -> None:
        if medium not in _VALID_MEDIA:
            raise TargetStoreError("Unsupported target medium")
        self.targets = [
            target for target in self.targets if target.medium != medium
        ]
        for priority, target in enumerate(self.targets):
            target.priority = priority
        self.save()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
