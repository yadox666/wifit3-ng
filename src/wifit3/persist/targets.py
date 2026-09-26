from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir


TARGETS_PATH = Path(user_config_dir("wifit3", appauthor=False)) / "targets.json"
TARGETS_VERSION = 1
_VALID_MEDIA = {"wifi", "bluetooth"}
_VALID_KINDS = {"ap", "client", "device"}


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
    def __init__(self, path: Path = TARGETS_PATH) -> None:
        self.path = path
        self.targets: list[SavedTarget] = []
        self.errors: list[str] = []
        self.load()

    def load(self) -> None:
        try:
            payload = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            self.targets = []
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.targets = []
            self.errors.append(f"Could not load targets: {exc}")
            return
        if not isinstance(payload, dict) or payload.get("version") != TARGETS_VERSION:
            self.targets = []
            self.errors.append("Unsupported targets.json version")
            return
        loaded = []
        raw_targets = payload.get("targets", [])
        if not isinstance(raw_targets, list):
            raw_targets = []
        for raw in raw_targets:
            try:
                target = SavedTarget(**raw)
            except (TypeError, ValueError):
                continue
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        payload = {
            "version": TARGETS_VERSION,
            "targets": [asdict(target) for target in self.targets],
        }
        try:
            temporary.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            temporary.replace(self.path)
        except OSError as exc:
            raise TargetStoreError(f"Could not save targets: {exc}") from exc

    def find(self, medium: str, kind: str, identifier: str) -> SavedTarget | None:
        normalized = identifier.casefold()
        return next(
            (
                target for target in self.targets
                if target.medium == medium
                and target.kind == kind
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
    ) -> SavedTarget:
        alias = alias.strip()
        if not alias:
            raise TargetStoreError("Alias is required")
        if len(alias) > 64:
            raise TargetStoreError("Alias must be 64 characters or fewer")
        if medium not in _VALID_MEDIA or kind not in _VALID_KINDS:
            raise TargetStoreError("Unsupported target type")
        if not identifier.strip():
            raise TargetStoreError("Target identifier is required")
        target = self.find(medium, kind, identifier)
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
            )
            self.targets.append(target)
        else:
            target.alias = alias
            if _fill_empty(target.details, details):
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
