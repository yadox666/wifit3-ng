"""Persistent Classic BR/EDR link-key (bond) store.

Link keys are secrets: this file is written with 0600 permissions and the keys
are NEVER logged. At-rest encryption is expected to be provided by the
deployment (e.g. an encrypted volume in production); this module only persists
the bond so the lab can reconnect to an authorized target without re-pairing.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_dir

from wifit3.persist.private_files import write_private_text

logger = logging.getLogger(__name__)

BLUETOOTH_BONDS_PATH = (
    Path(user_data_dir("wifit3", appauthor=False)) / "bluetooth_bonds.json"
)
_SCHEMA_VERSION = 1
LINK_KEY_LENGTH = 16


@dataclass(frozen=True, slots=True)
class StoredBond:
    identifier: str
    link_key: bytes
    key_type: int | None = None
    name: str | None = None
    created_at: float = 0.0
    updated_at: float = 0.0


class BluetoothBondStore:
    """Read/write a JSON file of Classic link keys keyed by BD_ADDR.

    The store is intentionally tiny and dependency-free. It never logs a link
    key; callers must treat :class:`StoredBond.link_key` as a secret.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else BLUETOOTH_BONDS_PATH

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> dict[str, StoredBond]:
        """Return ``{casefolded_identifier: StoredBond}``; empty on any error."""
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Could not read Bluetooth bond store: %s", exc)
            return {}
        bonds: dict[str, StoredBond] = {}
        for identifier, entry in (raw.get("bonds") or {}).items():
            bond = self._decode(identifier, entry)
            if bond is not None:
                bonds[identifier.casefold()] = bond
        return bonds

    @staticmethod
    def _decode(identifier: str, entry: object) -> StoredBond | None:
        if not isinstance(entry, dict):
            return None
        try:
            link_key = bytes.fromhex(entry["link_key"])
        except (KeyError, TypeError, ValueError):
            return None
        if len(link_key) != LINK_KEY_LENGTH:
            return None
        return StoredBond(
            identifier=identifier,
            link_key=link_key,
            key_type=entry.get("key_type"),
            name=entry.get("name"),
            created_at=float(entry.get("created_at") or 0.0),
            updated_at=float(entry.get("updated_at") or 0.0),
        )

    def get(self, identifier: str) -> StoredBond | None:
        return self.load().get(identifier.casefold())

    def all(self) -> list[StoredBond]:
        return list(self.load().values())

    def save_bond(
        self,
        identifier: str,
        link_key: bytes,
        *,
        key_type: int | None = None,
        name: str | None = None,
    ) -> StoredBond | None:
        """Persist (or refresh) a bond. Returns ``None`` for an invalid key."""
        if len(link_key) != LINK_KEY_LENGTH:
            return None
        folded = identifier.casefold()
        bonds = self.load()
        now = time.time()
        created = bonds[folded].created_at if folded in bonds else now
        bond = StoredBond(
            identifier=identifier,
            link_key=bytes(link_key),
            key_type=key_type,
            name=name,
            created_at=created,
            updated_at=now,
        )
        bonds[folded] = bond
        self._write(bonds)
        return bond

    def forget(self, identifier: str) -> bool:
        folded = identifier.casefold()
        bonds = self.load()
        if folded not in bonds:
            return False
        del bonds[folded]
        self._write(bonds)
        return True

    def _write(self, bonds: dict[str, StoredBond]) -> None:
        payload = {
            "version": _SCHEMA_VERSION,
            "bonds": {
                bond.identifier: {
                    "link_key": bond.link_key.hex(),
                    "key_type": bond.key_type,
                    "name": bond.name,
                    "created_at": bond.created_at,
                    "updated_at": bond.updated_at,
                }
                for bond in bonds.values()
            },
        }
        # write_private_text creates the parent dir and hardens the file to 0600.
        write_private_text(self._path, json.dumps(payload, indent=2) + "\n")
