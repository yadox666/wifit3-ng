"""Crash-safe persistence for passive network metadata beside capture artifacts."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from wifit3.persist.common import bssid_to_dashed, safe_ssid
from wifit3.wlan.network_metadata import NetworkMetadata


SAVE_INTERVAL_SECONDS = 5.0


class NetworkMetadataStoreError(RuntimeError):
    pass


def network_metadata_path(directory: Path, ssid: str | None, bssid: str) -> Path:
    return directory / (
        f"{safe_ssid(ssid)}_{bssid_to_dashed(bssid)}_network.json"
    )


def _existing_path(directory: Path, ssid: str | None, bssid: str) -> Path:
    expected = network_metadata_path(directory, ssid, bssid)
    if expected.exists():
        return expected
    matches = list(directory.glob(f"*_{bssid_to_dashed(bssid)}_network.json"))
    if not matches:
        return expected
    try:
        return max(matches, key=lambda path: path.stat().st_mtime)
    except OSError:
        return matches[0]


class NetworkMetadataStore:
    def __init__(self, directory: Path, bssid: str, ssid: str | None) -> None:
        self.directory = directory
        self.path = _existing_path(directory, ssid, bssid)
        self.errors: list[str] = []
        self.metadata = NetworkMetadata(bssid.casefold(), ssid or "")
        self._saved_revision = 0
        self._last_save = 0.0
        self._load(bssid, ssid or "")

    @property
    def dirty(self) -> bool:
        return self.metadata.revision != self._saved_revision

    def _load(self, bssid: str, ssid: str) -> None:
        try:
            payload = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not load network metadata: {exc}")
            return
        metadata = NetworkMetadata.from_dict(
            payload, expected_bssid=bssid, ssid=ssid,
        )
        if metadata is None:
            self.errors.append("Unsupported or invalid network metadata")
            return
        self.metadata = metadata
        self._saved_revision = metadata.revision

    def flush_if_due(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if not self.dirty or now - self._last_save < SAVE_INTERVAL_SECONDS:
            return False
        self.save()
        self._last_save = now
        return True

    def save(self) -> None:
        if not self.dirty:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        payload, revision = self.metadata.serialized_snapshot()
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
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise NetworkMetadataStoreError(
                f"Could not save network metadata: {exc}",
            ) from exc
        self._saved_revision = revision
