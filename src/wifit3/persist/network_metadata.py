"""SQLite persistence for passive network metadata."""
from __future__ import annotations

import time

from wifit3.persist.ap_history import ApHistoryStore, ApHistoryStoreError
from wifit3.wlan.network_metadata import NetworkMetadata


SAVE_INTERVAL_SECONDS = 5.0


class NetworkMetadataStoreError(RuntimeError):
    pass


class NetworkMetadataStore:
    def __init__(
        self,
        history: ApHistoryStore,
        bssid: str,
        ssid: str | None,
    ) -> None:
        self.history = history
        self.bssid = bssid.casefold()
        self.ssid = ssid or ""
        self.errors: list[str] = []
        self.metadata = NetworkMetadata(self.bssid, self.ssid)
        self._saved_revision = 0
        self._last_save = 0.0
        self._load()

    @property
    def dirty(self) -> bool:
        return self.metadata.revision != self._saved_revision

    def _load(self) -> None:
        payload = self.history.network_metadata_payload(self.bssid)
        if payload is None:
            return
        metadata = NetworkMetadata.from_dict(
            payload, expected_bssid=self.bssid, ssid=self.ssid,
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
        payload, revision = self.metadata.serialized_snapshot()
        try:
            self.history.save_network_metadata(self.bssid, self.ssid, payload)
        except ApHistoryStoreError as exc:
            raise NetworkMetadataStoreError(
                f"Could not save network metadata: {exc}",
            ) from exc
        self._saved_revision = revision
