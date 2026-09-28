from __future__ import annotations

import threading
from dataclasses import asdict

from wifit3.models import BluetoothDevice, BluetoothInspection
from wifit3.persist.bluetooth_history import BluetoothHistoryStore
from wifit3.persist.config import Config


class BluetoothEventCapture:
    """SQLite recording of advertisements and read-only GATT observations."""

    def __init__(
        self,
        store: BluetoothHistoryStore,
        identifier: str,
        alias: str,
    ) -> None:
        self.store = store
        self.identifier = identifier.casefold()
        self._lock = threading.Lock()
        self._closed = False
        per_part = Config.target_capture_max_mb * 1024 * 1024
        max_bytes = (
            0
            if Config.target_capture_max_parts == 0
            else per_part * Config.target_capture_max_parts
        )
        self.capture_id = store.start_event_capture(
            self.identifier,
            alias,
            max_bytes=max_bytes,
        )
        self.count = 0
        self.dropped = 0

    def record_advertisement(self, device: BluetoothDevice) -> None:
        if device.identifier.casefold() != self.identifier:
            return
        self._write("advertisement", asdict(device))

    def record_inspection(self, inspection: BluetoothInspection) -> None:
        if inspection.device.identifier.casefold() != self.identifier:
            return
        self._write("gatt", asdict(inspection))

    def _write(self, event: str, data: dict) -> None:
        with self._lock:
            if self._closed:
                return
            if not self.store.append_event(self.capture_id, event, data):
                self.dropped += 1
                return
            self.count += 1

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self.store.finish_event_capture(self.capture_id)
            self._closed = True
