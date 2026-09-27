from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict
from pathlib import Path

from wifit3.models import BluetoothDevice, BluetoothInspection
from wifit3.persist.common import safe_ssid
from wifit3.persist.config import Config


class BluetoothEventCapture:
    """Local JSONL record of advertisements and read-only GATT observations."""

    def __init__(self, identifier: str, alias: str) -> None:
        directory = Path(Config.captures_dir) / "bluetooth_targets"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.path = directory / f"target_events_{safe_ssid(alias)}_{stamp}.jsonl"
        self.identifier = identifier.casefold()
        self._stream = self.path.open("a", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._closed = False
        self._max_bytes = Config.target_capture_max_mb * 1024 * 1024
        self._max_parts = Config.target_capture_max_parts
        self.paths = [self.path]
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
        record = {"timestamp": time.time(), "event": event, "data": data}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            if self._closed:
                return
            if (
                self._stream.tell() > 0
                and self._stream.tell() + len(line.encode("utf-8")) > self._max_bytes
                and not self._rotate()
            ):
                self.dropped += 1
                return
            self._stream.write(line)
            self._stream.flush()
            self.count += 1

    def _rotate(self) -> bool:
        if self._max_parts > 0 and len(self.paths) >= self._max_parts:
            return False
        self._stream.close()
        next_path = self.path.with_name(
            f"{self.path.stem}_part{len(self.paths) + 1}.jsonl",
        )
        self._stream = next_path.open("a", encoding="utf-8")
        try:
            os.chmod(next_path, 0o600)
        except OSError:
            pass
        self.paths.append(next_path)
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._stream.close()
            self._closed = True
