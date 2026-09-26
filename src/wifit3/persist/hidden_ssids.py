from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from platformdirs import user_config_dir


HIDDEN_SSIDS_PATH = (
    Path(user_config_dir("wifit3", appauthor=False)) / "hidden_ssids.json"
)
HIDDEN_SSIDS_VERSION = 1


class HiddenSsidStoreError(RuntimeError):
    pass


@dataclass
class HiddenSsidRecord:
    bssid: str
    ssid: str
    first_revealed_at: float
    last_revealed_at: float
    reveal_method: str


class HiddenSsidStore:
    def __init__(self, path: Path = HIDDEN_SSIDS_PATH) -> None:
        self.path = path
        self.records: dict[str, HiddenSsidRecord] = {}
        self.errors: list[str] = []
        self.load()

    def load(self) -> None:
        try:
            payload = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not load hidden SSIDs: {exc}")
            return
        if not isinstance(payload, dict) or payload.get("version") != HIDDEN_SSIDS_VERSION:
            self.errors.append("Unsupported hidden_ssids.json version")
            return
        for raw in payload.get("networks", []):
            try:
                record = HiddenSsidRecord(**raw)
            except (TypeError, ValueError):
                continue
            if record.bssid and record.ssid:
                self.records[record.bssid.casefold()] = record

    def lookup(self, bssid: str) -> str | None:
        record = self.records.get(bssid.casefold())
        return record.ssid if record is not None else None

    def remember(self, bssid: str, ssid: str, reveal_method: str) -> None:
        bssid = bssid.casefold().strip()
        ssid = ssid.strip()
        if not bssid or not ssid or ssid == "<hidden>":
            return
        now = time.time()
        record = self.records.get(bssid)
        if record is None:
            record = HiddenSsidRecord(
                bssid=bssid,
                ssid=ssid,
                first_revealed_at=now,
                last_revealed_at=now,
                reveal_method=reveal_method,
            )
            self.records[bssid] = record
        else:
            record.ssid = ssid
            record.last_revealed_at = now
            record.reveal_method = reveal_method
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        payload = {
            "version": HIDDEN_SSIDS_VERSION,
            "networks": [
                asdict(record)
                for record in sorted(
                    self.records.values(), key=lambda item: item.bssid,
                )
            ],
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
            raise HiddenSsidStoreError(
                f"Could not save hidden SSIDs: {exc}",
            ) from exc
