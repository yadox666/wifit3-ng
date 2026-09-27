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


@dataclass
class ClientProbeRecord:
    client_mac: str
    ssid: str
    channels: list[int]
    last_channel: int
    first_seen: float
    last_seen: float
    count: int


class HiddenSsidStore:
    def __init__(self, path: Path = HIDDEN_SSIDS_PATH) -> None:
        self.path = path
        self.records: dict[str, HiddenSsidRecord] = {}
        self.client_probes: dict[tuple[str, str], ClientProbeRecord] = {}
        self._last_probe_save: dict[tuple[str, str], float] = {}
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
        for raw in payload.get("client_probes", []):
            try:
                record = ClientProbeRecord(**raw)
                record.client_mac = record.client_mac.casefold()
                record.channels = sorted({int(channel) for channel in record.channels})
                record.last_channel = int(record.last_channel)
                record.count = max(1, int(record.count))
            except (TypeError, ValueError):
                continue
            if record.client_mac and record.ssid:
                key = (record.client_mac, record.ssid)
                self.client_probes[key] = record
                self._last_probe_save[key] = record.last_seen

    def lookup(self, bssid: str) -> str | None:
        record = self.records.get(bssid.casefold())
        return record.ssid if record is not None else None

    def probes_for_client(self, client_mac: str) -> list[ClientProbeRecord]:
        client_mac = client_mac.casefold()
        return [
            record
            for (mac, _ssid), record in self.client_probes.items()
            if mac == client_mac
        ]

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

    def remember_probe(
        self,
        client_mac: str,
        ssid: str,
        channel: int,
        *,
        now: float | None = None,
    ) -> None:
        """Persist a directed probe without inventing a BSSID-to-SSID mapping."""
        client_mac = client_mac.casefold().strip()
        ssid = ssid.strip()
        if not client_mac or not ssid or ssid == "<hidden>":
            return
        now = time.time() if now is None else now
        key = (client_mac, ssid)
        record = self.client_probes.get(key)
        is_new = record is None
        if record is None:
            record = ClientProbeRecord(
                client_mac=client_mac,
                ssid=ssid,
                channels=[int(channel)],
                last_channel=int(channel),
                first_seen=now,
                last_seen=now,
                count=1,
            )
            self.client_probes[key] = record
        else:
            if channel not in record.channels:
                record.channels.append(int(channel))
                record.channels.sort()
            record.last_channel = int(channel)
            record.last_seen = now
            record.count += 1
        if is_new or now - self._last_probe_save.get(key, 0) >= 5:
            self.save()
            self._last_probe_save[key] = now

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
            "client_probes": [
                asdict(record)
                for record in sorted(
                    self.client_probes.values(),
                    key=lambda item: (item.client_mac, item.ssid.casefold()),
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
