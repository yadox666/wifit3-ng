"""Private persistence for public Wi-Fi beacon compatibility profiles."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from platformdirs import user_config_dir

from wifit3.dot11.ie import iter_information_elements

WIFI_PROFILES_PATH = (
    Path(user_config_dir("wifit3", appauthor=False)) / "wifi_profiles.json"
)
WIFI_PROFILES_VERSION = 1
_MAX_RECORDS = 2048
_MAX_IES_BYTES = 4096
_SAVE_INTERVAL_S = 30


class WifiProfileStoreError(RuntimeError):
    pass


@dataclass(slots=True)
class WifiProfileRecord:
    bssid: str
    ssid: str
    channel: int
    ies_hex: str
    rsn_ie_hex: str
    akm_suites: list[int]
    pmf_capable: bool
    pmf_required: bool
    first_seen: float
    last_seen: float

    @property
    def ies(self) -> bytes:
        return bytes.fromhex(self.ies_hex)

    @property
    def rsn_ie(self) -> bytes:
        return bytes.fromhex(self.rsn_ie_hex)


class WifiProfileStore:
    def __init__(self, path: Path = WIFI_PROFILES_PATH) -> None:
        self.path = path
        self.records: dict[str, WifiProfileRecord] = {}
        self.errors: list[str] = []
        self._last_save = 0.0
        self._dirty = False
        self.load()

    def load(self) -> None:
        try:
            payload = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Could not load Wi-Fi profiles: {exc}")
            return
        if not isinstance(payload, dict) or payload.get("version") != WIFI_PROFILES_VERSION:
            self.errors.append("Unsupported wifi_profiles.json version")
            return
        for raw in payload.get("profiles", []):
            try:
                record = WifiProfileRecord(**raw)
                record.bssid = record.bssid.casefold()
                record.channel = int(record.channel)
                record.akm_suites = [int(value) for value in record.akm_suites]
                ies = record.ies
                rsn_ie = record.rsn_ie
            except (TypeError, ValueError):
                continue
            if (
                record.bssid
                and record.ssid
                and 0 < record.channel
                and len(ies) <= _MAX_IES_BYTES
                and _valid_rsn(rsn_ie)
            ):
                self.records[record.bssid] = record

    def profiles_for_ssid(self, ssid: str) -> list[WifiProfileRecord]:
        return sorted(
            (record for record in self.records.values() if record.ssid == ssid),
            key=lambda record: record.last_seen,
            reverse=True,
        )

    def remember(
        self,
        *,
        bssid: str,
        ssid: str,
        channel: int,
        beacon: bytes,
        rsn_ie: bytes,
        akm_suites: list[int],
        pmf_capable: bool,
        pmf_required: bool,
        now: float | None = None,
    ) -> None:
        if not ssid or ssid == "<hidden>" or not _valid_rsn(rsn_ie):
            return
        ies = _canonical_ies(beacon)
        if not ies:
            return
        now = time.time() if now is None else now
        bssid = bssid.casefold()
        previous = self.records.get(bssid)
        record = WifiProfileRecord(
            bssid=bssid,
            ssid=ssid,
            channel=int(channel),
            ies_hex=ies.hex(),
            rsn_ie_hex=rsn_ie.hex(),
            akm_suites=sorted({int(value) for value in akm_suites}),
            pmf_capable=bool(pmf_capable),
            pmf_required=bool(pmf_required),
            first_seen=previous.first_seen if previous is not None else now,
            last_seen=now,
        )
        changed = previous is None or _profile_signature(previous) != _profile_signature(record)
        self.records[bssid] = record
        if len(self.records) > _MAX_RECORDS:
            oldest = min(self.records.values(), key=lambda item: item.last_seen)
            self.records.pop(oldest.bssid, None)
        due = now - self._last_save >= _SAVE_INTERVAL_S
        self._dirty = self._dirty or changed or due
        if self._dirty and (changed or due):
            self.save()

    def save(self) -> None:
        if not self._dirty and self.path.exists():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        payload = {
            "version": WIFI_PROFILES_VERSION,
            "profiles": [
                asdict(record)
                for record in sorted(
                    self.records.values(),
                    key=lambda item: item.bssid,
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
            raise WifiProfileStoreError(
                f"Could not save Wi-Fi profiles: {exc}",
            ) from exc
        self._last_save = time.time()
        self._dirty = False


def _canonical_ies(beacon: bytes) -> bytes:
    if len(beacon) < 36:
        return b""
    ies = b"".join(
        raw for _tag_id, _body, raw in iter_information_elements(beacon, start=36)
    )
    return ies[:_MAX_IES_BYTES]


def _valid_rsn(rsn_ie: bytes) -> bool:
    return (
        len(rsn_ie) >= 4
        and rsn_ie[0] == 48
        and rsn_ie[1] == len(rsn_ie) - 2
    )


def _profile_signature(record: WifiProfileRecord) -> tuple:
    return (
        record.ssid,
        record.channel,
        record.ies_hex,
        record.rsn_ie_hex,
        tuple(record.akm_suites),
        record.pmf_capable,
        record.pmf_required,
    )
