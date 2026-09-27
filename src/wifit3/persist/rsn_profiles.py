"""Load bounded WPA/RSN evidence from prior JSON scan exports."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from wifit3.persist.config import Config

_MAX_EXPORTS = 256
_MAX_EXPORT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScanRsnProfile:
    ssid: str
    bssid: str
    channel: int
    rsn_ie: bytes
    akm_suites: tuple[int, ...]
    pmf_capable: bool
    source_file: str


def load_scan_rsn_profiles(ssid: str) -> list[ScanRsnProfile]:
    """Return newest-first exact-SSID RSN profiles from bounded scan history."""
    directory = Path(Config.captures_dir) / "scan_exports"
    try:
        paths = sorted(
            directory.glob("scan_*.json"),
            key=lambda path: path.name,
            reverse=True,
        )[:_MAX_EXPORTS]
    except OSError:
        return []

    profiles: list[ScanRsnProfile] = []
    for path in paths:
        try:
            if path.stat().st_size > _MAX_EXPORT_BYTES:
                continue
            payload = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        access_points = payload.get("access_points", [])
        if not isinstance(access_points, list):
            continue
        for raw in access_points:
            profile = _profile_from_record(raw, ssid, path.name)
            if profile is not None:
                profiles.append(profile)
    return profiles


def _profile_from_record(
    raw: object,
    ssid: str,
    source_file: str,
) -> ScanRsnProfile | None:
    if not isinstance(raw, dict) or raw.get("ssid") != ssid:
        return None
    encoded = raw.get("rsn_ie_hex")
    try:
        rsn_ie = bytes.fromhex(encoded) if isinstance(encoded, str) else b""
        channel = int(raw.get("channel", 0))
        akm_suites = tuple(int(value) for value in raw.get("akm_suites", ()))
    except (TypeError, ValueError):
        return None
    if (
        len(rsn_ie) < 4
        or rsn_ie[0] != 48
        or rsn_ie[1] != len(rsn_ie) - 2
        or channel <= 0
    ):
        return None
    return ScanRsnProfile(
        ssid=ssid,
        bssid=str(raw.get("bssid", "")).casefold(),
        channel=channel,
        rsn_ie=rsn_ie,
        akm_suites=akm_suites,
        pmf_capable=bool(raw.get("pmf_capable", False)),
        source_file=source_file,
    )
