from __future__ import annotations

import json
import platform
import secrets
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from wifit3.models.location import LocationFix


_WORDS = (
    "amber", "anchor", "apricot", "atlas", "bamboo", "beacon", "birch",
    "breeze", "brook", "canyon", "cedar", "cipher", "cobalt", "comet",
    "coral", "cosmos", "crystal", "delta", "ember", "falcon", "fern",
    "fjord", "forest", "fox", "galaxy", "garden", "glacier", "harbor",
    "hazel", "horizon", "indigo", "island", "jade", "juniper", "lagoon",
    "lantern", "lilac", "lotus", "maple", "marble", "meadow", "meteor",
    "mist", "moon", "mosaic", "nebula", "oasis", "ocean", "olive",
    "onyx", "orbit", "otter", "pebble", "pine", "plum", "prairie",
    "quartz", "raven", "reef", "river", "robin", "saffron", "sage",
    "signal", "silver", "sparrow", "spruce", "star", "stone", "summit",
    "sunset", "tide", "timber", "topaz", "valley", "violet", "willow",
    "wind", "winter", "zenith",
)


def _utc_iso(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def location_fix_to_metadata(fix: LocationFix) -> dict[str, Any]:
    return {
        "latitude": fix.latitude,
        "longitude": fix.longitude,
        "altitude_m": fix.altitude_m,
        "accuracy_m": fix.accuracy_m,
        "observed_at": fix.observed_at,
        "observed_at_utc": _utc_iso(fix.observed_at),
        "source": fix.source,
        "satellites": fix.satellites,
        "fix_quality": fix.fix_quality,
    }


def collect_session_metadata(
    *,
    mode: str,
    wifit3_version: str,
    started_at: float,
    gps_fix: LocationFix | None = None,
    gps_port: str = "",
) -> dict[str, Any]:
    """Build a JSON-serializable session metadata blob (no secrets)."""
    meta: dict[str, Any] = {
        "mode": mode,
        "wifit3_version": wifit3_version,
        "python_version": sys.version.split()[0],
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "node": platform.node(),
        },
        "started_at_utc": _utc_iso(started_at),
    }
    if gps_port:
        meta["gps_port"] = gps_port
    if gps_fix is not None:
        meta["gps_start"] = location_fix_to_metadata(gps_fix)
    return meta


def session_end_metadata_patch(
    ended_at: float,
    *,
    gps_fix: LocationFix | None = None,
) -> dict[str, Any]:
    patch: dict[str, Any] = {"ended_at_utc": _utc_iso(ended_at)}
    if gps_fix is not None:
        patch["gps_end"] = location_fix_to_metadata(gps_fix)
    return patch


def merge_session_metadata(
    existing_json: str,
    patch: Mapping[str, Any],
) -> str:
    try:
        base = json.loads(existing_json or "{}")
    except json.JSONDecodeError:
        base = {}
    if not isinstance(base, dict):
        base = {}
    base.update(patch)
    return json.dumps(base, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class ScanSession:
    id: str
    name: str
    started_at: float
    media: frozenset[str]
    mode: str
    description: str = ""
    metadata_json: str = "{}"


def normalize_session_names(existing: Iterable[str]) -> set[str]:
    return {
        str(name).casefold()
        for name in existing
        if str(name).strip()
    }


def persisted_session_names(*stores: object) -> set[str]:
    """Collect session labels already stored in AP / Bluetooth history DBs."""
    names: set[str] = set()
    for store in stores:
        rows = getattr(store, "scan_sessions", None)
        if rows is None:
            continue
        for item in rows():
            if isinstance(item, dict):
                raw = item.get("name")
            else:
                raw = getattr(item, "name", None)
            if raw is not None and str(raw).strip():
                names.add(str(raw))
    return names


def session_name_available(name: str, existing: Iterable[str]) -> bool:
    label = name.strip()
    if not label:
        return False
    return label.casefold() not in normalize_session_names(existing)


def generate_session_name(existing: Iterable[str] = ()) -> str:
    """Return a memorable, non-sensitive two/three-word session label."""
    used = normalize_session_names(existing)
    while True:
        word_count = 2 if secrets.randbelow(4) == 0 else 3
        name = "-".join(secrets.SystemRandom().sample(_WORDS, word_count))
        if name.casefold() not in used:
            return name


def allocate_session_name(
    requested: str | None,
    existing: Iterable[str],
) -> str:
    """Use ``requested`` when free; otherwise draw a new name not in ``existing``."""
    label = (requested or "").strip()
    if label and session_name_available(label, existing):
        return label
    return generate_session_name(existing)


def new_scan_session(
    media: Iterable[str],
    *,
    mode: str,
    existing_names: Iterable[str] = (),
    name: str | None = None,
    description: str = "",
    metadata: Mapping[str, Any] | None = None,
    started_at: float | None = None,
) -> ScanSession:
    normalized = frozenset(str(item).strip().casefold() for item in media if item)
    if not normalized:
        raise ValueError("A scan session requires at least one medium")
    started = time.time() if started_at is None else started_at
    label = allocate_session_name(name, existing_names)
    meta = dict(metadata or {})
    return ScanSession(
        id=str(uuid.uuid4()),
        name=label,
        started_at=started,
        media=normalized,
        mode=mode,
        description=description.strip(),
        metadata_json=json.dumps(meta, separators=(",", ":"), sort_keys=True),
    )
