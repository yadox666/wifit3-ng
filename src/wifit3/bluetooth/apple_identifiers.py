"""Map Apple GATT model strings (e.g. iPhone13,4) to marketing names.

Data is vendored from the community-maintained apple-device-identifiers project
(iOS, iPadOS, watchOS, tvOS, macOS, visionOS JSON files). No network fetch at
runtime.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

_APPLE_IDENTIFIER = re.compile(
    r"^(?:iPhone|iPad|iPod|Watch|AppleTV|AudioAccessory|AirPods|"
    r"Mac|RealityDevice|iBridge|HomePod|iProd)\d",
    re.IGNORECASE,
)

_DATASETS = (
    "ios-device-identifiers.json",
    "watchos-device-identifiers.json",
    "tvos-device-identifiers.json",
    "mac-device-identifiers.json",
    "visionos-device-identifiers.json",
)


@lru_cache(maxsize=1)
def _load_mappings() -> dict[str, str]:
    merged: dict[str, str] = {}
    package = resources.files("wifit3.bluetooth.data")
    for filename in _DATASETS:
        payload = json.loads(package.joinpath(filename).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            if isinstance(key, str) and isinstance(value, str) and value.strip():
                merged[key.strip()] = value.strip()
    return merged


def looks_like_apple_internal_model(model_number: str) -> bool:
    return bool(_APPLE_IDENTIFIER.match(model_number.strip()))


def apple_marketing_name(model_number: str) -> str | None:
    """Return a friendly name for an Apple internal identifier, if known."""
    key = model_number.strip()
    if not key:
        return None
    mappings = _load_mappings()
    return mappings.get(key)


def format_device_model_number(
    model_number: str,
    *,
    detail: bool = False,
) -> str:
    """Format a GATT model string for UI (Apple IDs → marketing names)."""
    raw = model_number.strip()
    if not raw:
        return ""
    friendly = apple_marketing_name(raw)
    if friendly is None:
        return raw
    if detail:
        return f"{friendly} ({raw})"
    return friendly
