"""Map Apple GATT model strings (e.g. iPhone13,4) to marketing names.

Data is vendored from the community-maintained apple-device-identifiers project
(iOS, iPadOS, watchOS, tvOS, macOS, visionOS JSON files). No network fetch at
runtime.
"""
from __future__ import annotations

import json
import re
import struct
from functools import lru_cache
from importlib import resources

_APPLE_IDENTIFIER = re.compile(
    r"^(?:iPhone|iPad|iPod|Watch|AppleTV|AudioAccessory|AirPods|"
    r"Mac|RealityDevice|iBridge|HomePod|iProd)\d",
    re.IGNORECASE,
)
_APPLE_PNP_PRODUCT = re.compile(
    r"Apple(?:, Inc\.)?\s*·\s*product 0x([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_BT_APPLE_VENDOR = 0x004C

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


def format_apple_pnp_label(
    decoded: str,
    *,
    detail: bool = False,
    raw: bytes | None = None,
) -> str | None:
    """Format an Apple PnP ID without guessing an unpublished product model."""
    product: int | None = None
    if raw and len(raw) >= 7:
        source, vendor, product_id, _version = struct.unpack_from("<BHHH", raw)
        if source == 0x01 and vendor == _BT_APPLE_VENDOR:
            product = product_id
    if product is None:
        match = _APPLE_PNP_PRODUCT.search(decoded or "")
        if match:
            product = int(match.group(1), 16)
    if product is None:
        return None
    friendly = f"Apple Bluetooth device (PID 0x{product:04X})"
    if detail and decoded.strip():
        return f"{friendly} ({decoded.strip()})"
    return friendly
