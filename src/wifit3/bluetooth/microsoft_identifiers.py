"""Map Microsoft GATT PnP IDs (0x2A50) to friendly product names.

Keys in ``microsoft-pnp-products.json`` use ``bt:VVVV:PPPP`` (Bluetooth SIG
assigned company) or ``usb:VVVV:PPPP`` (USB vendor ID) for PnP source 0x02.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

_USB_MICROSOFT_VENDOR = 0x045E
_BT_MICROSOFT_VENDOR = 0x0006

_PRODUCT_IN_LABEL = re.compile(r"product 0x([0-9A-Fa-f]+)", re.IGNORECASE)


@lru_cache(maxsize=1)
def _load_mappings() -> dict[str, str]:
    payload = json.loads(
        resources.files("wifit3.bluetooth.data")
        .joinpath("microsoft-pnp-products.json")
        .read_text(encoding="utf-8"),
    )
    if not isinstance(payload, dict):
        return {}
    return {
        str(key).casefold(): str(value).strip()
        for key, value in payload.items()
        if isinstance(key, str) and isinstance(value, str) and value.strip()
    }


def _lookup(source: int, vendor: int, product: int) -> str | None:
    if source == 0x01:
        key = f"bt:{vendor:04x}:{product:04x}"
    elif source == 0x02:
        key = f"usb:{vendor:04x}:{product:04x}"
    else:
        return None
    return _load_mappings().get(key.casefold())


def microsoft_pnp_product_name(
    source: int,
    vendor: int,
    product: int,
) -> str | None:
    """Return a friendly label for a decoded PnP tuple when known."""
    name = _lookup(source, vendor, product)
    if name is not None:
        return name
    if source == 0x01 and vendor == _BT_MICROSOFT_VENDOR:
        return "Microsoft Bluetooth device"
    if source == 0x02 and vendor == _USB_MICROSOFT_VENDOR:
        return "Microsoft USB Bluetooth device"
    return None


def format_pnp_label(
    decoded: str,
    *,
    detail: bool = False,
    raw: bytes | None = None,
) -> str:
    """Format a stored or freshly decoded PnP ID line for UI."""
    if raw and len(raw) >= 7:
        import struct

        source, vendor, product, version = struct.unpack_from("<BHHH", raw)
        friendly = microsoft_pnp_product_name(source, vendor, product)
        technical = decoded.strip() if decoded.strip() else (
            f"vendor 0x{vendor:04X} · product 0x{product:04X} · v{version}"
        )
        if friendly:
            if detail:
                return f"{friendly} ({technical})"
            return friendly
        return technical
    stripped = (decoded or "").strip()
    if not stripped:
        return ""
    if "microsoft" not in stripped.casefold():
        return stripped
    match = _PRODUCT_IN_LABEL.search(stripped)
    if not match:
        return stripped
    product = int(match.group(1), 16)
    friendly = _lookup(0x01, _BT_MICROSOFT_VENDOR, product)
    if friendly is None:
        friendly = microsoft_pnp_product_name(0x01, _BT_MICROSOFT_VENDOR, product)
    if friendly is None:
        return stripped
    if detail:
        return f"{friendly} ({stripped})"
    return friendly
