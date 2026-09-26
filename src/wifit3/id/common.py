from __future__ import annotations

from wifit3.models.identity import canonical_vendor
from .oui_db import mapping as oui_mapping
from .vendors import VENDOR_BY_OUI

_PREFIX_LENGTHS = (9, 7, 6)


def hex_mac(mac: str) -> str:
    """Normalize MAC address string by stripping colons/hyphens and uppercasing."""
    return mac.replace(":", "").replace("-", "").upper()


def lookup_oui(mac: str) -> str | None:
    """Return the vendor name for a MAC, or None if unknown."""
    oui = hex_mac(mac)
    live = oui_mapping()
    for n in _PREFIX_LENGTHS:
        key = oui[:n]
        if key in live:
            return live[key]
        hit = VENDOR_BY_OUI.get(key)
        if hit is not None:
            return hit
    return None


def vendor_for_mac(mac: str) -> str | None:
    """Return canonical vendor name for a MAC address, or None if unknown."""
    return canonical_vendor(lookup_oui(mac))
