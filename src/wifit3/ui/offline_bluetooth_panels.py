"""Split offline BT/BLE rows into main vs secondary tables (live scanner parity)."""
from __future__ import annotations

import re
from typing import Any

_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_UNKNOWN_NAMES = frozenset({
    "",
    "<unknown>",
    "unknown",
    "unnamed",
    "bluetooth device",
    "‹unknown›",
})
_PRIVATE_ADDRESS_TYPES = frozenset({
    "anonymous",
    "non-resolvable-private",
    "resolvable-private",
    "random",
    "random-reserved",
    "platform-opaque",
})


def _meaningful_name(name: str) -> bool:
    return name.strip().casefold() not in _UNKNOWN_NAMES


def _manufacturer_ids(record: dict[str, Any]) -> tuple[int, ...]:
    raw = record.get("manufacturer_ids") or []
    return tuple(int(item) for item in raw)


def is_anonymous_apple_record(record: dict[str, Any]) -> bool:
    return 0x004C in _manufacturer_ids(record) and not _meaningful_name(
        str(record.get("name") or ""),
    )


def _has_gatt_identity(record: dict[str, Any]) -> bool:
    return any(
        str(record.get(field) or "").strip()
        for field in (
            "model_number",
            "manufacturer_name",
            "gatt_device_name",
            "pnp_id",
        )
    )


def _has_catalog_signal(record: dict[str, Any]) -> bool:
    catalog = record.get("catalog")
    if isinstance(catalog, dict):
        if str(catalog.get("class") or "").strip():
            return True
        if catalog.get("labels"):
            return True
        if str(catalog.get("family_id") or "").strip():
            return True
    return False


def _has_advertisement_signal(record: dict[str, Any]) -> bool:
    return bool(
        record.get("service_uuids")
        or record.get("service_data_uuids")
        or _manufacturer_ids(record)
        or record.get("class_of_device") is not None
        or record.get("appearance") is not None
    )


def _is_platform_uuid(identifier: str) -> bool:
    return len(identifier) == 36 and identifier.count("-") == 4


def offline_bluetooth_use_secondary_panel(record: dict[str, Any]) -> bool:
    """True when the row belongs in the lower private / sparse-ID table."""
    if is_anonymous_apple_record(record):
        return True
    address_type = str(record.get("address_type") or "unknown").casefold()
    name = str(record.get("name") or "")
    enriched = (
        _meaningful_name(name)
        or _has_gatt_identity(record)
        or _has_catalog_signal(record)
    )
    if address_type in _PRIVATE_ADDRESS_TYPES and not enriched:
        return True
    identifier = str(record.get("identifier") or "")
    if _is_platform_uuid(identifier) and not enriched:
        return True
    if (
        _MAC_RE.match(identifier)
        and address_type in _PRIVATE_ADDRESS_TYPES
        and not enriched
    ):
        return True
    if not enriched and not _has_advertisement_signal(record):
        return True
    return False
