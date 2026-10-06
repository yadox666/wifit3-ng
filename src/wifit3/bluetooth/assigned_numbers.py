from __future__ import annotations

from collections.abc import Iterable, Mapping
from uuid import UUID

from bluetooth_numbers import characteristic, company, descriptor, oui, service
from bluetooth_numbers.exceptions import UnknownUUIDError

from wifit3.bluetooth.assigned_number_updates import (
    BROWSE_GROUP_UUIDS,
    CHARACTERISTIC_UPDATES,
    CHARACTERISTIC_UUIDS,
    DECLARATION_UUIDS,
    DESCRIPTOR_UUIDS,
    MESH_PROFILE_UUIDS,
    NORDIC_CHARACTERISTIC_UUIDS,
    NORDIC_DESCRIPTOR_UUIDS,
    NORDIC_SERVICE_UUIDS,
    NORDIC_UUID_SOURCES,
    OBJECT_TYPE_UUIDS,
    PROTOCOL_UUIDS,
    REVIEWED_CHARACTERISTIC_UUIDS,
    REVIEWED_DESCRIPTOR_UUIDS,
    REVIEWED_SERVICE_UUIDS,
    REVIEWED_UUID_SOURCES,
    SDO_UUIDS,
    SERVICE_CLASS_UUIDS,
    SERVICE_NAME_OVERRIDES,
    SERVICE_UPDATES,
    SERVICE_UUIDS,
    UNIT_UUIDS,
)
from wifit3.bluetooth.member_uuids import MEMBER_UUID_OWNERS
from wifit3.bluetooth.signatures import SERVICE_CLASSIFICATIONS


def manufacturer_label(company_ids: tuple[int, ...], identifier: str) -> str:
    """Company names from advertisement IDs, falling back to a public-address OUI."""
    labels = [
        f"{company.get(company_id, f'0x{company_id:04X}')} ({company_id:04X})"
        for company_id in company_ids
    ]
    if labels:
        return ", ".join(labels)
    prefix = identifier.upper()[:8]
    return oui.get(prefix, "")


def known_company_label(company_ids: tuple[int, ...]) -> str:
    """Known company names only, without numeric identifier suffixes."""
    return ", ".join(
        name
        for company_id in company_ids
        if (name := company.get(company_id))
    )


def service_label(service_uuid: str) -> str:
    """Assigned service name with its compact UUID, or just the UUID when unknown."""
    key = _service_key(service_uuid)
    compact = _compact_uuid(service_uuid)
    name = (
        SERVICE_NAME_OVERRIDES.get(compact)
        or _service_name(key)
        or _updated_name(service_uuid, SERVICE_UPDATES)
        or _classic_service_name(compact)
        or MEMBER_UUID_OWNERS.get(compact)
    )
    return f"{name} ({compact})" if name else compact


def service_name(service_uuid: str) -> str:
    """Short assigned service name, the registered owner of a member UUID, or a custom label."""
    compact = _compact_uuid(service_uuid)
    name = (
        SERVICE_NAME_OVERRIDES.get(compact)
        or _service_name(_service_key(service_uuid))
        or _updated_name(service_uuid, SERVICE_UPDATES)
        or _classic_service_name(compact)
    )
    if name:
        return name
    owner = MEMBER_UUID_OWNERS.get(compact)
    if owner:
        return f"{owner} ({compact})"
    short = compact if len(compact) <= 8 else compact[:8] + "…"
    return f"Custom ({short})"


def characteristic_name(characteristic_uuid: str) -> str:
    """Assigned characteristic name, or a compact custom UUID."""
    key = _service_key(characteristic_uuid)
    try:
        name = characteristic[key] if key is not None else None
    except UnknownUUIDError:
        name = None
    if name:
        return name
    updated_name = _updated_name(characteristic_uuid, CHARACTERISTIC_UPDATES)
    if updated_name:
        return updated_name
    compact = _compact_uuid(characteristic_uuid)
    short = compact if len(compact) <= 8 else compact[:8] + "…"
    return f"Custom ({short})"


def descriptor_name(descriptor_uuid: str) -> str:
    """Bluetooth SIG descriptor name, or a compact custom UUID."""
    compact = _compact_uuid(descriptor_uuid)
    assigned = DESCRIPTOR_UUIDS.get(compact)
    if not assigned:
        assigned = NORDIC_DESCRIPTOR_UUIDS.get(compact)
    if not assigned:
        assigned = REVIEWED_DESCRIPTOR_UUIDS.get(compact)
    if assigned:
        return assigned
    key = _service_key(descriptor_uuid)
    try:
        name = descriptor[key] if key is not None else None
    except UnknownUUIDError:
        name = None
    if name:
        return name
    short = compact if len(compact) <= 8 else compact[:8] + "…"
    return f"Custom ({short})"


_SIG_ASSIGNED_UUID_TABLES: tuple[Mapping[str, str], ...] = (
    SERVICE_UUIDS,
    SERVICE_CLASS_UUIDS,
    CHARACTERISTIC_UUIDS,
    DESCRIPTOR_UUIDS,
    DECLARATION_UUIDS,
    UNIT_UUIDS,
    PROTOCOL_UUIDS,
    BROWSE_GROUP_UUIDS,
    MESH_PROFILE_UUIDS,
    OBJECT_TYPE_UUIDS,
    SDO_UUIDS,
)
_ASSIGNED_UUID_TABLES = _SIG_ASSIGNED_UUID_TABLES + (
    NORDIC_SERVICE_UUIDS,
    NORDIC_CHARACTERISTIC_UUIDS,
    NORDIC_DESCRIPTOR_UUIDS,
    REVIEWED_SERVICE_UUIDS,
    REVIEWED_CHARACTERISTIC_UUIDS,
    REVIEWED_DESCRIPTOR_UUIDS,
)


def assigned_uuid_name(uuid_value: str) -> str | None:
    """Resolve a SIG, Nordic-catalogued, or member-owned UUID."""
    compact = _compact_uuid(uuid_value)
    for table in _ASSIGNED_UUID_TABLES:
        name = table.get(compact)
        if name:
            return name
    return MEMBER_UUID_OWNERS.get(compact)


def service_uuid_owner(service_uuid: str) -> str | None:
    """Company owning a member UUID, unless it is a standard assigned service."""
    compact = _compact_uuid(service_uuid)
    if (
        compact in SERVICE_UUIDS
        or compact in SERVICE_CLASS_UUIDS
        or compact in SERVICE_NAME_OVERRIDES
    ):
        return None
    return MEMBER_UUID_OWNERS.get(compact)


_PROPERTY_DETAILS = {
    "broadcast": "May broadcast the value through server configuration.",
    "read": "Permits an ATT Read Request; security policy may still reject it.",
    "write-without-response": "Permits an unacknowledged ATT Write Command.",
    "write": "Permits an acknowledged ATT Write Request.",
    "notify": "Server may send unacknowledged value updates through CCCD.",
    "indicate": "Server may send acknowledged value updates through CCCD.",
    "authenticated-signed-writes": "Permits signed writes without an encrypted link.",
    "extended-properties": "Additional behavior is defined by descriptor 0x2900.",
}


def characteristic_property_detail(property_name: str) -> str:
    """Official GATT meaning of an advertised characteristic property."""
    return _PROPERTY_DETAILS.get(
        property_name,
        "Unknown or platform-specific advertised property.",
    )


def uuid_metadata_source(uuid_value: str, *, kind: str) -> str:
    """Provenance for a resolved UUID label."""
    compact = _compact_uuid(uuid_value)
    if any(compact in table for table in _SIG_ASSIGNED_UUID_TABLES):
        return "Bluetooth SIG Assigned Numbers"
    if compact in NORDIC_UUID_SOURCES:
        source = NORDIC_UUID_SOURCES[compact]
        return f"Nordic Bluetooth Numbers Database ({source})"
    if compact in REVIEWED_UUID_SOURCES:
        return f"Reviewed vendor UUID ({REVIEWED_UUID_SOURCES[compact]})"
    updates = SERVICE_UPDATES if kind == "service" else CHARACTERISTIC_UPDATES
    if compact in updates:
        return "Bundled vendor UUID registry"
    if compact in MEMBER_UUID_OWNERS:
        return "Bluetooth SIG member UUID registry"
    if len(compact) == 4:
        return "Bluetooth SIG Assigned Numbers"
    return "Vendor-specific UUID; public semantics unavailable"


_INFERRED_SERVICE_CHARACTERISTICS = {
    "Apple Notification Center Service": frozenset(
        {
            "9fbf120d-6301-42d9-8c58-25e699a21dbd",
            "69d1d8f3-45e1-49a8-9821-9bbdfdaad9d9",
            "22eac6e9-24d6-4bb5-be44-b36ace7c7bfb",
        }
    ),
    "Apple Media Service": frozenset(
        {
            "9b3c81d8-57b1-4a8a-b8df-0e56f7ca51c2",
            "2f7cabce-808d-411f-9a0c-bb92ba96c102",
            "c6b2f38c-23ab-46d8-a6ab-a3a870bbd5d7",
        }
    ),
    "Fast Pair Service": frozenset(
        {
            f"fe2c123{suffix}-8366-4814-8eb0-01de32100bea"
            for suffix in "3456789"
        }
    ),
}


def resolved_service_name(service_uuid: str, characteristic_uuids: Iterable[str]) -> str:
    """Return the direct service name or infer a vendor service from its characteristics."""
    direct_name = service_name(service_uuid)
    if not direct_name.startswith("Custom ("):
        return direct_name

    observed_uuids = {_canonical_uuid(uuid) for uuid in characteristic_uuids}
    for inferred_name, known_uuids in _INFERRED_SERVICE_CHARACTERISTICS.items():
        if observed_uuids & known_uuids:
            return f"{inferred_name} (inferred)"
    return direct_name


def _classic_service_name(compact_uuid: str) -> str | None:
    """Friendly Classic SDP name, falling back to the complete SIG table."""
    entry = SERVICE_CLASSIFICATIONS.get(compact_uuid.casefold())
    if entry is not None:
        return str(entry[1])
    name = SERVICE_CLASS_UUIDS.get(compact_uuid.casefold())
    if name == "PnPInformation":
        return "PnP Information"
    return name


def _service_name(key: UUID | int | None) -> str | None:
    if key is None:
        return None
    try:
        return service[key]
    except UnknownUUIDError:
        return None


def _updated_name(uuid: str, updates: Mapping[str, str]) -> str | None:
    return updates.get(_compact_uuid(uuid))


def _service_key(service_uuid: str) -> UUID | int | None:
    try:
        return int(service_uuid, 16) if len(service_uuid) == 4 else UUID(service_uuid)
    except (ValueError, AttributeError):
        return None


def _compact_uuid(service_uuid: str) -> str:
    suffix = "-0000-1000-8000-00805f9b34fb"
    lowered = service_uuid.lower()
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return lowered


def _canonical_uuid(uuid: str) -> str:
    compact = _compact_uuid(uuid)
    if len(compact) == 4:
        return f"0000{compact}-0000-1000-8000-00805f9b34fb"
    return compact

