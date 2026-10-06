"""Read-only decoding for standardized GATT descriptor metadata."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from bluetooth_numbers import company


_PRESENTATION_FORMATS = {
    0x01: "boolean",
    0x02: "2-bit value",
    0x04: "uint8",
    0x06: "uint16",
    0x08: "uint32",
    0x0A: "uint64",
    0x0C: "sint8",
    0x0E: "sint16",
    0x10: "sint32",
    0x12: "sint64",
    0x14: "float32",
    0x15: "float64",
    0x16: "SFLOAT",
    0x17: "FLOAT",
    0x18: "duint16",
    0x19: "UTF-8 string",
    0x1A: "UTF-16 string",
    0x1B: "opaque structure",
}

# Standardized identity reads during passive enrichment (vendor-neutral).
ENRICHMENT_IDENTITY_BY_SERVICE: dict[str, frozenset[str]] = {
    "180a": frozenset({
        "2a24", "2a25", "2a26", "2a27", "2a28", "2a29", "2a50",
    }),
    "1800": frozenset({"2a00"}),
}

ENRICHMENT_CHARACTERISTIC_UUIDS = frozenset(
    uuid for uuids in ENRICHMENT_IDENTITY_BY_SERVICE.values() for uuid in uuids
)

# Persisted on ``devices`` and merged across observations / offline reload.
GATT_IDENTITY_STORAGE_FIELDS: tuple[str, ...] = (
    "model_number",
    "serial_number",
    "firmware_revision",
    "hardware_revision",
    "software_revision",
    "manufacturer_name",
    "gatt_device_name",
    "pnp_id",
)

# Maps GATT short UUID → ``BluetoothDevice`` field for text/binary identity chars.
_IDENTITY_TEXT_FIELDS = {
    "2a00": "gatt_device_name",
    "2a24": "model_number",
    "2a25": "serial_number",
    "2a26": "firmware_revision",
    "2a27": "hardware_revision",
    "2a28": "software_revision",
    "2a29": "manufacturer_name",
}

_PNP_ID_SOURCE = {
    0x01: "Bluetooth SIG",
    0x02: "USB",
}


def decode_pnp_id(value: bytes, *, detail: bool = False) -> str:
    """Decode PnP ID (0x2A50) into a compact vendor/product label."""
    if len(value) < 7:
        return ""
    from wifit3.bluetooth.microsoft_identifiers import (
        format_pnp_label,
        microsoft_pnp_product_name,
    )

    source, vendor, product, version = struct.unpack_from("<BHHH", value)
    source_label = _PNP_ID_SOURCE.get(source, f"source {source}")
    if source == 0x01:
        vendor_label = company.get(vendor, f"company 0x{vendor:04X}")
        technical = f"{vendor_label} · product 0x{product:04X} · v{version}"
    elif source == 0x02:
        vendor_label = company.get(vendor, f"USB vendor 0x{vendor:04X}")
        technical = f"{vendor_label} · USB product 0x{product:04X} · v{version}"
    else:
        technical = (
            f"{source_label} vendor 0x{vendor:04X} · "
            f"product 0x{product:04X} · v{version}"
        )
    friendly = microsoft_pnp_product_name(source, vendor, product)
    if friendly:
        if detail:
            return f"{friendly} ({technical})"
        return friendly
    return format_pnp_label(technical, detail=detail, raw=value) or technical


def device_information_fields(inspection) -> dict[str, str]:
    """Extract standardized GATT identity fields from a live inspection."""
    return gatt_identity_fields(inspection)


def gatt_identity_fields(inspection) -> dict[str, str]:
    """Map readable GAP/DIS characteristics onto ``BluetoothDevice`` fields."""
    found: dict[str, str] = {}
    for service in getattr(inspection, "services", ()) or ():
        service_short = compact_uuid(service.uuid)
        allowed = ENRICHMENT_IDENTITY_BY_SERVICE.get(service_short)
        if allowed is None:
            continue
        for characteristic in getattr(service, "characteristics", ()) or ():
            short = compact_uuid(characteristic.uuid)
            if short not in allowed:
                continue
            if getattr(characteristic, "read_error", None):
                continue
            if short == "2a50":
                raw = _characteristic_raw_bytes(characteristic)
                decoded = decode_pnp_id(raw)
                if decoded:
                    found["pnp_id"] = decoded
                continue
            field = _IDENTITY_TEXT_FIELDS.get(short)
            if field is None:
                continue
            value = (characteristic.value or "").strip()
            if value:
                found[field] = value
    return found


@dataclass(frozen=True, slots=True)
class GattIdentityParts:
    brand: str
    model: str
    submodel: str


def _field(source: Any, name: str) -> str:
    if source is None:
        return ""
    if isinstance(source, dict):
        value = source.get(name)
    else:
        value = getattr(source, name, "")
    return str(value or "").strip()


def merge_gatt_identity_fields(device: Any, *sources: Any) -> Any:
    """Fill empty GATT identity attributes from prior observations or cache."""
    from dataclasses import replace

    updates: dict[str, str] = {}
    for source in sources:
        if source is None:
            continue
        for field in GATT_IDENTITY_STORAGE_FIELDS:
            if updates.get(field):
                continue
            incoming = _field(source, field)
            if incoming and not _field(device, field):
                updates[field] = incoming
    if not updates:
        return device
    return replace(device, **updates)


def gatt_identity_parts(source: Any) -> GattIdentityParts:
    """Brand / model / submodel from standardized GATT identity reads."""
    brand = _field(source, "manufacturer_name")
    if not brand:
        pnp = _field(source, "pnp_id")
        if pnp and " · " in pnp:
            brand = pnp.split(" · ", 1)[0].strip()
    if not brand:
        brand = _field(source, "hardware_vendor")

    raw_model = _field(source, "model_number")
    hardware_product = _field(source, "hardware_product")
    gatt_name = _field(source, "gatt_device_name")
    if gatt_name.casefold() in {"", "<unknown>", "unknown", "unnamed", "bluetooth device"}:
        gatt_name = ""

    model = ""
    submodel = ""
    if raw_model:
        from wifit3.bluetooth.apple_identifiers import format_device_model_number

        friendly = format_device_model_number(raw_model)
        if friendly and friendly != raw_model:
            model = friendly
            submodel = raw_model
        else:
            model = raw_model
            if hardware_product and hardware_product.casefold() != raw_model.casefold():
                submodel = hardware_product
    elif gatt_name:
        model = gatt_name
        submodel = hardware_product
    elif hardware_product:
        model = hardware_product
    elif _field(source, "pnp_id"):
        pnp_id = _field(source, "pnp_id")
        from wifit3.bluetooth.apple_identifiers import format_apple_pnp_label

        model = format_apple_pnp_label(pnp_id) or pnp_id

    return GattIdentityParts(brand=brand, model=model, submodel=submodel)


def format_gatt_identity_line(parts: GattIdentityParts) -> str:
    return " · ".join(
        piece for piece in (parts.brand, parts.model, parts.submodel) if piece
    )


def gatt_identity_search_text(source: Any) -> str:
    parts = gatt_identity_parts(source)
    return " ".join(filter(None, (parts.brand, parts.model, parts.submodel)))


def display_model_label(device, *, include_identifier: bool = False) -> str:
    """Best-effort MODEL column text from cached GATT identity (all vendors)."""
    from wifit3.bluetooth.apple_identifiers import format_device_model_number

    if getattr(device, "model_number", ""):
        return format_device_model_number(
            device.model_number, detail=include_identifier,
        )
    gatt_name = (getattr(device, "gatt_device_name", "") or "").strip()
    if gatt_name and gatt_name.casefold() not in {
        "<unknown>", "unknown", "unnamed", "bluetooth device",
    }:
        return gatt_name
    if getattr(device, "pnp_id", ""):
        from wifit3.bluetooth.apple_identifiers import format_apple_pnp_label
        from wifit3.bluetooth.microsoft_identifiers import format_pnp_label

        apple_label = format_apple_pnp_label(
            device.pnp_id,
            detail=include_identifier,
        )
        if apple_label:
            return apple_label
        label = format_pnp_label(
            device.pnp_id,
            detail=include_identifier,
        )
        if label:
            return label
        return device.pnp_id
    return getattr(device, "hardware_product", "") or ""


def _characteristic_raw_bytes(characteristic) -> bytes:
    value_hex = getattr(characteristic, "value_hex", "") or ""
    if value_hex:
        try:
            return bytes.fromhex(value_hex.replace(" ", ""))
        except ValueError:
            pass
    return b""


def compact_uuid(uuid_value: str) -> str:
    lowered = str(uuid_value).lower()
    suffix = "-0000-1000-8000-00805f9b34fb"
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return lowered


def decode_descriptor_value(uuid_value: str, value: bytes) -> str:
    """Decode standardized metadata while preserving numeric on-wire fields."""
    short = compact_uuid(uuid_value)
    if short == "2900" and len(value) >= 2:
        flags = int.from_bytes(value[:2], "little")
        enabled = []
        if flags & 0x0001:
            enabled.append("reliable write")
        if flags & 0x0002:
            enabled.append("writable auxiliaries")
        return f"0x{flags:04x} ({', '.join(enabled) or 'no extended flags'})"
    if short == "2901":
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    if short == "2902" and len(value) >= 2:
        flags = int.from_bytes(value[:2], "little")
        enabled = []
        if flags & 0x0001:
            enabled.append("notifications enabled")
        if flags & 0x0002:
            enabled.append("indications enabled")
        return f"0x{flags:04x} ({', '.join(enabled) or 'updates disabled'})"
    if short == "2904" and len(value) >= 7:
        format_code, exponent, unit, namespace, description = struct.unpack_from(
            "<BbHBH",
            value,
        )
        format_name = _PRESENTATION_FORMATS.get(
            format_code,
            f"unknown format 0x{format_code:02x}",
        )
        return (
            f"{format_name}; exponent {exponent}; unit 0x{unit:04x}; "
            f"namespace 0x{namespace:02x}; description 0x{description:04x}"
        )
    return value.hex(" ")
