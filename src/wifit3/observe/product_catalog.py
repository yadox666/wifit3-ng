"""Product-family labels beside the protocol signature layer.

Protocol type, decode text, and the observe signature pack are left unchanged.
A family match adds labels, a class, notes, an extra-attention line, and an
optional live chip. An empty match does not clear a family already stored.

Clues follow the public Fieldwatch catalog (MIT, Copyright 2026 Off Grid Pete
LLC, https://github.com/OffGridPete/Fieldwatch). Router OUI dumps are not
imported. WPA ``00:50:F2`` and RSN ``00:0F:AC`` are protocol tags, not a brand.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable

from platformdirs import user_data_dir

from wifit3.observe.remote_id import RemoteIdReport, summarize_remote_id
from wifit3.persist.private_files import write_private_text
from wifit3.observe.tracker_state import decode_dult, decode_find_hub


_PROTOCOL_OUIS = frozenset({"0050f2", "000fac"})
_NEAR_OWNER = "Near the owner. Separated is the state that can follow you."
_FIND_HUB_NEARBY = (
    "Co-travel is often your own tag, or someone who joined with their own keys."
)
_REMOTE_EMERGENCY = "Remote ID status is Emergency."


@dataclass(frozen=True, slots=True)
class CatalogFamily:
    """One catalog family for the browser. Matching uses the same JSON rules."""

    id: str
    label: str
    catalog_class: str
    notes: str
    attention: str
    clues: tuple[str, ...]
    user_owned: bool = False


@dataclass(frozen=True, slots=True)
class CatalogRuleForm:
    """One editable clue in the catalog UI."""

    kind: str
    text: str = ""
    company_id: int | None = None
    prefix: str = ""
    radio: str = ""


RULE_KIND_CHOICES: tuple[tuple[str, str], ...] = (
    ("Name contains", "name_contains"),
    ("Name pattern (glob)", "name_glob"),
    ("Name pattern (regex)", "name_regex"),
    ("Manufacturer (OUI or name)", "manufacturer"),
    ("OUI", "oui"),
    ("MAC prefix", "mac_prefix"),
    ("Vendor IE (Wi‑Fi)", "vendor_ie"),
    ("BLE company ID", "manufacturer_id"),
    ("BLE manufacturer data", "manufacturer_data"),
    ("Service UUID", "service_uuid"),
    ("Service data (UUID)", "service_data"),
    ("Service data contains (hex)", "service_data_contains"),
    ("GATT brand contains", "gatt_brand_contains"),
    ("GATT model contains", "gatt_model_contains"),
    ("GATT submodel contains", "gatt_submodel_contains"),
    ("GATT model (regex)", "gatt_model_regex"),
)

RADIO_CHOICES: tuple[tuple[str, str], ...] = (
    ("Any radio", ""),
    ("Wi‑Fi only", "wifi"),
    ("BLE only", "ble"),
)


@dataclass(frozen=True, slots=True)
class CatalogHit:
    """One radio's product-family annotation. Empty means no new match."""

    labels: tuple[str, ...] = ()
    catalog_class: str = ""
    notes: str = ""
    attention: str = ""
    live: str = ""
    live_strong: bool = False
    sentence: str = ""

    @property
    def present(self) -> bool:
        return bool(self.labels or self.live or self.attention)


@dataclass(frozen=True, slots=True)
class _Rule:
    kind: str
    text: str
    company_id: int | None
    prefix: str
    radio: str
    regex_flags: str = ""


@dataclass(frozen=True, slots=True)
class _Family:
    id: str
    label: str
    catalog_class: str
    notes: str
    attention: str
    decode: str
    rules: tuple[_Rule, ...]
    user_owned: bool = False


@dataclass(frozen=True, slots=True)
class _Suppress:
    drop: str
    when_any: frozenset[str]
    unless_name_contains: tuple[str, ...]
    unless_service: frozenset[str]
    when_other_class_not: str


@dataclass(frozen=True, slots=True)
class _Observation:
    radio: str
    name: str
    mac: str
    vendor_ies: frozenset[str]
    manufacturer: dict[int, bytes]
    service_data: dict[str, bytes]
    service_uuids: frozenset[str]
    gatt_brand: str = ""
    gatt_model: str = ""
    gatt_submodel: str = ""


def _observation_bluetooth(
    manufacturer_data: dict[int, bytes] | None,
    service_data: dict[str, bytes] | None,
    service_uuids=(),
    *,
    name: str = "",
    mac: str = "",
    gatt_source: Any = None,
) -> _Observation:
    from wifit3.bluetooth.gatt_metadata import gatt_identity_parts

    parts = gatt_identity_parts(gatt_source) if gatt_source is not None else None
    return _Observation(
        radio="ble",
        name=name,
        mac=mac,
        vendor_ies=frozenset(),
        manufacturer=dict(manufacturer_data or {}),
        service_data=dict(service_data or {}),
        service_uuids=frozenset(service_uuids),
        gatt_brand=parts.brand if parts else "",
        gatt_model=parts.model if parts else "",
        gatt_submodel=parts.submodel if parts else "",
    )


def match_bluetooth(
    manufacturer_data: dict[int, bytes] | None,
    service_data: dict[str, bytes] | None,
    service_uuids=(),
    *,
    name: str = "",
    mac: str = "",
    gatt_source: Any = None,
) -> CatalogHit:
    """Family labels for one BLE advertisement. Protocol hints are not changed."""
    return _match(_observation_bluetooth(
        manufacturer_data,
        service_data,
        service_uuids,
        name=name,
        mac=mac,
        gatt_source=gatt_source,
    ))


def match_wifi(
    ssid: str | None,
    bssid: str,
    vendor_ouis: set[str] | frozenset[str],
) -> CatalogHit:
    """Family labels for one access point. The signature-pack label is separate."""
    return _match(_Observation(
        radio="wifi",
        name=ssid or "",
        mac=bssid,
        vendor_ies=frozenset(vendor_ouis),
        manufacturer={},
        service_data={},
        service_uuids=frozenset(),
    ))


def overlay_remote_id(hit: CatalogHit, report: RemoteIdReport | None) -> CatalogHit:
    """Fill the live chip from a Remote ID decode without changing its summary."""
    if report is None or not report.live:
        return hit
    return replace(
        hit,
        live=report.live,
        live_strong=report.live_strong,
        sentence=report.sentence,
    )


def with_protocol_live(
    hit: CatalogHit,
    protocol_type: str,
    decode_state: str,
) -> CatalogHit:
    """Copy a live chip from an existing decoder when the family did not set one."""
    if hit.live or not protocol_type:
        return hit
    parsed = _protocol_live(protocol_type)
    if parsed is None:
        return hit
    live, strong, sentence = parsed
    if sentence and sentence in decode_state:
        sentence = ""
    return replace(hit, live=live, live_strong=strong, sentence=sentence)


_DISPLAY_DETAIL_FAMILY_IDS = {
    "Television": "ble-tv-bracket",
    "Monitor": "ble-tv-bracket",
    "Projector": "ble-tv-bracket",
}


def supplement_catalog_hit(hit: CatalogHit, device) -> CatalogHit:
    """Fill CLASS/FAMILY from BLE appearance or classification when rules miss."""
    if hit.present or getattr(device, "catalog_family_id", ""):
        return hit
    if getattr(device, "catalog_labels", ()) or getattr(device, "catalog_class", ""):
        return hit
    from wifit3.bluetooth.classification import device_classification

    classification = device_classification(device)
    if classification.category != "Display":
        return CatalogHit()
    family_id = _DISPLAY_DETAIL_FAMILY_IDS.get(classification.detail)
    if family_id is None:
        return CatalogHit()
    if classification.source not in {"Appearance", "Name"} and classification.confidence not in {
        "high",
        "medium",
    }:
        return CatalogHit()
    supplemented = catalog_hit_for_family_id(family_id)
    if not supplemented.present:
        return CatalogHit()
    return supplemented


def catalog_hit_for_family_id(family_id: str) -> CatalogHit:
    """Build a catalog hit from a stock or user family id (manual assignment)."""
    wanted = (family_id or "").strip()
    if not wanted:
        return CatalogHit()
    for family in families():
        if family.id == wanted:
            return CatalogHit(
                labels=(family.label,),
                catalog_class=family.catalog_class,
                notes=family.notes,
                attention=family.attention,
            )
    return CatalogHit()


def apply_catalog_hit(holder, hit: CatalogHit) -> None:
    """Write family display fields onto capabilities or a Bluetooth device."""
    holder.catalog_labels = hit.labels
    holder.catalog_class = hit.catalog_class
    holder.catalog_notes = hit.notes
    holder.catalog_attention = hit.attention
    holder.catalog_live = hit.live
    holder.catalog_live_strong = hit.live_strong
    holder.catalog_sentence = hit.sentence
    if hit.attention and hasattr(holder, "signature_watch"):
        holder.signature_watch = True


def manual_catalog_family_id(source) -> str:
    if source is None:
        return ""
    if isinstance(source, dict):
        caps = source.get("capabilities")
        if isinstance(caps, dict):
            value = caps.get("catalog_family_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
        catalog = source.get("catalog")
        if isinstance(catalog, dict):
            value = catalog.get("family_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
        value = source.get("catalog_family_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
        return ""
    return str(getattr(source, "catalog_family_id", "") or "").strip()


def resolve_catalog_hit(auto: CatalogHit, holder) -> CatalogHit:
    """Prefer a manually pinned family over an automatic rule match."""
    family_id = manual_catalog_family_id(holder)
    if family_id:
        manual = catalog_hit_for_family_id(family_id)
        if manual.present:
            return manual
    return auto


def choose_catalog(hit: CatalogHit, previous, *, name: str = "") -> CatalogHit:
    """Keep a stored family when this advertisement did not match one.

    A stored class that the current name contradicts is dropped. A quiet
    advertisement still does not erase a family the name allows.
    """
    family_id = manual_catalog_family_id(previous)
    if family_id:
        manual = catalog_hit_for_family_id(family_id)
        if manual.present:
            return manual
    if hit.present or previous is None:
        return hit
    if previous.catalog_labels or previous.catalog_live or previous.catalog_attention:
        kept = CatalogHit(
            labels=tuple(previous.catalog_labels),
            catalog_class=previous.catalog_class,
            notes=previous.catalog_notes,
            attention=previous.catalog_attention,
            live=previous.catalog_live,
            live_strong=previous.catalog_live_strong,
            sentence=previous.catalog_sentence,
        )
        context = (name or "").strip() or catalog_name_context(previous)
        if name.strip() and previous is not None:
            hinted = catalog_name_context(previous)
            if hinted and hinted.casefold() not in context.casefold():
                context = f"{context} {hinted}"
        agreed = _name_classes(context, radio=_holder_radio(previous))
        if agreed and kept.catalog_class and kept.catalog_class not in agreed:
            return CatalogHit()
        return kept
    return hit


def device_fields(hit: CatalogHit) -> dict:
    return {
        "catalog_labels": hit.labels,
        "catalog_class": hit.catalog_class,
        "catalog_notes": hit.notes,
        "catalog_attention": hit.attention,
        "catalog_live": hit.live,
        "catalog_live_strong": hit.live_strong,
        "catalog_sentence": hit.sentence,
    }


def apply_capabilities(capabilities, hit: CatalogHit) -> None:
    """Write family fields onto a fresh capability object. Does not clear a label."""
    if not hit.present:
        return
    capabilities.catalog_labels = hit.labels
    capabilities.catalog_class = hit.catalog_class
    capabilities.catalog_notes = hit.notes
    capabilities.catalog_attention = hit.attention
    capabilities.catalog_live = hit.live
    capabilities.catalog_live_strong = hit.live_strong
    capabilities.catalog_sentence = hit.sentence
    if hit.attention:
        capabilities.signature_watch = True


def prepare_device_catalog(
    device,
    *,
    manufacturer_data: dict[int, bytes] | None = None,
    service_data: dict[str, bytes] | None = None,
) -> dict:
    """Recompute or enrich family fields before SQLite persistence.

    Live observations already carry catalog fields; this path covers throttled
    writes, GATT-only updates, and protocol-only decodes when payloads are
    still available from the last advertisement.
    """
    if getattr(device, "catalog_family_id", ""):
        return {}
    from wifit3.bluetooth.gatt_metadata import gatt_identity_parts

    gatt_parts = gatt_identity_parts(device)
    has_gatt = bool(gatt_parts.brand or gatt_parts.model or gatt_parts.submodel)
    fresh = CatalogHit()
    if manufacturer_data or service_data or has_gatt:
        fresh = with_protocol_live(
            match_bluetooth(
                manufacturer_data or {},
                service_data or {},
                getattr(device, "service_uuids", ()) or (),
                name=getattr(device, "name", ""),
                mac=getattr(device, "identifier", ""),
                gatt_source=device,
            ),
            getattr(device, "protocol_type", "") or "",
            getattr(device, "decode_state", "") or "",
        )
    elif getattr(device, "protocol_type", ""):
        fresh = with_protocol_live(
            CatalogHit(),
            device.protocol_type,
            device.decode_state or "",
        )
    chosen = choose_catalog(fresh, device)
    if not chosen.present:
        chosen = supplement_catalog_hit(CatalogHit(), device)
    if not chosen.present:
        return {}
    return device_fields(chosen)


_WIFI_CATALOG_CAPABILITY_KEYS = (
    "catalog_labels",
    "catalog_class",
    "catalog_notes",
    "catalog_attention",
    "catalog_live",
    "catalog_live_strong",
    "catalog_sentence",
)


def catalog_json_from_hit(hit: CatalogHit, *, family_id: str = "") -> str:
    """Normalized ``catalog_json`` / offline catalog dict for one match."""
    pinned = (family_id or "").strip()
    if not hit.present and not pinned:
        return "{}"
    payload = {
        "labels": list(hit.labels),
        "class": hit.catalog_class,
        "notes": hit.notes,
        "attention": hit.attention,
        "live": hit.live,
        "live_strong": hit.live_strong,
        "sentence": hit.sentence,
    }
    if pinned:
        payload["family_id"] = pinned
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def patch_wifi_capabilities_catalog(
    raw: dict[str, Any],
    hit: CatalogHit,
    *,
    family_id: str | None = None,
) -> dict[str, Any]:
    """Replace stored Wi-Fi catalog fields from a fresh family match."""
    updated = dict(raw)
    for key in _WIFI_CATALOG_CAPABILITY_KEYS:
        updated.pop(key, None)
    pinned = family_id if family_id is not None else str(raw.get("catalog_family_id") or "")
    pinned = pinned.strip()
    if pinned:
        updated["catalog_family_id"] = pinned
    else:
        updated.pop("catalog_family_id", None)
    if not hit.present:
        return updated
    updated["catalog_labels"] = list(hit.labels)
    updated["catalog_class"] = hit.catalog_class
    updated["catalog_notes"] = hit.notes
    updated["catalog_attention"] = hit.attention
    updated["catalog_live"] = hit.live
    updated["catalog_live_strong"] = hit.live_strong
    updated["catalog_sentence"] = hit.sentence
    if hit.attention:
        updated["signature_watch"] = True
    return updated


def wifi_catalog_hit(
    ssid: str | None,
    bssid: str,
    vendor_ouis: set[str] | frozenset[str],
    capabilities: dict[str, Any] | None = None,
) -> CatalogHit:
    """Match Wi-Fi catalog rules, respecting a manual ``catalog_family_id``."""
    family_id = ""
    if isinstance(capabilities, dict):
        family_id = str(capabilities.get("catalog_family_id") or "").strip()
    if family_id:
        manual = catalog_hit_for_family_id(family_id)
        if manual.present:
            return manual
    return match_wifi(ssid, bssid, vendor_ouis)


def bluetooth_catalog_hit_from_history(
    *,
    name: str,
    identifier: str,
    protocol: dict[str, Any],
    manufacturer_ids: Iterable[int],
    service_data_uuids: Iterable[str],
    service_uuids: Iterable[str],
    gatt_source: Any = None,
) -> CatalogHit:
    """Re-match one Bluetooth history row from fields kept in SQLite."""
    manufacturer: dict[int, bytes] = {}
    for company_id in manufacturer_ids:
        try:
            manufacturer[int(company_id)] = b""
        except (TypeError, ValueError):
            continue
    service_data = {str(uuid): b"" for uuid in service_data_uuids}
    uuids = tuple(str(uuid) for uuid in service_uuids)
    return with_protocol_live(
        match_bluetooth(
            manufacturer,
            service_data,
            uuids,
            name=name,
            mac=identifier,
            gatt_source=gatt_source,
        ),
        str(protocol.get("type") or ""),
        str(protocol.get("decode_state") or ""),
    )


def catalog_blob(device) -> str:
    """JSON for history. ``{}`` means this observation has nothing new to store."""
    family_id = str(getattr(device, "catalog_family_id", "") or "").strip()
    if not (
        family_id
        or device.catalog_labels
        or device.catalog_live
        or device.catalog_attention
    ):
        return "{}"
    hit = CatalogHit(
        labels=tuple(device.catalog_labels),
        catalog_class=device.catalog_class,
        notes=device.catalog_notes,
        attention=device.catalog_attention,
        live=device.catalog_live,
        live_strong=device.catalog_live_strong,
        sentence=device.catalog_sentence,
    )
    return catalog_json_from_hit(hit, family_id=family_id)


def restore_catalog(device, raw: str) -> bool:
    """Fill empty family fields from stored JSON. Returns whether anything changed."""
    try:
        payload = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    family_id = str(payload.get("family_id") or "").strip()
    if family_id:
        hit = catalog_hit_for_family_id(family_id)
        if not hit.present:
            return False
        device.catalog_family_id = family_id
        apply_catalog_hit(device, hit)
        return True
    if device.catalog_labels or device.catalog_live or device.catalog_attention:
        return False
    labels = payload.get("labels")
    if not isinstance(labels, list) or not labels:
        if not payload.get("live") and not payload.get("attention"):
            return False
        labels = []
    device.catalog_labels = tuple(str(item) for item in labels if isinstance(item, str))
    device.catalog_class = str(payload.get("class") or "")
    device.catalog_notes = str(payload.get("notes") or "")
    device.catalog_attention = str(payload.get("attention") or "")
    device.catalog_live = str(payload.get("live") or "")
    device.catalog_live_strong = bool(payload.get("live_strong"))
    device.catalog_sentence = str(payload.get("sentence") or "")
    return bool(device.catalog_labels or device.catalog_live or device.catalog_attention)


def _matched_families(observed: _Observation) -> tuple[_Family, ...]:
    families, suppressions = _load()
    matched = [
        family for family in families
        if any(_rule_hits(rule, observed) for rule in family.rules)
    ]
    matched = _suppress(matched, suppressions, observed)
    matched = _drop_name_conflict(matched, observed)
    return tuple(matched)


def matched_wifi_family_ids(
    ssid: str | None,
    bssid: str,
    vendor_ouis: set[str] | frozenset[str],
    *,
    catalog_family_id: str = "",
) -> frozenset[str]:
    """Stock-rule family ids for one AP (pinned manual id wins when set)."""
    pinned = (catalog_family_id or "").strip()
    if pinned:
        return frozenset({pinned})
    observed = _Observation(
        radio="wifi",
        name=ssid or "",
        mac=bssid,
        vendor_ies=frozenset(vendor_ouis),
        manufacturer={},
        service_data={},
        service_uuids=frozenset(),
    )
    return frozenset(family.id for family in _matched_families(observed))


def matched_bluetooth_family_ids(
    device,
) -> frozenset[str]:
    """Stock-rule family ids for one Bluetooth observation."""
    pinned = str(getattr(device, "catalog_family_id", "") or "").strip()
    if pinned:
        return frozenset({pinned})
    manufacturer: dict[int, bytes] = {}
    for company_id in getattr(device, "manufacturer_ids", ()) or ():
        try:
            manufacturer[int(company_id)] = b""
        except (TypeError, ValueError):
            continue
    service_data = {
        str(uuid): b""
        for uuid in getattr(device, "service_data_uuids", ()) or ()
    }
    return frozenset(
        family.id
        for family in _matched_families(_observation_bluetooth(
            manufacturer,
            service_data,
            getattr(device, "service_uuids", ()) or (),
            name=getattr(device, "name", "") or "",
            mac=getattr(device, "identifier", "") or "",
            gatt_source=device,
        ))
    )


def _match(observed: _Observation) -> CatalogHit:
    matched = list(_matched_families(observed))
    if not matched:
        return CatalogHit()
    classes = tuple(dict.fromkeys(family.catalog_class for family in matched if family.catalog_class))
    notes = tuple(dict.fromkeys(family.notes for family in matched if family.notes))
    attention = tuple(dict.fromkeys(family.attention for family in matched if family.attention))
    live, strong, sentence = _decode_live(matched, observed)
    return CatalogHit(
        labels=tuple(family.label for family in matched),
        catalog_class=" · ".join(classes),
        notes=" ".join(notes),
        attention=" ".join(attention),
        live=live,
        live_strong=strong,
        sentence=sentence,
    )


def _suppress(matched: list[_Family], rules: tuple[_Suppress, ...], observed: _Observation) -> list[_Family]:
    ids = {family.id for family in matched}
    dropped: set[str] = set()
    name = observed.name.casefold()
    services = set()
    for uuid in (*observed.service_uuids, *observed.service_data):
        services |= _uuid_aliases(uuid)
    for rule in rules:
        if rule.drop not in ids:
            continue
        if rule.when_any and not (rule.when_any & ids):
            continue
        if rule.when_other_class_not:
            other = any(
                family.id != rule.drop and family.catalog_class != rule.when_other_class_not
                for family in matched
            )
            if not other:
                continue
        if rule.when_any or rule.when_other_class_not:
            if any(needle.casefold() in name for needle in rule.unless_name_contains):
                continue
            if rule.unless_service & services:
                continue
            dropped.add(rule.drop)
    if not dropped:
        return matched
    return [family for family in matched if family.id not in dropped]


def _decode_live(matched: list[_Family], observed: _Observation) -> tuple[str, bool, str]:
    live = ""
    strong = False
    sentence = ""
    for family in matched:
        chip = _family_live(family, observed)
        if chip is None:
            continue
        chip_live, chip_strong, chip_sentence = chip
        if not live or (chip_strong and not strong):
            live, strong, sentence = chip_live, chip_strong, chip_sentence
    return live, strong, sentence


def _family_live(family: _Family, observed: _Observation) -> tuple[str, bool, str] | None:
    if family.decode == "dult":
        state = decode_dult(_service_payload(observed, "fcb2") or b"")
    elif family.decode == "find_hub":
        state = decode_find_hub(_service_payload(observed, "feaa") or b"")
    elif family.decode == "remote_id":
        report = summarize_remote_id(_service_payload(observed, "fffa") or b"")
        if report is None or not report.live:
            return None
        return report.live, report.live_strong, report.sentence
    elif family.decode == "fast_pair":
        return _fast_pair_live(observed)
    else:
        return None
    if state is None or not state.live:
        return None
    return state.live, state.live_strong, state.sentence


def _fast_pair_live(observed: _Observation) -> tuple[str, bool, str]:
    payloads = [
        payload for uuid, payload in observed.service_data.items()
        if "fe2c" in _uuid_aliases(uuid)
    ]
    if any(len(payload) == 3 for payload in payloads):
        return "Fast Pair pairing", True, ""
    return (
        "Fast Pair",
        False,
        "A 3-byte model id is pairing mode. A longer account-key frame is common in a crowd.",
    )


def _service_payload(observed: _Observation, uuid16: str) -> bytes | None:
    for uuid, payload in observed.service_data.items():
        if uuid16 in _uuid_aliases(uuid):
            return payload
    return None


def _protocol_live(protocol_type: str) -> tuple[str, bool, str] | None:
    splits = (
        ("DULT tracker · ", {"Separated"}, _NEAR_OWNER, "Near owner"),
        ("Find Hub · ", {"Separated"}, _FIND_HUB_NEARBY, "Nearby"),
        ("Remote ID · ", {"Emergency"}, _REMOTE_EMERGENCY, "Emergency"),
    )
    for prefix, strong_values, quiet_sentence, quiet_live in splits:
        if not protocol_type.startswith(prefix):
            continue
        live = protocol_type[len(prefix):]
        sentence = quiet_sentence if live == quiet_live else ""
        if prefix.startswith("Remote ID") and live == "Emergency":
            sentence = _REMOTE_EMERGENCY
        return live, live in strong_values, sentence
    return None


def _rule_hits(rule: _Rule, observed: _Observation) -> bool:
    if rule.radio and rule.radio != observed.radio:
        return False
    if rule.kind in {"name_contains", "name_glob", "name_regex"}:
        targets = _name_match_targets(observed)
        if not targets:
            return False
        if rule.kind == "name_contains":
            return any(_name_has(name, rule.text) for name in targets)
        if rule.kind == "name_regex":
            compiled = _compiled_name_regex(rule.text, rule.regex_flags)
            if compiled is None:
                return False
            return any(compiled.fullmatch(name) is not None for name in targets)
        return any(
            fnmatch.fnmatch(name.casefold(), rule.text.casefold()) for name in targets
        )
    if rule.kind == "oui":
        return _oui_hits(rule.text, observed, vendor=True, address=True)
    if rule.kind == "vendor_ie":
        return _oui_hits(rule.text, observed, vendor=True, address=False)
    if rule.kind == "mac_prefix":
        return _mac_hex(observed.mac).startswith(_hex_text(rule.text))
    if rule.kind == "manufacturer":
        return _manufacturer_hits(rule.text, observed)
    if rule.kind == "manufacturer_id":
        return rule.company_id in observed.manufacturer
    if rule.kind == "manufacturer_data":
        prefix = _hex_text(rule.prefix)
        if not prefix:
            return False
        for company, payload in observed.manufacturer.items():
            if rule.company_id not in (None, company):
                continue
            if payload.hex().startswith(prefix):
                return True
        return False
    if rule.kind == "service_uuid":
        wanted = _uuid_aliases(rule.text)
        have = set()
        for uuid in (*observed.service_uuids, *observed.service_data):
            have |= _uuid_aliases(uuid)
        return bool(wanted & have)
    if rule.kind == "service_data":
        payload = _service_payload(observed, _hex_text(rule.text))
        if payload is None:
            return False
        prefix = _hex_text(rule.prefix)
        return not prefix or payload.hex().startswith(prefix)
    if rule.kind == "service_data_contains":
        needle = _hex_text(rule.prefix)
        if not needle:
            return False
        reversed_needle = _reversed_hex(needle)
        for payload in observed.service_data.values():
            haystack = payload.hex()
            if needle in haystack or (
                reversed_needle and reversed_needle != needle and reversed_needle in haystack
            ):
                return True
        return False
    if rule.kind == "gatt_brand_contains":
        clue = rule.text.strip()
        return bool(clue) and clue.casefold() in observed.gatt_brand.casefold()
    if rule.kind == "gatt_model_contains":
        clue = rule.text.strip()
        if not clue:
            return False
        lowered = clue.casefold()
        return lowered in observed.gatt_model.casefold() or lowered in observed.gatt_submodel.casefold()
    if rule.kind == "gatt_submodel_contains":
        clue = rule.text.strip()
        return bool(clue) and clue.casefold() in observed.gatt_submodel.casefold()
    if rule.kind == "gatt_model_regex":
        clue = rule.text.strip()
        if not clue:
            return False
        compiled = _compiled_name_regex(clue, rule.regex_flags)
        if compiled is None:
            return False
        for candidate in (observed.gatt_model, observed.gatt_submodel):
            if candidate and compiled.fullmatch(candidate) is not None:
                return True
        return False
    return False


def _manufacturer_hits(text: str, observed: _Observation) -> bool:
    """Wi‑Fi BSSID OUI prefix or IEEE OUI vendor name (not SSID)."""
    if observed.radio != "wifi":
        return False
    clue = text.strip()
    if not clue:
        return False
    if _manufacturer_clue_is_hex(clue):
        wanted = _hex_text(clue)
        if len(wanted) < 6 or wanted[:6] in _PROTOCOL_OUIS:
            return False
        return _mac_hex(observed.mac).startswith(wanted)
    from wifit3.id import vendor_for_mac

    vendor = vendor_for_mac(observed.mac) or ""
    if not vendor:
        return False
    return clue.casefold() in vendor.casefold()


def _manufacturer_clue_is_hex(clue: str) -> bool:
    stripped = clue.strip()
    if not stripped:
        return False
    compact = re.sub(r"[^0-9a-fA-F]", "", stripped)
    if len(compact) < 6:
        return False
    for char in stripped:
        if char in ":-. \t":
            continue
        if char not in "0123456789abcdefABCDEF":
            return False
    return True


def _oui_hits(text: str, observed: _Observation, *, vendor: bool, address: bool) -> bool:
    wanted = _hex_text(text)
    if not wanted or wanted[:6] in _PROTOCOL_OUIS:
        return False
    if address:
        mac = _mac_hex(observed.mac)
        if mac.startswith(wanted):
            return True
        recovered = _universal_wifi_oui(observed)
        if recovered and len(wanted) <= 6 and recovered == wanted[:6]:
            return True
    if vendor and observed.radio == "wifi":
        for item in observed.vendor_ies:
            hex_oui = _hex_text(item)
            if hex_oui[:6] in _PROTOCOL_OUIS:
                continue
            if hex_oui.startswith(wanted):
                return True
    return False


def _universal_wifi_oui(observed: _Observation) -> str:
    """Clear the local bit on a Wi-Fi BSSID so a guest or mesh radio can match."""
    if observed.radio != "wifi":
        return ""
    raw = _mac_bytes(observed.mac)
    if raw is None or len(raw) < 3 or not (raw[0] & 0x02):
        return ""
    return bytes((raw[0] & ~0x02,)).hex() + raw[1:3].hex()


# A name that already says what the radio is. A family whose class disagrees is
# dropped, so a Samsung TV is not filed as a SmartTag.
_NAME_CLASSES = (
    ("Display", ("television", "smart tv", "tv", "projector", "proj", "oled")),
    ("Audio", (
        "soundbar", "speaker", "buds", "earbuds", "earbud", "headphones",
        "headphone", "headset", "homepod", "airpods", "beats",
    )),
    ("Wearable", ("smart watch", "galaxy watch", "apple watch", "watch")),
    ("Wearable", (
        "mi color", "mi band", "smart band", "watch fit", "huawei watch",
        "galaxy watch", "garmin", "fitbit", "amazfit", "polar",
    )),
    ("Phone", (
        "iphone", "smartphone",
        "androidap", "androidshare", "instant hotspot",
        "redmi note", "redmi", "xiaomi", "galaxy", "infinix", "xperia",
        "s23+", "a17 de",
    )),
    ("Computer", ("macbook", "laptop", "notebook", "imac", "mac mini", "ai-thinker")),
    ("Tablet", ("ipad",)),
    ("Finder", ("smarttag", "smart tag", "galaxy smarttag", "airtag", "find my")),
    ("Glasses", ("ray-ban", "rayban", "spectacles", "vuzix", "meta view")),
    ("Vehicle", (
        "tesla", "cybertruck",
        "androidauto", "android auto", "carplay",
        "uconnect", "mbux", "bmw wlan", "ford sync",
        "vw hotspot", "audi mmi", "skoda", "seat hotspot",
        "internet da", "hotspot de", "hyundai", "hyunday", "toyota", "lexus",
        "renault", "mazda", "porsche", "kia", "byd",
        "sph-da", "pioneer", "snm941",
    )),
    # Wi‑Fi SSID hints only - see ``_WIFI_ONLY_NAME_HINT_CLASSES``.
    ("Home router", (
        "digifibra", "movistar", "livebox", "vodafone", "smartbox",
        "jazztel", "pepephone", "masmovil", "yoigo",
        "mifibra", "miwifi", "redwifi", "sagemcom", "lowi", "sercomm",
        "tp-link", "tenda", "iberdrola", "calima", "ohana", "zte",
    )),
    ("Camera", ("70mai", "dashcam", "cvr", "mtdvr")),
    ("Alarm", ("securitas", "verisure")),
    ("Cleaning device", ("roomba", "irobot", "braava", "washer")),
    ("IoT", (
        "lorawan", "lora", "dragino", "rakwireless", "rak72", "sensecap",
        "milesight", "kerlink", "wisgate", "helium", "hc-05", "hc-06",
        "multitech", "tektelic",
    )),
    ("Hospitality", (
        "hotel", "apartment", "apartamento", "restaurante", "restaurant",
        "cafe", "chillout", "hostal", "hostel", "hospedaje", "alojamiento",
        "motel", "resort", "pension", "comedor", "bistro", "burger",
        "habitacion", "habitaciones", "rooms", "glamping",
    )),
    ("Printer", (
        "officejet", "laserjet", "hp-print", "epson",
    )),
    ("Camera", ("osmo",)),
    ("Drone", ("drone",)),
)

_WIFI_SSID_FAMILY_IDS = frozenset({
    "home-router-isp",
})

# Name-based conflict hints that only apply to Wi‑Fi SSIDs, not BLE/BT names.
_WIFI_ONLY_NAME_HINT_CLASSES = frozenset({
    "Home router",
})


def _holder_radio(holder) -> str:
    if holder is None:
        return ""
    if str(getattr(holder, "bssid", "") or "").strip():
        return "wifi"
    if str(getattr(holder, "identifier", "") or "").strip():
        return "ble"
    return ""


def _wifi_scope_rule(family_id: str, rule: _Rule) -> _Rule:
    """Stock ISP router clues are Wi‑Fi SSID rules; never match on BLE/BT."""
    if family_id not in _WIFI_SSID_FAMILY_IDS:
        return rule
    if not rule.kind.startswith("name_"):
        return rule
    if rule.radio == "wifi":
        return rule
    return replace(rule, radio="wifi")


def catalog_name_context(holder: Any) -> str:
    """Advertisement name plus resolved GATT model strings for catalog rules."""
    if holder is None:
        return ""
    manufacturer: dict[int, bytes] = {}
    for company_id in getattr(holder, "manufacturer_ids", ()) or ():
        try:
            manufacturer[int(company_id)] = b""
        except (TypeError, ValueError):
            continue
    observed = _observation_bluetooth(
        manufacturer,
        {
            str(uuid): b""
            for uuid in getattr(holder, "service_data_uuids", ()) or ()
        },
        getattr(holder, "service_uuids", ()) or (),
        name=getattr(holder, "name", "") or "",
        mac=getattr(holder, "identifier", "") or "",
        gatt_source=holder,
    )
    return " ".join(_name_match_targets(observed))


def _name_match_targets(observed: _Observation) -> tuple[str, ...]:
    """BLE/BT names used for catalog name rules (advertisement + GATT identity)."""
    targets: list[str] = []
    primary = _usable_name(observed.name)
    if primary:
        targets.append(primary)
    for value in (observed.gatt_model, observed.gatt_submodel):
        text = value.strip()
        if not text:
            continue
        if any(text.casefold() == existing.casefold() for existing in targets):
            continue
        targets.append(text)
    return tuple(targets)


def _drop_name_conflict(matched: list[_Family], observed: _Observation) -> list[_Family]:
    """Drop a product class the advertised name already contradicts."""
    blob = " ".join(_name_match_targets(observed))
    agreed = _name_classes(blob, radio=observed.radio)
    if not agreed:
        return matched
    return [
        family for family in matched
        if not family.catalog_class or family.catalog_class in agreed
    ]


def _name_classes(name: str, *, radio: str = "") -> frozenset[str]:
    usable = _usable_name(name)
    if not usable:
        return frozenset()
    agreed: set[str] = set()
    for catalog_class, phrases in _NAME_CLASSES:
        if catalog_class in _WIFI_ONLY_NAME_HINT_CLASSES and radio != "wifi":
            continue
        if any(_name_has(usable, phrase) for phrase in phrases):
            agreed.add(catalog_class)
    return frozenset(agreed)


def _name_has(name: str, needle: str) -> bool:
    """True when needle is a whole word, or a word plus a numeric suffix.

    ``Tile`` does not match inside ``reptile``. ``SmartTag`` matches ``SmartTag2``.
    ``tv`` matches a word that is or ends with ``tv``, such as ``HDTV``.
    """
    parts = [part for part in re.split(r"[^a-z0-9]+", name.casefold()) if part]
    wanted = [part for part in re.split(r"[^a-z0-9]+", needle.casefold()) if part]
    if not parts or not wanted:
        return False
    if len(wanted) > 1:
        width = len(wanted)
        return any(parts[index:index + width] == wanted for index in range(len(parts) - width + 1))
    want = wanted[0]
    return any(_token_has(token, want) for token in parts)


def _token_has(token: str, want: str) -> bool:
    if token == want:
        return True
    if len(want) >= 4 and token.startswith(want) and token[len(want):].isdigit():
        return True
    return want == "tv" and len(token) > 2 and token.endswith("tv")


@lru_cache(maxsize=512)
def _compiled_name_regex(pattern: str, flags_text: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, _regex_compile_flags(flags_text))
    except re.error:
        return None


def _regex_compile_flags(flags_text: str) -> int:
    """Regex flags for name_regex clues. Default ignores case (like glob).

    ``s`` = case-sensitive. ``i`` = ignore case (default). ``m`` / ``x`` = re flags.
    """
    letters = flags_text.casefold()
    if "s" in letters:
        value = 0
    else:
        value = re.IGNORECASE
    if "m" in letters:
        value |= re.MULTILINE
    if "x" in letters:
        value |= re.VERBOSE
    return value


# Worked examples shown beside regex clues (catalog browser + editor).
NAME_REGEX_WORKED_EXAMPLES: tuple[dict[str, str], ...] = (
    {
        "pattern": "(?i)^PROJ[0-9A-Za-z_-]{0,28}$",
        "flags": "",
        "sample": "PROJ-ROOM-A",
    },
    {
        "pattern": "^ST-[0-9]{4}[A-Z]{3}$",
        "flags": "s",
        "sample": "ST-1440LDW",
    },
)


def name_regex_syntax_error(pattern: str, flags_text: str = "") -> str | None:
    """Return a compile error message, or None when the pattern is valid."""
    text = pattern.strip()
    if not text:
        return "Pattern is empty"
    try:
        re.compile(text, _regex_compile_flags(flags_text))
    except re.error as exc:
        return str(exc)
    return None


def name_regex_matches_sample(
    pattern: str, flags_text: str, sample: str,
) -> bool:
    """True when ``sample`` is a full name/SSID match for the clue pattern."""
    compiled = _compiled_name_regex(pattern.strip(), flags_text)
    if compiled is None:
        return False
    return compiled.fullmatch(sample) is not None


def name_regex_reference_lines() -> tuple[str, str]:
    """Two human-readable regex examples for UI hints."""
    first, second = NAME_REGEX_WORKED_EXAMPLES
    return (
        (
            f"{first['pattern']} → {first['sample']}"
            + (" (default: ignore case)" if not first["flags"] else "")
        ),
        (
            f"{second['pattern']} flags {second['flags']} → {second['sample']}"
            if second["flags"]
            else f"{second['pattern']} → {second['sample']}"
        ),
    )


def name_regex_try_worked_examples(
    pattern: str, flags_text: str = "",
) -> tuple[bool, bool]:
    """Whether each worked example SSID matches the given pattern."""
    first = NAME_REGEX_WORKED_EXAMPLES[0]
    second = NAME_REGEX_WORKED_EXAMPLES[1]
    return (
        name_regex_matches_sample(pattern, flags_text, first["sample"]),
        name_regex_matches_sample(pattern, flags_text, second["sample"]),
    )


def _usable_name(name: str) -> str:
    text = name.strip()
    if text.casefold() in {"", "<unknown>", "unknown", "unnamed"}:
        return ""
    return text


def _mac_hex(mac: str) -> str:
    return _hex_text(mac)


def _mac_bytes(mac: str) -> bytes | None:
    hex_mac = _hex_text(mac)
    if len(hex_mac) < 6 or len(hex_mac) % 2:
        return None
    try:
        return bytes.fromhex(hex_mac)
    except ValueError:
        return None


def _hex_text(value: str) -> str:
    return "".join(character for character in value.lower() if character in "0123456789abcdef")


def _reversed_hex(value: str) -> str:
    if len(value) < 2 or len(value) % 2:
        return ""
    return "".join(value[index:index + 2] for index in range(len(value) - 2, -1, -2))


def _uuid_aliases(uuid: str) -> set[str]:
    hex_uuid = _hex_text(uuid)
    if not hex_uuid:
        return set()
    aliases = {hex_uuid}
    if len(hex_uuid) == 32 and hex_uuid.endswith("00001000800000805f9b34fb"):
        aliases.add(hex_uuid[4:8])
    elif len(hex_uuid) == 8 and hex_uuid.startswith("0000"):
        aliases.add(hex_uuid[4:])
    return aliases


def user_catalog_path() -> Path:
    """User-editable catalog overrides and custom families."""
    return Path(user_data_dir("wifit3", appauthor=False)) / "product-catalog-user.json"


def reload_catalog() -> None:
    """Drop the in-memory merge of stock and user catalog data."""
    _load.cache_clear()
    _stock_family_ids.cache_clear()


def _empty_user_catalog() -> dict:
    return {"schema": 1, "families": [], "hidden_stock": []}


def _read_user_catalog() -> dict:
    path = user_catalog_path()
    if not path.is_file():
        return _empty_user_catalog()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return _empty_user_catalog()
    if not isinstance(document, dict) or document.get("schema") != 1:
        return _empty_user_catalog()
    families = document.get("families")
    hidden = document.get("hidden_stock")
    if not isinstance(families, list):
        families = []
    if not isinstance(hidden, list):
        hidden = []
    return {"schema": 1, "families": families, "hidden_stock": hidden}


def _write_user_catalog(document: dict) -> None:
    write_private_text(
        user_catalog_path(),
        json.dumps(document, indent=2, sort_keys=True) + "\n",
    )
    reload_catalog()


@lru_cache(maxsize=1)
def _stock_family_ids() -> frozenset[str]:
    families, _suppressions = _load_stock()
    return frozenset(family.id for family in families)


@lru_cache(maxsize=1)
def _load_stock() -> tuple[tuple[_Family, ...], tuple[_Suppress, ...]]:
    try:
        text = files("wifit3.observe").joinpath(
            "stock_product_families.json",
        ).read_text(encoding="utf-8")
        document = json.loads(text)
    except (OSError, json.JSONDecodeError, TypeError):
        return (), ()
    if not isinstance(document, dict) or document.get("schema") != 1:
        return (), ()
    families = []
    for raw in document.get("families") or []:
        family = _parse_family(raw)
        if family is not None and family.rules:
            families.append(family)
    suppressions = []
    for raw in document.get("suppress") or []:
        rule = _parse_suppress(raw)
        if rule is not None:
            suppressions.append(rule)
    return tuple(families), tuple(suppressions)


@lru_cache(maxsize=1)
def _load() -> tuple[tuple[_Family, ...], tuple[_Suppress, ...]]:
    stock_families, suppressions = _load_stock()
    user_doc = _read_user_catalog()
    hidden = frozenset(str(item) for item in user_doc.get("hidden_stock") or [])
    user_families: list[_Family] = []
    for raw in user_doc.get("families") or []:
        family = _parse_family(raw)
        if family is not None and family.rules:
            user_families.append(replace(family, user_owned=True))
    user_ids = {family.id for family in user_families}
    merged = list(user_families)
    for family in stock_families:
        if family.id in user_ids or family.id in hidden:
            continue
        merged.append(family)
    return tuple(merged), suppressions


def _family_by_id(family_id: str) -> _Family | None:
    for family in _load()[0]:
        if family.id == family_id:
            return family
    return None


def family_rule_forms(family_id: str) -> tuple[CatalogRuleForm, ...]:
    family = _family_by_id(family_id)
    if family is None:
        return ()
    return tuple(_rule_to_form(rule) for rule in family.rules)


def catalog_family_record(family_id: str) -> dict | None:
    family = _family_by_id(family_id)
    if family is None:
        return None
    stock = family_id in _stock_family_ids()
    return {
        "id": family.id,
        "label": family.label,
        "class": family.catalog_class,
        "notes": family.notes,
        "attention": family.attention,
        "user_owned": family.user_owned,
        "stock": stock and not family.user_owned,
        "rules": [_rule_to_dict(rule) for rule in family.rules],
    }


def suggest_family_id(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")
    slug = slug[:48] or "family"
    if not _family_by_id(slug):
        return slug
    for index in range(2, 100):
        candidate = f"{slug}-{index}"
        if not _family_by_id(candidate):
            return candidate
    return f"{slug}-new"


def save_catalog_family(record: dict) -> tuple[bool, str]:
    family_id = str(record.get("id") or "").strip()
    label = str(record.get("label") or "").strip()
    if not family_id or not label:
        return False, "Family needs an id and a label"
    rules = []
    for raw in record.get("rules") or []:
        if isinstance(raw, dict):
            rule = _parse_rule(raw)
            if rule is not None:
                rules.append(rule)
    if not rules:
        return False, "Add at least one matching clue"
    payload = {
        "id": family_id,
        "label": label,
        "class": str(record.get("class") or "").strip(),
        "notes": str(record.get("notes") or "").strip(),
        "attention": str(record.get("attention") or "").strip(),
        "rules": [_rule_to_dict(rule) for rule in rules],
    }
    document = _read_user_catalog()
    families = list(document.get("families") or [])
    replaced = False
    for index, existing in enumerate(families):
        if isinstance(existing, dict) and existing.get("id") == family_id:
            families[index] = payload
            replaced = True
            break
    if not replaced:
        families.append(payload)
    document["families"] = families
    _write_user_catalog(document)
    action = "Updated" if replaced else "Added"
    return True, f"{action} catalog family {label}"


def delete_catalog_family(family_id: str) -> tuple[bool, str]:
    document = _read_user_catalog()
    families = list(document.get("families") or [])
    kept = [
        item for item in families
        if not (isinstance(item, dict) and item.get("id") == family_id)
    ]
    if len(kept) < len(families):
        document["families"] = kept
        _write_user_catalog(document)
        return True, "Removed user catalog entry"
    if family_id not in _stock_family_ids():
        return False, "Unknown family"
    hidden = list(document.get("hidden_stock") or [])
    if family_id in hidden:
        return False, "Family already hidden"
    hidden.append(family_id)
    document["hidden_stock"] = hidden
    _write_user_catalog(document)
    return True, "Hidden stock family from catalog and matching"


def build_rule_dict(
    kind: str,
    text: str = "",
    *,
    company_id: str = "",
    prefix: str = "",
    radio: str = "",
) -> dict | None:
    parsed_company = _parse_company_id(company_id) if company_id.strip() else None
    if kind == "manufacturer_id":
        if parsed_company is None:
            return None
        return {"kind": kind, "company_id": parsed_company, "radio": radio or ""}
    if kind == "manufacturer_data":
        if parsed_company is None:
            return None
        payload = {"kind": kind, "company_id": parsed_company, "radio": radio or ""}
        if prefix.strip():
            payload["prefix"] = prefix.strip()
        return payload
    if kind == "service_data":
        if not text.strip():
            return None
        payload = {"kind": kind, "text": text.strip(), "radio": radio or ""}
        if prefix.strip():
            payload["prefix"] = prefix.strip()
        return payload
    if kind == "service_data_contains":
        needle = prefix.strip() or text.strip()
        if not needle:
            return None
        return {"kind": kind, "prefix": needle, "radio": radio or ""}
    if kind == "name_regex":
        pattern = text.strip()
        if not pattern or _compiled_name_regex(pattern, prefix.strip()) is None:
            return None
        payload: dict = {"kind": kind, "text": pattern, "radio": radio or ""}
        if prefix.strip():
            payload["flags"] = prefix.strip()
        return payload
    if kind in {
        "name_contains", "name_glob", "manufacturer", "oui", "mac_prefix",
        "vendor_ie", "service_uuid",
    }:
        if not text.strip():
            return None
        return {"kind": kind, "text": text.strip(), "radio": radio or ""}
    return None


def _parse_company_id(raw: str) -> int | None:
    text = raw.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            value = int(text, 16)
        else:
            value = int(text, 10)
    except ValueError:
        return None
    if 0 <= value <= 0xFFFF:
        return value
    return None


def _rule_to_dict(rule: _Rule) -> dict:
    payload: dict = {"kind": rule.kind}
    if rule.text:
        payload["text"] = rule.text
    if rule.company_id is not None:
        payload["company_id"] = rule.company_id
    if rule.prefix:
        payload["prefix"] = rule.prefix
    if rule.radio:
        payload["radio"] = rule.radio
    if rule.regex_flags:
        payload["flags"] = rule.regex_flags
    return payload


def _rule_to_form(rule: _Rule) -> CatalogRuleForm:
    return CatalogRuleForm(
        kind=rule.kind,
        text=rule.text,
        company_id=rule.company_id,
        prefix=rule.prefix,
        radio=rule.radio,
    )


def _parse_family(raw: object) -> _Family | None:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id")
    label = raw.get("label")
    if not isinstance(identifier, str) or not isinstance(label, str):
        return None
    family_id = identifier.strip()
    rules = tuple(
        _wifi_scope_rule(family_id, rule)
        for item in raw.get("rules") or []
        if (rule := _parse_rule(item)) is not None
    )
    return _Family(
        id=family_id,
        label=label.strip(),
        catalog_class=str(raw.get("class") or "").strip(),
        notes=str(raw.get("notes") or "").strip(),
        attention=str(raw.get("attention") or "").strip(),
        decode=str(raw.get("decode") or "").strip(),
        rules=rules,
    )


def _parse_rule(raw: object) -> _Rule | None:
    if not isinstance(raw, dict):
        return None
    kind = raw.get("kind")
    if not isinstance(kind, str) or not kind:
        return None
    company = raw.get("company_id")
    if company is not None and (not isinstance(company, int) or not 0 <= company <= 0xFFFF):
        return None
    radio = raw.get("radio") or ""
    if radio not in {"", "ble", "wifi"}:
        return None
    regex_flags = str(raw.get("flags") or "")
    text = str(raw.get("text") or "")
    if kind in {"name_regex", "gatt_model_regex"}:
        if not text.strip() or _compiled_name_regex(text.strip(), regex_flags) is None:
            return None
    if kind.startswith("gatt_") and kind not in {
        "gatt_brand_contains",
        "gatt_model_contains",
        "gatt_submodel_contains",
        "gatt_model_regex",
    }:
        return None
    if kind.startswith("gatt_") and kind != "gatt_model_regex" and not text.strip():
        return None
    return _Rule(
        kind=kind,
        text=text,
        company_id=company,
        prefix=str(raw.get("prefix") or ""),
        radio=radio,
        regex_flags=regex_flags,
    )


def _parse_suppress(raw: object) -> _Suppress | None:
    if not isinstance(raw, dict) or not isinstance(raw.get("drop"), str):
        return None
    when_any = raw.get("when_any") or []
    unless_name = raw.get("unless_name_contains") or []
    unless_service = raw.get("unless_service") or []
    other = raw.get("when_other_class_not") or ""
    if not isinstance(when_any, list) or not isinstance(unless_name, list):
        return None
    if not isinstance(unless_service, list) or not isinstance(other, str):
        return None
    return _Suppress(
        drop=raw["drop"],
        when_any=frozenset(str(item) for item in when_any),
        unless_name_contains=tuple(str(item) for item in unless_name),
        unless_service=frozenset(_hex_text(str(item)) for item in unless_service),
        when_other_class_not=other,
    )


def families() -> tuple[CatalogFamily, ...]:
    """Merged stock and user families in catalog order."""
    loaded, _suppressions = _load()
    return tuple(
        CatalogFamily(
            id=family.id,
            label=family.label,
            catalog_class=family.catalog_class,
            notes=family.notes,
            attention=family.attention,
            clues=tuple(_clue_text(rule) for rule in family.rules),
            user_owned=family.user_owned,
        )
        for family in loaded
    )


def family_classes() -> tuple[str, ...]:
    return tuple(sorted({
        family.catalog_class for family in families() if family.catalog_class
    }))


def catalog_family_select_options() -> tuple[tuple[str, str], ...]:
    """``(label, family_id)`` pairs sorted by class then family label."""
    rows = sorted(
        families(),
        key=lambda family: (
            (family.catalog_class or "").casefold(),
            family.label.casefold(),
            family.id,
        ),
    )
    options: list[tuple[str, str]] = [("All families", "")]
    for family in rows:
        cls = family.catalog_class or "·"
        options.append((f"{cls} - {family.label}", family.id))
    return tuple(options)


def matching_families(
    text: str = "",
    catalog_class: str = "",
) -> tuple[CatalogFamily, ...]:
    """Families whose label, class, notes, attention, or clues contain every word."""
    wanted = "" if catalog_class in {"", "all"} else catalog_class
    tokens = text.casefold().split()
    matched = []
    for family in families():
        if wanted and family.catalog_class != wanted:
            continue
        blob = " ".join((
            family.label,
            family.catalog_class,
            family.notes,
            family.attention,
            *family.clues,
        )).casefold()
        if all(token in blob for token in tokens):
            matched.append(family)
    return tuple(matched)


def _clue_text(rule: _Rule) -> str:
    if rule.radio == "wifi":
        radio = " · Wi‑Fi"
    elif rule.radio == "ble":
        radio = " · BLE"
    else:
        radio = f" · {rule.radio.upper()}" if rule.radio else ""
    if rule.kind == "name_contains":
        body = f"name contains {rule.text}"
    elif rule.kind == "name_glob":
        body = f"name matches {rule.text}"
    elif rule.kind == "name_regex":
        flag_note = f" flags {rule.regex_flags}" if rule.regex_flags else ""
        body = f"name regex {rule.text}{flag_note}"
    elif rule.kind == "oui":
        body = f"OUI {rule.text}"
    elif rule.kind == "manufacturer":
        if _manufacturer_clue_is_hex(rule.text.strip()):
            body = f"manufacturer OUI {rule.text}"
        else:
            body = f"manufacturer name {rule.text}"
    elif rule.kind == "mac_prefix":
        body = f"MAC prefix {rule.text}"
    elif rule.kind == "manufacturer_id" and rule.company_id is not None:
        body = f"company 0x{rule.company_id:04X}"
    elif rule.kind == "manufacturer_data" and rule.company_id is not None:
        prefix = f" prefix {rule.prefix}" if rule.prefix else ""
        body = f"manufacturer 0x{rule.company_id:04X}{prefix}"
    elif rule.kind == "service_uuid":
        body = f"service UUID {rule.text}"
    elif rule.kind == "service_data":
        prefix = f" prefix {rule.prefix}" if rule.prefix else ""
        body = f"service data {rule.text}{prefix}"
    elif rule.kind == "service_data_contains":
        body = f"service data contains {rule.text}"
    elif rule.kind == "vendor_ie":
        body = f"vendor IE {rule.text}"
    elif rule.kind == "gatt_brand_contains":
        body = f"GATT brand contains {rule.text}"
    elif rule.kind == "gatt_model_contains":
        body = f"GATT model contains {rule.text}"
    elif rule.kind == "gatt_submodel_contains":
        body = f"GATT submodel contains {rule.text}"
    elif rule.kind == "gatt_model_regex":
        flag_note = f" flags {rule.regex_flags}" if rule.regex_flags else ""
        body = f"GATT model regex {rule.text}{flag_note}"
    else:
        body = " ".join(part for part in (rule.kind, rule.text) if part)
    return f"{body}{radio}"
