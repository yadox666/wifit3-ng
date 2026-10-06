"""Target / whitelist row filters for live scanners and offline history."""
from __future__ import annotations

from typing import Any

from wifit3.models import AccessPoint, BluetoothDevice, Client
from wifit3.persist.targets import SavedTarget, TargetStore
from wifit3.observe.product_catalog import matched_wifi_family_ids
from wifit3.targeting import (
    is_target_entry,
    is_whitelisted_entry,
    iter_wifi_client_sightings,
    match_access_point,
    match_bluetooth_device,
    match_client,
    target_matches_bluetooth_device,
    target_matches_wifi_ap,
)

TARGET_ANY = "__targets__"
TARGET_ANY_WHITELIST = "__whitelist__"


def build_target_select_options(store: TargetStore | None) -> list[tuple[str, str]]:
    options: list[tuple[str, str]] = [
        ("Any device", ""),
        ("⌖ Any target", TARGET_ANY),
        ("◇ Any whitelist", TARGET_ANY_WHITELIST),
    ]
    if store is None:
        return options
    for target in store.ordered():
        if not target.enabled:
            continue
        prefix = "◇" if target.role == "whitelist" else "⌖"
        label = f"{prefix} {target.alias}"
        if target.match_mode == "name":
            label = f"{label} · name"
        elif target.match_mode == "probe":
            label = f"{label} · probe"
        options.append((label, target.id))
    return options


def refresh_target_select(select, store: TargetStore | None) -> None:
    options = build_target_select_options(store)
    current = str(select.value or "")
    select.set_options(options)
    if any(value == current for _label, value in options):
        select.value = current
    else:
        select.value = ""


def _passes(matched: SavedTarget | None, filter_id: str) -> bool:
    if not filter_id:
        return True
    if filter_id == TARGET_ANY:
        return is_target_entry(matched)
    if filter_id == TARGET_ANY_WHITELIST:
        return is_whitelisted_entry(matched)
    return matched is not None and matched.enabled and matched.id == filter_id


def ap_matches_target_filter(
    store: TargetStore | None,
    ap: AccessPoint,
    filter_id: str,
) -> bool:
    if not filter_id or store is None:
        return True
    if filter_id in (TARGET_ANY, TARGET_ANY_WHITELIST):
        return _passes(match_access_point(store, ap), filter_id)
    target = store.get(filter_id)
    if target is None:
        return False
    if not target_matches_wifi_ap(target, ap):
        return False
    return _passes(target, filter_id)


def client_matches_target_filter(
    store: TargetStore | None,
    client: Client,
    filter_id: str,
) -> bool:
    if not filter_id or store is None:
        return True
    if filter_id == TARGET_ANY:
        return any(
            is_target_entry(target)
            for target, _where in iter_wifi_client_sightings(store, client)
        )
    if filter_id == TARGET_ANY_WHITELIST:
        return any(
            is_whitelisted_entry(target)
            for target, _where in iter_wifi_client_sightings(store, client)
        )
    matched = match_client(store, client)
    if _passes(matched, filter_id):
        return True
    return any(
        target.id == filter_id
        for target, _where in iter_wifi_client_sightings(store, client)
    )


def bluetooth_matches_target_filter(
    store: TargetStore | None,
    device: BluetoothDevice,
    filter_id: str,
) -> bool:
    if not filter_id or store is None:
        return True
    if filter_id in (TARGET_ANY, TARGET_ANY_WHITELIST):
        return _passes(match_bluetooth_device(store, device), filter_id)
    target = store.get(filter_id)
    if target is None:
        return False
    if not target_matches_bluetooth_device(target, device):
        return False
    return _passes(target, filter_id)


def _offline_record_candidates(
    store: TargetStore,
    kind: str,
    record: dict[str, Any],
) -> list[SavedTarget]:
    if kind == "aps":
        bssid = str(record.get("bssid", ""))
        candidates: list[SavedTarget | None] = []
        if bssid:
            candidates.append(store.find("wifi", "ap", bssid))
        ssid = record.get("ssid")
        if ssid:
            candidates.append(store.find_by_name("wifi", "ap", str(ssid)))
        caps = record.get("capabilities")
        caps_dict = caps if isinstance(caps, dict) else {}
        vendor_ouis = {
            str(item) for item in (caps_dict.get("vendor_ouis") or []) if item
        }
        family_id = str(caps_dict.get("catalog_family_id") or "").strip()
        for fid in matched_wifi_family_ids(
            str(ssid or ""),
            bssid,
            vendor_ouis,
            catalog_family_id=family_id,
        ):
            candidates.append(store.find("catalog", "family", fid))
        seen: set[str] = set()
        out: list[SavedTarget] = []
        for item in candidates:
            if item is not None and item.enabled and item.id not in seen:
                seen.add(item.id)
                out.append(item)
        return out
    if kind == "clients":
        mac = str(record.get("client_mac", ""))
        candidates: list[SavedTarget | None] = []
        if mac:
            candidates.append(store.find("wifi", "client", mac))
        for ssid in record.get("probed_ssids") or []:
            candidates.append(store.find_by_probe(str(ssid)))
            candidates.append(store.find_by_name("wifi", "ap", str(ssid)))
        for item in record.get("access_points") or []:
            if not isinstance(item, dict):
                continue
            ssid = item.get("ssid")
            if ssid:
                candidates.append(store.find_by_name("wifi", "ap", str(ssid)))
        return [
            item for item in candidates
            if item is not None and item.enabled
        ]
    identifier = str(record.get("identifier", ""))
    name = record.get("name")
    matched = store.find("bluetooth", "device", identifier) if identifier else None
    if matched is None and name and name != "<Unknown>":
        matched = store.find_by_name("bluetooth", "device", str(name))
    return [matched] if matched is not None and matched.enabled else []


def match_offline_record(
    store: TargetStore | None,
    kind: str,
    record: dict[str, Any],
) -> SavedTarget | None:
    """Saved target or whitelist group for an offline history row, if any."""
    if store is None:
        return None
    candidates = _offline_record_candidates(store, kind, record)
    for target in candidates:
        if is_target_entry(target):
            return target
    for target in candidates:
        if is_whitelisted_entry(target):
            return target
    return None


def offline_record_matches_target_filter(
    store: TargetStore | None,
    kind: str,
    record: dict[str, Any],
    filter_id: str,
) -> bool:
    if not filter_id or store is None:
        return True
    if kind == "aps":
        candidates = _offline_record_candidates(store, kind, record)
        if not candidates:
            if filter_id in (TARGET_ANY, TARGET_ANY_WHITELIST):
                return False
            return _passes(None, filter_id)
        return any(_passes(item, filter_id) for item in candidates)
    if kind == "clients":
        candidates = _offline_record_candidates(store, kind, record)
        if filter_id == TARGET_ANY:
            return any(is_target_entry(item) for item in candidates)
        if filter_id == TARGET_ANY_WHITELIST:
            return any(is_whitelisted_entry(item) for item in candidates)
        return any(_passes(item, filter_id) for item in candidates)
    candidates = _offline_record_candidates(store, kind, record)
    if not candidates:
        if filter_id in (TARGET_ANY, TARGET_ANY_WHITELIST):
            return False
        return _passes(None, filter_id)
    return any(_passes(item, filter_id) for item in candidates)
