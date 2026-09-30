"""Target / whitelist row filters for live scanners and offline history."""
from __future__ import annotations

from typing import Any

from wifit3.models import AccessPoint, BluetoothDevice, Client
from wifit3.persist.targets import SavedTarget, TargetStore
from wifit3.targeting import (
    is_target_entry,
    is_whitelisted_entry,
    iter_wifi_client_sightings,
    match_access_point,
    match_bluetooth_device,
    match_client,
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
    return _passes(match_access_point(store, ap), filter_id)


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
    return _passes(match_bluetooth_device(store, device), filter_id)


def offline_record_matches_target_filter(
    store: TargetStore | None,
    kind: str,
    record: dict[str, Any],
    filter_id: str,
) -> bool:
    if not filter_id or store is None:
        return True
    if kind == "aps":
        bssid = str(record.get("bssid", ""))
        matched = store.find("wifi", "ap", bssid) if bssid else None
        ssid = record.get("ssid")
        if matched is None and ssid:
            matched = store.find_by_name("wifi", "ap", str(ssid))
        return _passes(matched, filter_id)
    if kind == "clients":
        mac = str(record.get("client_mac", ""))
        candidates: list[SavedTarget | None] = [store.find("wifi", "client", mac)]
        for ssid in record.get("probed_ssids") or []:
            candidates.append(store.find_by_probe(str(ssid)))
            candidates.append(store.find_by_name("wifi", "ap", str(ssid)))
        for item in record.get("access_points") or []:
            if not isinstance(item, dict):
                continue
            ssid = item.get("ssid")
            if ssid:
                candidates.append(store.find_by_name("wifi", "ap", str(ssid)))
        if filter_id == TARGET_ANY:
            return any(is_target_entry(item) for item in candidates)
        if filter_id == TARGET_ANY_WHITELIST:
            return any(is_whitelisted_entry(item) for item in candidates)
        return any(_passes(item, filter_id) for item in candidates)
    identifier = str(record.get("identifier", ""))
    name = record.get("name")
    matched = store.find("bluetooth", "device", identifier) if identifier else None
    if matched is None and name and name != "<Unknown>":
        matched = store.find_by_name("bluetooth", "device", str(name))
    return _passes(matched, filter_id)
