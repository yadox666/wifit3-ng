"""Split offline Wi-Fi client rows into main vs private-MAC tables."""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from wifit3.id.common import (
    is_locally_administered_mac,
    is_manufacturer_mac,
    vendor_for_mac,
)
from wifit3.ui.fingerprint_format import offline_wifi_meaningful_fingerprint_keys
from wifit3.ui.offline_client_probes import offline_client_probed_ssids


def wifi_client_fingerprint_keys(record: dict[str, Any]) -> frozenset[str]:
    return offline_wifi_meaningful_fingerprint_keys(record)


def client_has_association_or_probes(record: dict[str, Any]) -> bool:
    if int(record.get("access_point_count") or 0) > 0:
        return True
    access_points = record.get("access_points")
    if isinstance(access_points, list) and access_points:
        return True
    return bool(offline_client_probed_ssids(record))


def public_wifi_client_fingerprint_keys(
    records: Iterable[dict[str, Any]],
) -> frozenset[str]:
    keys: set[str] = set()
    for record in records:
        if not client_has_association_or_probes(record):
            continue
        mac = str(record.get("client_mac") or "")
        if is_locally_administered_mac(mac):
            continue
        if not vendor_for_mac(mac):
            continue
        keys.update(wifi_client_fingerprint_keys(record))
    return frozenset(keys)


def shared_wifi_client_fingerprint_keys(
    records: Iterable[dict[str, Any]],
) -> frozenset[str]:
    counts: Counter[str] = Counter()
    for record in records:
        if not client_has_association_or_probes(record):
            continue
        for key in wifi_client_fingerprint_keys(record):
            counts[key] += 1
    return frozenset(key for key, count in counts.items() if count >= 2)


def offline_wifi_client_stays_in_main_panel(
    record: dict[str, Any],
    public_fingerprint_keys: frozenset[str],
    shared_fingerprint_keys: frozenset[str],
) -> bool:
    if not client_has_association_or_probes(record):
        return False
    mac = str(record.get("client_mac") or "")
    if is_manufacturer_mac(mac):
        return True
    client_keys = wifi_client_fingerprint_keys(record)
    if not client_keys:
        return False
    return bool(
        (client_keys & public_fingerprint_keys)
        or (client_keys & shared_fingerprint_keys)
    )


def offline_wifi_client_use_secondary_panel(
    record: dict[str, Any],
    public_fingerprint_keys: frozenset[str],
    shared_fingerprint_keys: frozenset[str],
) -> bool:
    return not offline_wifi_client_stays_in_main_panel(
        record,
        public_fingerprint_keys,
        shared_fingerprint_keys,
    )


def partition_offline_wifi_clients(
    filtered: list[dict[str, Any]],
    *,
    all_records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    public_keys = public_wifi_client_fingerprint_keys(all_records)
    shared_keys = shared_wifi_client_fingerprint_keys(all_records)
    main: list[dict[str, Any]] = []
    secondary: list[dict[str, Any]] = []
    for record in filtered:
        if offline_wifi_client_use_secondary_panel(record, public_keys, shared_keys):
            secondary.append(record)
        else:
            main.append(record)
    return main, secondary
