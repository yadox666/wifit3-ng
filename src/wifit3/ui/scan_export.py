from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from rich.text import Text

from wifit3.crack.handshake import pmkid_crackable
from wifit3.dot11.ie import beacon_rsn_ie
from wifit3.id import vendor_for_mac
from wifit3.models import AccessPoint, Client
from wifit3.persist.config import Config
from wifit3.persist.private_files import (
    ensure_private_directory,
    open_private_text_write,
    write_private_text,
)
from wifit3.ui.catalog_format import catalog_class_cell, catalog_family_cell
from wifit3.ui.encryption_format import format_encryption_markup
from wifit3.ui.location_format import format_position

if TYPE_CHECKING:
    from wifit3.persist.vault import Vault

# Column keys shown in the AP / client scanner tables (order preserved for CSV).
AP_SCAN_TABLE_COLUMNS: tuple[str, ...] = (
    "ssid",
    "captures",
    "channel",
    "signal",
    "country",
    "beacons",
    "last_seen",
    "location",
    "encryption",
    "wps",
    "uptime",
    "bssid",
    "identity",
    "catalog_class",
    "catalog_family",
    "clients",
    "stations",
)
CLIENT_SCAN_TABLE_COLUMNS: tuple[str, ...] = (
    "client",
    "manufacturer",
    "signal",
    "packets",
    "last_seen",
    "location",
    "ssid",
    "probes",
)


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _json_safe(value):
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        values = [_json_safe(item) for item in value]
        return sorted(values) if isinstance(value, set) else values
    return value


def _positions(entity) -> list[dict]:
    return [
        {
            "latitude": position.latitude,
            "longitude": position.longitude,
            "altitude_m": position.altitude_m,
            "accuracy_m": position.accuracy_m,
            "observed_at": _iso_time(position.observed_at),
            "source": position.source,
            "signal_dbm": position.rssi,
        }
        for position in entity.positions
    ]


def _format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _format_ap_uptime(uptime_us: int | None) -> str:
    if uptime_us is None:
        return ""
    seconds = uptime_us // 1_000_000
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}h"
    if hours:
        return f"{hours}h {minutes:02}m"
    if minutes:
        return f"{minutes}m {seconds:02}s"
    return f"{seconds}s"


def _capture_badges(ap: AccessPoint, vault: Vault | None) -> str:
    has_hs = any(hs.is_complete for hs in ap.handshakes.values())
    has_pmk = any(hs.pmkid and pmkid_crackable(hs) for hs in ap.handshakes.values())
    has_psk = False
    has_wep = ap.wep_key is not None
    has_wps = ap.wps_pbc_psk is not None
    if vault is not None:
        has_hs = vault.has_handshake(ap) or has_hs
        has_pmk = vault.has_pmkid(ap) or has_pmk
        has_psk = vault.has_psk(ap)
        has_wep = vault.has_wep_key(ap) or has_wep
        has_wps = vault.has_wps_psk(ap) or has_wps
    silent = Config.is_silenced(ap.bssid)
    badges: list[str] = []
    if silent:
        badges.append("✗S")
    if has_hs:
        badges.append("✓HS")
    if has_pmk:
        badges.append("✓PMK")
    if has_psk:
        badges.append("✓PSK")
    if has_wep:
        badges.append("✓WEP")
    if has_wps:
        badges.append("✓WPS")
    return " ".join(badges)


def _client_counts_and_stations(
    clients: Iterable[Client],
) -> tuple[dict[str, int], dict[str, str]]:
    counts: dict[str, int] = {}
    grouped: dict[str, list[tuple[str, str]]] = {}
    for client in clients:
        if not client.bssid:
            continue
        counts[client.bssid] = counts.get(client.bssid, 0) + 1
        vendor = vendor_for_mac(client.mac)
        if vendor:
            grouped.setdefault(client.bssid, []).append((client.mac, vendor))
    labels = {
        bssid: ", ".join(name for _mac, name in sorted(pairs))
        for bssid, pairs in grouped.items()
    }
    return counts, labels


def _encryption_plain(ap: AccessPoint) -> str:
    return Text.from_markup(
        format_encryption_markup(ap),
        emoji=False,
    ).plain


def _wps_plain(ap: AccessPoint) -> str:
    if ap.wps:
        return "WPS 🔒" if ap.wps_locked else "WPS"
    return ""


def _ap_table_row(
    ap: AccessPoint,
    *,
    now: float,
    client_counts: dict[str, int],
    station_labels: dict[str, str],
    vault: Vault | None,
) -> dict[str, object]:
    age = max(0, int(now - ap.last_seen))
    return {
        "ssid": ap.ssid or "",
        "captures": _capture_badges(ap, vault),
        "channel": ap.channel,
        "signal": ap.signal,
        "country": ap.country_code or "",
        "beacons": ap.beacons,
        "last_seen": _format_age(age),
        "location": format_position(ap.positions),
        "encryption": _encryption_plain(ap),
        "wps": _wps_plain(ap),
        "uptime": _format_ap_uptime(ap.uptime_us),
        "bssid": ap.bssid,
        "identity": ap.identity.summary,
        "catalog_class": catalog_class_cell(ap.capabilities).plain,
        "catalog_family": catalog_family_cell(ap.capabilities).plain,
        "clients": client_counts.get(ap.bssid, 0),
        "stations": station_labels.get(ap.bssid, ""),
    }


def _client_table_row(
    client: Client,
    ap: AccessPoint | None,
    *,
    now: float,
) -> dict[str, object]:
    age = max(0, int(now - client.last_seen))
    return {
        "client": client.mac,
        "manufacturer": vendor_for_mac(client.mac) or "",
        "signal": client.signal,
        "packets": client.packets,
        "last_seen": _format_age(age),
        "location": format_position(client.positions),
        "ssid": ap.ssid if ap and ap.ssid else "",
        "probes": ", ".join(sorted(client.probed_ssids)),
    }


def _ap_record(
    ap: AccessPoint,
    *,
    table: dict[str, object],
) -> dict:
    rsn_ie = beacon_rsn_ie(ap.last_beacon_frame)
    record = {
        "ssid": ap.ssid,
        "bssid": ap.bssid,
        "is_own_fake": ap.is_own_fake,
        "own_fake_active": ap.own_fake_active,
        "manufacturer": vendor_for_mac(ap.bssid),
        "signal_dbm": ap.signal,
        "channel": ap.channel,
        "encryption": ap.encryption,
        "rsn_ie_hex": rsn_ie.hex() if rsn_ie is not None else None,
        "akms": list(ap.akms),
        "akm_suites": list(ap.akm_suites),
        "pairwise_cipher": ap.pairwise_cipher,
        "pmf_capable": ap.pmf_capable,
        "pmf_required": ap.pmf_required,
        "wps": ap.wps,
        "wps_locked": ap.wps_locked,
        "country": ap.country_code,
        "remote_id": ap.capabilities.remote_id,
        "signature": ap.capabilities.signature_label,
        "catalog": list(ap.capabilities.catalog_labels),
        "catalog_class": ap.capabilities.catalog_class,
        "catalog_live": ap.capabilities.catalog_live,
        "catalog_attention": ap.capabilities.catalog_attention,
        "first_seen": _iso_time(ap.first_seen),
        "last_seen": _iso_time(ap.last_seen),
        "capabilities": _json_safe(asdict(ap.capabilities)),
        "positions": _positions(ap),
    }
    record.update(table)
    return record


def _client_record(
    client: Client,
    access_points: dict[str, AccessPoint],
    *,
    table: dict[str, object],
) -> dict:
    ap = access_points.get(client.bssid or "")
    record = {
        "mac": client.mac,
        "manufacturer": vendor_for_mac(client.mac),
        "signal_dbm": client.signal,
        "packets": client.packets,
        "connected_bssid": client.bssid,
        "connected_ssid": ap.ssid if ap else None,
        "probe_requests": sorted(client.probed_ssids),
        "probe_observations": {
            ssid: {
                "channel": observation.channel,
                "first_seen": _iso_time(observation.first_seen),
                "last_seen": _iso_time(observation.last_seen),
                "count": observation.count,
                "historical": observation.historical,
            }
            for ssid, observation in sorted(client.probe_observations.items())
        },
        "last_seen": _iso_time(client.last_seen),
        "capabilities": _json_safe(asdict(client.capabilities)),
        "positions": _positions(client),
    }
    record.update(table)
    return record


def export_scan_snapshot(
    access_points: Iterable[AccessPoint],
    clients: Iterable[Client],
    *,
    vault: Vault | None = None,
) -> tuple[Path, Path]:
    """Write a timestamped JSON report and a flat CSV summary for the current scan."""
    aps = list(access_points)
    client_list = list(clients)
    ap_by_bssid = {ap.bssid: ap for ap in aps}
    exported_at = datetime.now(timezone.utc)
    now = time.time()
    client_counts, station_labels = _client_counts_and_stations(client_list)
    ap_records = []
    for ap in aps:
        table = _ap_table_row(
            ap,
            now=now,
            client_counts=client_counts,
            station_labels=station_labels,
            vault=vault,
        )
        ap_records.append(_ap_record(ap, table=table))
    client_records = []
    for client in client_list:
        table = _client_table_row(
            client,
            ap_by_bssid.get(client.bssid or ""),
            now=now,
        )
        client_records.append(
            _client_record(client, ap_by_bssid, table=table),
        )
    report = {
        "exported_at": exported_at.isoformat(),
        "access_points": ap_records,
        "clients": client_records,
    }

    directory = Path(Config.captures_dir) / "scan_exports"
    ensure_private_directory(directory)
    stem = f"scan_{exported_at.strftime('%Y%m%d_%H%M%S_%f')}"
    json_path = directory / f"{stem}.json"
    csv_path = directory / f"{stem}.csv"
    write_private_text(json_path, json.dumps(report, indent=2, ensure_ascii=False))

    csv_fields = ["type", *AP_SCAN_TABLE_COLUMNS, *CLIENT_SCAN_TABLE_COLUMNS]
    with open_private_text_write(csv_path, newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for ap in ap_records:
            row = {"type": "access_point"}
            row.update({key: ap.get(key, "") for key in AP_SCAN_TABLE_COLUMNS})
            writer.writerow(row)
        for client in client_records:
            row = {"type": "client"}
            row.update({key: client.get(key, "") for key in CLIENT_SCAN_TABLE_COLUMNS})
            writer.writerow(row)
    return json_path, csv_path
