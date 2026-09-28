from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from wifit3.id import vendor_for_mac
from wifit3.dot11.ie import beacon_rsn_ie
from wifit3.models import AccessPoint, Client
from wifit3.persist.config import Config
from wifit3.persist.private_files import (
    ensure_private_directory,
    open_private_text_write,
    write_private_text,
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


def _ap_record(ap: AccessPoint) -> dict:
    rsn_ie = beacon_rsn_ie(ap.last_beacon_frame)
    return {
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
        "first_seen": _iso_time(ap.first_seen),
        "last_seen": _iso_time(ap.last_seen),
        "capabilities": _json_safe(asdict(ap.capabilities)),
        "positions": _positions(ap),
    }


def _client_record(client: Client, access_points: dict[str, AccessPoint]) -> dict:
    ap = access_points.get(client.bssid or "")
    return {
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


def export_scan_snapshot(
    access_points: Iterable[AccessPoint],
    clients: Iterable[Client],
) -> tuple[Path, Path]:
    """Write a timestamped JSON report and a flat CSV summary for the current scan."""
    aps = list(access_points)
    client_list = list(clients)
    ap_by_bssid = {ap.bssid: ap for ap in aps}
    exported_at = datetime.now(timezone.utc)
    report = {
        "exported_at": exported_at.isoformat(),
        "access_points": [_ap_record(ap) for ap in aps],
        "clients": [_client_record(client, ap_by_bssid) for client in client_list],
    }

    directory = Path(Config.captures_dir) / "scan_exports"
    ensure_private_directory(directory)
    stem = f"scan_{exported_at.strftime('%Y%m%d_%H%M%S_%f')}"
    json_path = directory / f"{stem}.json"
    csv_path = directory / f"{stem}.csv"
    write_private_text(json_path, json.dumps(report, indent=2, ensure_ascii=False))

    fields = [
        "type", "name", "address", "manufacturer", "signal_dbm", "channel",
        "security_or_network", "country", "activity", "last_seen",
        "latitude", "longitude", "accuracy_m",
    ]
    with open_private_text_write(csv_path, newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for ap in report["access_points"]:
            writer.writerow({
                "type": "access_point",
                "name": ap["ssid"] or "",
                "address": ap["bssid"],
                "manufacturer": ap["manufacturer"] or "",
                "signal_dbm": ap["signal_dbm"],
                "channel": ap["channel"],
                "security_or_network": ap["encryption"] or "",
                "country": ap["country"] or "",
                "activity": "",
                "last_seen": ap["last_seen"],
                "latitude": ap["positions"][0]["latitude"] if ap["positions"] else "",
                "longitude": ap["positions"][0]["longitude"] if ap["positions"] else "",
                "accuracy_m": ap["positions"][0]["accuracy_m"] if ap["positions"] else "",
            })
        for client in report["clients"]:
            probes = "; ".join(client["probe_requests"])
            writer.writerow({
                "type": "client",
                "name": probes,
                "address": client["mac"],
                "manufacturer": client["manufacturer"] or "",
                "signal_dbm": client["signal_dbm"],
                "channel": "",
                "security_or_network": client["connected_ssid"] or client["connected_bssid"] or "",
                "country": "",
                "activity": client["packets"],
                "last_seen": client["last_seen"],
                "latitude": client["positions"][-1]["latitude"] if client["positions"] else "",
                "longitude": client["positions"][-1]["longitude"] if client["positions"] else "",
                "accuracy_m": client["positions"][-1]["accuracy_m"] if client["positions"] else "",
            })
    return json_path, csv_path
