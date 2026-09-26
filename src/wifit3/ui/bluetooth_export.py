from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from wifit3.bluetooth.assigned_numbers import manufacturer_label, service_label
from wifit3.bluetooth.classification import device_category
from wifit3.models import BluetoothDevice
from wifit3.persist.config import Config


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _safe_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def export_bluetooth_snapshot(devices: Iterable[BluetoothDevice]) -> Path:
    """Write a timestamped CSV snapshot of observed Bluetooth devices."""
    exported_at = datetime.now(timezone.utc)
    directory = Path(Config.captures_dir) / "scan_exports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"bluetooth_{exported_at.strftime('%Y%m%d_%H%M%S_%f')}.csv"
    fields = [
        "name", "identifier", "manufacturer", "probable_type", "signal_dbm",
        "tx_power_dbm", "advertisements", "latest_interval_ms", "first_seen",
        "last_seen", "manufacturer_data_bytes", "service_data_bytes",
        "advertised_services", "service_uuids", "service_data_uuids",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for device in devices:
            services = [service_label(uuid) for uuid in device.service_uuids]
            row = {
                "name": device.name,
                "identifier": device.identifier,
                "manufacturer": manufacturer_label(
                    device.manufacturer_ids, device.identifier
                ) or "",
                "probable_type": device_category(device),
                "signal_dbm": device.rssi,
                "tx_power_dbm": device.tx_power if device.tx_power is not None else "",
                "advertisements": device.advertisement_count,
                "latest_interval_ms": (
                    round(device.advertisement_interval * 1000)
                    if device.advertisement_interval is not None else ""
                ),
                "first_seen": _iso_time(device.first_seen),
                "last_seen": _iso_time(device.last_seen),
                "manufacturer_data_bytes": device.manufacturer_data_bytes,
                "service_data_bytes": device.service_data_bytes,
                "advertised_services": "; ".join(services),
                "service_uuids": "; ".join(device.service_uuids),
                "service_data_uuids": "; ".join(device.service_data_uuids),
            }
            writer.writerow({key: _safe_cell(value) for key, value in row.items()})
    return path
