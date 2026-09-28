from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from wifit3.bluetooth.assigned_numbers import manufacturer_label, service_label
from wifit3.bluetooth.classification import device_classification
from wifit3.models import BluetoothDevice
from wifit3.persist.config import Config
from wifit3.persist.private_files import (
    ensure_private_directory,
    open_private_text_write,
    write_private_text,
)


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _safe_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _record(device: BluetoothDevice) -> dict:
    all_services = sorted(set(device.service_uuids) | set(device.service_data_uuids))
    classification = device_classification(device)
    return {
        "name": device.name,
        "identifier": device.identifier,
        "radio": device.radio_label,
        "discovery_source": device.discovery_source,
        "address_type": device.address_type,
        "baseline_status": device.baseline_status,
        "profile_changed": device.profile_changed,
        "manufacturer": manufacturer_label(
            device.manufacturer_ids, device.identifier
        ) or "",
        "probable_type": classification.category,
        "exact_type": classification.detail,
        "classification_source": classification.source,
        "classification_confidence": classification.confidence,
        "classification_ambiguous": classification.ambiguous,
        "protocol_category": device.protocol_category,
        "protocol_type": device.protocol_type,
        "protocol_source": device.protocol_source,
        "protocol_confidence": device.protocol_confidence,
        "bluez_modalias": device.modalias,
        "hardware_vendor": device.hardware_vendor,
        "hardware_product": device.hardware_product,
        "hardware_identity_source": device.hardware_source,
        "signal_dbm": device.rssi,
        "signal_average_dbm": device.rssi_average,
        "signal_min_dbm": device.rssi_min,
        "signal_max_dbm": device.rssi_max,
        "signal_samples": device.rssi_samples,
        "signal_trend": device.rssi_trend,
        "class_of_device": (
            f"0x{device.class_of_device:06x}"
            if device.class_of_device is not None else ""
        ),
        "appearance": (
            f"0x{device.appearance:04x}" if device.appearance is not None else ""
        ),
        "tx_power_dbm": device.tx_power,
        "advertisements": device.advertisement_count,
        "latest_interval_ms": (
            round(device.advertisement_interval * 1000)
            if device.advertisement_interval is not None else None
        ),
        "first_seen": _iso_time(device.first_seen),
        "last_seen": _iso_time(device.last_seen),
        "manufacturer_data_bytes": device.manufacturer_data_bytes,
        "service_data_bytes": device.service_data_bytes,
        "payload_fingerprint": device.payload_fingerprint,
        "profile_fingerprint": device.profile_fingerprint,
        "advertised_services": list(dict.fromkeys(
            service_label(uuid) for uuid in all_services
        )),
        "service_uuids": list(device.service_uuids),
        "service_data_uuids": list(device.service_data_uuids),
    }


def _csv_record(record: dict) -> dict:
    converted = dict(record)
    for key in ("advertised_services", "service_uuids", "service_data_uuids"):
        converted[key] = "; ".join(record[key])
    for key, value in converted.items():
        if value is None:
            converted[key] = ""
    return {key: _safe_cell(value) for key, value in converted.items()}


def export_bluetooth_snapshot(devices: Iterable[BluetoothDevice]) -> Path:
    """Write a private timestamped CSV snapshot of observed Bluetooth devices."""
    exported_at = datetime.now(timezone.utc)
    directory = Path(Config.captures_dir) / "scan_exports"
    ensure_private_directory(directory)
    path = directory / f"bluetooth_{exported_at.strftime('%Y%m%d_%H%M%S_%f')}.csv"
    records = [_record(device) for device in devices]
    fields = list(records[0]) if records else list(_record_fields())
    with open_private_text_write(path, newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(_csv_record(record) for record in records)
    return path


def export_bluetooth_bundle(
    devices: Iterable[BluetoothDevice],
) -> tuple[Path, Path, Path]:
    """Write CSV, JSON, and JSONL snapshots sharing one timestamp."""
    records = [_record(device) for device in devices]
    exported_at = datetime.now(timezone.utc)
    directory = Path(Config.captures_dir) / "scan_exports"
    ensure_private_directory(directory)
    stem = f"bluetooth_{exported_at.strftime('%Y%m%d_%H%M%S_%f')}"
    csv_path = directory / f"{stem}.csv"
    json_path = directory / f"{stem}.json"
    jsonl_path = directory / f"{stem}.jsonl"
    fields = list(records[0]) if records else list(_record_fields())
    with open_private_text_write(csv_path, newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(_csv_record(record) for record in records)
    report = {
        "exported_at": exported_at.isoformat(),
        "devices": records,
    }
    write_private_text(json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    write_private_text(
        jsonl_path,
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
    )
    return csv_path, json_path, jsonl_path


def _record_fields() -> tuple[str, ...]:
    return (
        "name", "identifier", "radio", "discovery_source", "address_type",
        "baseline_status", "profile_changed", "manufacturer", "probable_type",
        "exact_type", "classification_source", "classification_confidence",
        "classification_ambiguous", "protocol_category", "protocol_type",
        "protocol_source", "protocol_confidence", "bluez_modalias",
        "hardware_vendor", "hardware_product", "hardware_identity_source",
        "signal_dbm", "signal_average_dbm", "signal_min_dbm", "signal_max_dbm",
        "signal_samples", "signal_trend", "class_of_device", "appearance",
        "tx_power_dbm",
        "advertisements", "latest_interval_ms", "first_seen", "last_seen",
        "manufacturer_data_bytes", "service_data_bytes", "payload_fingerprint",
        "profile_fingerprint", "advertised_services", "service_uuids",
        "service_data_uuids",
    )
