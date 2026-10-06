"""Structured offline BT/BLE detail, with raw tail fields."""
from __future__ import annotations

from typing import Any

from rich.markup import escape

from wifit3.persist.bluetooth_history import bluetooth_device_from_offline_record
from wifit3.ui.bluetooth_detail import device_detail_lines
from wifit3.ui.offline_detail_common import (
    catalog_assignment_section,
    gps_section,
    history_section,
    offline_timestamp,
    scan_session_section,
    stored_fields_section,
)

_RECORD_SKIP = frozenset({
    "identifier",
    "name",
    "first_seen",
    "last_seen",
    "service_uuids",
    "service_data_uuids",
    "manufacturer_ids",
    "tx_power",
    "radio_types",
    "class_of_device",
    "appearance",
    "address_type",
    "profile_fingerprint",
    "payload_fingerprint",
    "modalias",
    "hardware_vendor",
    "hardware_product",
    "hardware_source",
    "model_number",
    "serial_number",
    "firmware_revision",
    "hardware_revision",
    "software_revision",
    "manufacturer_name",
    "gatt_device_name",
    "pnp_id",
    "ble_mac",
    "protocol",
    "catalog",
    "analysis",
    "event_captures",
    "scan_sessions",
    "probable_links",
    "positions",
    "fingerprint_id",
    "fingerprint_completeness",
    "bluetooth_fingerprint",
    "session_name",
    "session_count",
})


def offline_bluetooth_detail_markup(
    record: dict[str, Any],
    *,
    manual_catalog_family_id: str = "",
) -> str:
    device = bluetooth_device_from_offline_record(record)
    lines: list[str] = list(device_detail_lines(device))

    for block in (
        history_section(record),
        _bluetooth_fingerprint_section(record),
        scan_session_section(record),
        _event_capture_section(record),
        _probable_links_section(record),
        gps_section(record),
        catalog_assignment_section(manual_catalog_family_id),
        stored_fields_section(record, skip=_RECORD_SKIP),
    ):
        if block:
            lines.extend(["", *block])

    body = "\n".join(lines)
    return body or "[dim]No extra fields stored for this record.[/dim]"


def _bluetooth_fingerprint_section(record: dict[str, Any]) -> list[str]:
    fp_id = str(record.get("fingerprint_id") or "").strip()
    document = record.get("bluetooth_fingerprint")
    if not fp_id and not isinstance(document, dict):
        return []
    rows = ["[bold cyan]Bluetooth fingerprint[/bold cyan]"]
    if fp_id:
        rows.append(
            f"  [dim]Signature:[/dim] [cyan]{escape(fp_id[:16])}[/cyan] "
            f"[dim]({int(record.get('fingerprint_completeness') or 0)}% evidence)[/dim]",
        )
    if isinstance(document, dict) and document.get("kind"):
        rows.append(f"  [dim]Kind:[/dim] {escape(str(document['kind']))}")
    return rows if len(rows) > 1 else []


def _event_capture_section(record: dict[str, Any]) -> list[str]:
    captures = record.get("event_captures") or []
    if not captures:
        return []
    rows = ["[bold cyan]Event captures[/bold cyan]"]
    for item in captures[:5]:
        if not isinstance(item, dict):
            continue
        alias = str(item.get("alias") or item.get("capture_id") or "capture")
        started = offline_timestamp(item.get("started_at"))
        events = int(item.get("event_count") or 0)
        rows.append(
            f"  [bold]{escape(alias)}[/bold]  "
            f"[dim]{started} · {events} events[/dim]",
        )
    extra = len(captures) - 5
    if extra > 0:
        rows.append(f"  [dim]+{extra} more captures[/dim]")
    return rows


def _probable_links_section(record: dict[str, Any]) -> list[str]:
    links = record.get("probable_links") or []
    if not links:
        return []
    rows = ["[bold cyan]Observation links[/bold cyan]"]
    for item in links[:6]:
        if not isinstance(item, dict):
            continue
        peer = str(item.get("identifier") or "·")
        confidence = str(item.get("confidence") or "")
        method = str(item.get("method") or "")
        last = offline_timestamp(item.get("last_seen"))
        rows.append(
            f"  {escape(peer)}  [dim]{escape(confidence)} · {escape(method)} · {last}[/dim]",
        )
    extra = len(links) - 6
    if extra > 0:
        rows.append(f"  [dim]+{extra} more links[/dim]")
    return rows
