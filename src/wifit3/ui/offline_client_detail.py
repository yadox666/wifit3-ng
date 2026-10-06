"""Structured offline Wi‑Fi client detail, with raw tail fields."""
from __future__ import annotations

from typing import Any

from rich.markup import escape

from wifit3.id import vendor_for_mac
from wifit3.persist.ap_history import client_from_offline_record
from wifit3.ui.focus_model import client_advertised_details
from wifit3.ui.offline_detail_common import (
    gps_section,
    history_section,
    offline_timestamp,
    scan_session_section,
    stored_fields_section,
)

_RECORD_SKIP = frozenset({
    "client_mac",
    "first_seen",
    "last_seen",
    "access_point_count",
    "access_points",
    "scan_sessions",
    "positions",
    "session_name",
    "session_count",
})


def offline_client_detail_markup(record: dict[str, Any]) -> str:
    client = client_from_offline_record(record)
    mac = str(record.get("client_mac") or "")
    vendor = vendor_for_mac(mac)
    lines: list[str] = [
        f"[bold]{escape(mac)}[/bold]",
    ]
    if vendor:
        lines.append(f"[dim]Manufacturer:[/dim] {escape(vendor)}")
    lines.extend(["", client_advertised_details(client)])

    for block in (
        history_section(
            record,
            extras=[("Known APs", record.get("access_point_count"))],
        ),
        _access_points_section(record),
        scan_session_section(record),
        gps_section(record),
        _stored_section(record),
    ):
        if block:
            lines.extend(["", *block])

    body = "\n".join(lines)
    return body or "[dim]No extra fields stored for this record.[/dim]"


def _access_points_section(record: dict[str, Any]) -> list[str]:
    access_points = record.get("access_points") or []
    if not access_points:
        return []
    rows = ["[bold cyan]Associated access points[/bold cyan]"]
    for item in access_points[:8]:
        if not isinstance(item, dict):
            continue
        bssid = str(item.get("bssid") or "·")
        ssid = str(item.get("ssid") or "‹hidden›")
        channel = item.get("channel")
        ch_bit = f" · ch {channel}" if channel else ""
        enc = str(item.get("encryption") or "")
        enc_bit = f" · {escape(enc)}" if enc and enc != "Unknown" else ""
        last = offline_timestamp(item.get("last_seen"))
        rows.append(
            f"  [bold]{escape(ssid)}[/bold]  [dim]{escape(bssid)}{ch_bit}{enc_bit}[/dim]  "
            f"[dim]last {last}[/dim]",
        )
    extra = len(access_points) - 8
    if extra > 0:
        rows.append(f"  [dim]+{extra} more access points[/dim]")
    return rows


def _stored_section(record: dict[str, Any]) -> list[str]:
    return stored_fields_section(record, skip=_RECORD_SKIP)
