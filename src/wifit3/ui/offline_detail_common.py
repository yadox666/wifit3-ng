"""Shared helpers for offline DB detail panels."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from rich.markup import escape


def offline_timestamp(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return datetime.fromtimestamp(float(value)).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S",
        )
    except (OSError, OverflowError, TypeError, ValueError):
        return str(value)


def flatten_value(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        if not value and prefix:
            return [(prefix, "-")]
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_value(child, field))
        return rows
    if isinstance(value, list):
        if not value:
            return [(prefix, "-")]
        for index, child in enumerate(value, start=1):
            rows.extend(flatten_value(child, f"{prefix}[{index}]"))
        return rows
    if value is None or value == "":
        rendered = "-"
    elif prefix.endswith(
        ("first_seen", "last_seen", "started_at", "ended_at", "observed_at"),
    ):
        rendered = offline_timestamp(value)
    elif isinstance(value, bool):
        rendered = "yes" if value else "no"
    else:
        rendered = (
            json.dumps(value, ensure_ascii=False)
            if not isinstance(value, str)
            else value
        )
    return [(prefix, rendered)]


def format_stored_rows(rows: list[tuple[str, str]]) -> list[str]:
    if not rows:
        return []
    lines: list[str] = []
    for field, value in rows:
        text = str(value)
        if len(text) > 240:
            text = f"{text[:237]}…"
        lines.append(f"  [dim]{escape(field)}:[/dim] [cyan]{escape(text)}[/cyan]")
    return lines


def history_section(
    record: dict[str, Any],
    *,
    extras: list[tuple[str, Any]] | None = None,
) -> list[str]:
    rows = ["[bold cyan]History[/bold cyan]"]
    first = offline_timestamp(record.get("first_seen"))
    last = offline_timestamp(record.get("last_seen"))
    if first != "-":
        rows.append(f"  [dim]First seen:[/dim] {first}")
    if last != "-":
        rows.append(f"  [dim]Last seen:[/dim] {last}")
    for label, value in extras or []:
        if value is None or value == "":
            continue
        rows.append(f"  [dim]{escape(label)}:[/dim] {escape(str(value))}")
    return rows if len(rows) > 1 else []


def scan_session_section(record: dict[str, Any]) -> list[str]:
    sessions = record.get("scan_sessions") or []
    if not sessions:
        return []
    rows = ["[bold cyan]Scan sessions[/bold cyan]"]
    for item in sessions[:6]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "Legacy")
        mode = str(item.get("mode") or "")
        mode_bit = f" · {escape(mode)}" if mode else ""
        first = offline_timestamp(item.get("first_seen"))
        last = offline_timestamp(item.get("last_seen"))
        count = int(item.get("sighting_count") or 0)
        rows.append(
            f"  [bold]{escape(name)}[/bold]{mode_bit}  "
            f"[dim]{first} → {last} · {count} sightings[/dim]",
        )
    extra = len(sessions) - 6
    if extra > 0:
        rows.append(f"  [dim]+{extra} more sessions[/dim]")
    return rows


def gps_section(record: dict[str, Any]) -> list[str]:
    positions = record.get("positions") or []
    if not positions:
        return []
    rows = ["[bold cyan]GPS[/bold cyan]"]
    for item in positions[:4]:
        if not isinstance(item, dict):
            continue
        try:
            lat = float(item["latitude"])
            lon = float(item["longitude"])
            acc = float(item.get("accuracy_m", 0.0))
            when = offline_timestamp(item.get("observed_at"))
            source = str(item.get("source") or "unknown")
            rssi = item.get("rssi")
            rssi_bit = f" · {int(rssi)} dBm" if rssi is not None else ""
            rows.append(
                f"  {lat:.5f}, {lon:.5f} ±{acc:.0f} m  "
                f"[dim]{when} · {escape(source)}{rssi_bit}[/dim]",
            )
        except (KeyError, TypeError, ValueError):
            continue
    extra = len(positions) - 4
    if extra > 0:
        rows.append(f"  [dim]+{extra} more fixes[/dim]")
    return rows if len(rows) > 1 else []


def catalog_assignment_section(manual_catalog_family_id: str) -> list[str]:
    if not manual_catalog_family_id:
        return []
    return [
        "[bold cyan]Catalog assignment[/bold cyan]",
        f"  [dim]Manual family id:[/dim] [cyan]{escape(manual_catalog_family_id)}[/cyan] "
        "[dim]([bold]g[/bold] to change · Clear manual in picker)[/dim]",
    ]


def stored_fields_section(
    record: dict[str, Any],
    *,
    skip: frozenset[str],
    capability_extra: dict[str, Any] | None = None,
    capability_prefix: str = "capabilities",
) -> list[str]:
    rows: list[tuple[str, str]] = []
    if capability_extra:
        rows.extend(flatten_value(capability_extra, capability_prefix))
    tail = {
        key: value
        for key, value in record.items()
        if key not in skip
    }
    rows.extend(flatten_value(tail))
    formatted = format_stored_rows(rows)
    if not formatted:
        return []
    return ["[bold cyan]Stored fields[/bold cyan]", *formatted]
