"""Structured offline AP detail (grouped like Focus), with raw tail fields."""
from __future__ import annotations

from dataclasses import fields
from typing import Any

from rich.markup import escape

from wifit3.models import AccessPoint, AdvertisedCapabilities
from wifit3.persist.ap_history import access_point_from_offline_record
from wifit3.ui.encryption_format import format_encryption_markup
from wifit3.ui.focus_model import router_advertised_details
from wifit3.ui.offline_detail_common import (
    catalog_assignment_section,
    gps_section,
    history_section,
    offline_timestamp,
    scan_session_section,
    stored_fields_section,
)

_KNOWN_CAPABILITY_KEYS = frozenset(
    field.name for field in fields(AdvertisedCapabilities)
)

_RECORD_SKIP = frozenset({
    "capabilities",
    "security",
    "wps",
    "enterprise",
    "identity_evidence",
    "clients",
    "scan_sessions",
    "relationships",
    "positions",
    "ssid",
    "bssid",
    "channel",
    "encryption",
    "country_code",
    "first_seen",
    "last_seen",
    "ssid_source",
    "session_name",
    "session_count",
})


def offline_ap_detail_markup(
    record: dict[str, Any],
    *,
    manual_catalog_family_id: str = "",
) -> str:
    ap = access_point_from_offline_record(record)
    lines: list[str] = [
        f"[bold]{escape(str(record.get('ssid') or '‹hidden›'))}[/bold]  "
        f"[dim]{escape(str(record.get('bssid') or ''))}[/dim]",
        f"[dim]Encryption:[/dim] {format_encryption_markup(ap, detailed=True)}",
        "",
        router_advertised_details(ap),
    ]

    for block in (
        history_section(record, extras=[("Last channel", record.get("channel"))]),
        scan_session_section(record),
        _associated_clients_section(record),
        gps_section(record),
        _relationship_section(record),
        _wps_section(record, ap),
        catalog_assignment_section(manual_catalog_family_id),
        _stored_section(record),
    ):
        if block:
            lines.extend(["", *block])

    body = "\n".join(line for line in lines if line is not None)
    return body or "[dim]No extra fields stored for this record.[/dim]"


def _associated_clients_section(record: dict[str, Any]) -> list[str]:
    clients = record.get("clients") or []
    if not clients:
        return []
    rows = ["[bold cyan]Associated clients[/bold cyan]"]
    for item in clients[:8]:
        if not isinstance(item, dict):
            continue
        mac = str(item.get("client_mac") or "·")
        last = offline_timestamp(item.get("last_seen"))
        rows.append(f"  {escape(mac)}  [dim]last {last}[/dim]")
    extra = len(clients) - 8
    if extra > 0:
        rows.append(f"  [dim]+{extra} more clients[/dim]")
    return rows


def _relationship_section(record: dict[str, Any]) -> list[str]:
    relationships = record.get("relationships") or []
    if not relationships:
        return []
    by_kind: dict[str, list[str]] = {}
    for item in relationships:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "related")
        peer = str(item.get("related_bssid") or "")
        if peer:
            by_kind.setdefault(kind, []).append(peer)
    if not by_kind:
        return []
    rows = ["[bold cyan]Relationships[/bold cyan]"]
    for kind, peers in sorted(by_kind.items()):
        label = kind.replace("_", " ").title()
        shown = ", ".join(escape(peer) for peer in peers[:6])
        extra = len(peers) - 6
        if extra > 0:
            shown = f"{shown} [dim]+{extra}[/dim]"
        rows.append(f"  [dim]{escape(label)}:[/dim] {shown}")
    return rows


def _wps_section(record: dict[str, Any], ap: AccessPoint) -> list[str]:
    if not ap.wps:
        return []
    raw = record.get("wps")
    if not isinstance(raw, dict):
        return []
    rows = ["[bold cyan]WPS[/bold cyan]"]
    lock = "locked" if ap.wps_locked else "unlocked"
    rows.append(f"  [dim]State:[/dim] {lock}")
    if ap.wps_version:
        rows.append(f"  [dim]Version:[/dim] {escape(str(ap.wps_version))}")
    if ap.wps_uuid_e:
        rows.append(f"  [dim]UUID-E:[/dim] {escape(str(ap.wps_uuid_e))}")
    methods = raw.get("config_methods")
    if methods:
        rows.append(f"  [dim]Config methods:[/dim] {methods}")
    return rows if len(rows) > 1 else []


def _stored_section(record: dict[str, Any]) -> list[str]:
    caps = record.get("capabilities")
    extra = None
    if isinstance(caps, dict):
        extra = {
            key: value
            for key, value in caps.items()
            if key not in _KNOWN_CAPABILITY_KEYS
        }
        if not extra:
            extra = None
    return stored_fields_section(
        record,
        skip=_RECORD_SKIP,
        capability_extra=extra,
    )
