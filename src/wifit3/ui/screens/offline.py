from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static, Tab, Tabs

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


class OfflineDatabaseView(Screen):
    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("r", "reload", "Reload"),
        Binding("enter", "toggle_row", "Expand", priority=True),
    ]

    CSS = """
    OfflineDatabaseView #offline-body {
        height: 1fr;
        padding: 0 1;
    }
    OfflineDatabaseView #offline-title {
        height: 2;
        content-align: center middle;
        text-style: bold;
        color: $accent;
    }
    OfflineDatabaseView #offline-hint {
        height: 1;
        content-align: center middle;
        color: $text-muted;
    }
    OfflineDatabaseView Tabs {
        margin-top: 1;
    }
    OfflineDatabaseView DataTable {
        height: 1fr;
        border: round $primary;
        border-title-color: $accent;
        border-title-style: bold;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._records: dict[str, list[dict[str, Any]]] = {
            "aps": [], "clients": [], "bluetooth": [],
        }
        self._active = "aps"
        self._expanded: tuple[str, str] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="offline-body"):
            yield Static("OFFLINE DATABASE", id="offline-title")
            yield Static(
                "No radios are started · select a row and press Enter to inspect every field",
                id="offline-hint",
            )
            yield Tabs(
                Tab("ACCESS POINTS", id="offline-tab-aps"),
                Tab("CLIENTS", id="offline-tab-clients"),
                Tab("BT / BLE", id="offline-tab-bluetooth"),
                id="offline-tabs",
            )
            yield DataTable(
                id="offline-aps", cursor_type="row", zebra_stripes=True,
            )
            yield DataTable(
                id="offline-clients", cursor_type="row", zebra_stripes=True,
            )
            yield DataTable(
                id="offline-bluetooth", cursor_type="row", zebra_stripes=True,
            )
        yield Footer()

    def on_mount(self) -> None:
        self._configure_tables()
        self.reload()

    def on_screen_resume(self) -> None:
        self.reload()

    def _configure_tables(self) -> None:
        for kind in self._records:
            table = self._table(kind)
            table.add_columns("", "Identity", "Summary", "Last seen", "GPS")
            table.display = kind == self._active

    def reload(self) -> None:
        self._records["aps"] = self.app.ap_history_store.offline_access_points()
        self._records["clients"] = self.app.ap_history_store.offline_clients()
        self._records["bluetooth"] = (
            self.app.bluetooth_history_store.offline_devices()
        )
        position_kinds = {
            "aps": "wifi_ap",
            "clients": "wifi_client",
            "bluetooth": "bluetooth",
        }
        for kind, entity_kind in position_kinds.items():
            positions = self.app.location_store.positions_for_kind(entity_kind)
            for record in self._records[kind]:
                identity = self._identity(kind, record).casefold()
                record["positions"] = [
                    asdict(position) for position in positions.get(identity, [])
                ]
        self._expanded = None
        for kind in self._records:
            self._render_table(kind)

    def action_reload(self) -> None:
        self.reload()
        self.notify("Offline history reloaded", title="Database")

    def action_back(self) -> None:
        self.app.switch_screen("splash")

    def action_toggle_row(self) -> None:
        table = self._table(self._active)
        if table.row_count == 0:
            return
        try:
            row_key = table.coordinate_to_cell_key(
                table.cursor_coordinate,
            ).row_key.value
        except Exception:
            return
        self._toggle_record(self._active, str(row_key))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        kind = self._kind_for_table(event.data_table)
        if kind is not None:
            self._toggle_record(kind, str(event.row_key.value))

    def _toggle_record(self, kind: str, row_key: str) -> None:
        prefix = f"{kind}:"
        if not row_key.startswith(prefix):
            return
        identity = row_key.removeprefix(prefix)
        target = (kind, identity)
        self._expanded = None if self._expanded == target else target
        self._render_table(kind, selected_identity=identity)

    @on(Tabs.TabActivated, "#offline-tabs")
    def _tab_activated(self, event: Tabs.TabActivated) -> None:
        if event.tab is None or event.tab.id is None:
            return
        kind = event.tab.id.removeprefix("offline-tab-")
        if kind not in self._records:
            return
        self._active = kind
        self._expanded = None
        for table_kind in self._records:
            self._table(table_kind).display = table_kind == kind
        self._render_table(kind)
        self._table(kind).focus()

    def _render_table(
        self, kind: str, *, selected_identity: str | None = None,
    ) -> None:
        table = self._table(kind)
        table.clear()
        records = self._records[kind]
        for record in records:
            identity = self._identity(kind, record)
            expanded = self._expanded == (kind, identity)
            marker = Text("▾" if expanded else "▸", style="bold cyan")
            name, summary = self._summary(kind, record)
            table.add_row(
                marker,
                Text(name, style="bold"),
                Text(summary),
                Text(_timestamp(record.get("last_seen")), style="dim"),
                Text(_record_position(record), style="cyan"),
                key=f"{kind}:{identity}",
            )
            if expanded:
                for index, (field, value) in enumerate(_flatten(record)):
                    table.add_row(
                        Text("│", style="dim cyan"),
                        Text(field, style="dim"),
                        Text(value, style="cyan"),
                        "",
                        "",
                        key=f"detail:{kind}:{identity}:{index}",
                    )
        table.border_title = f"{_title(kind)} · {len(records):,} records"
        if not records:
            table.add_row(
                "", Text("No saved records", style="italic dim"),
                Text("Start a scan later to populate this view", style="dim"),
                "", "",
                key=f"empty:{kind}",
            )
        if selected_identity is not None:
            try:
                table.move_cursor(
                    row=table.get_row_index(f"{kind}:{selected_identity}"),
                )
            except Exception:
                pass

    def _summary(self, kind: str, record: dict[str, Any]) -> tuple[str, str]:
        if kind == "aps":
            name = str(record.get("ssid") or "‹hidden›")
            parts = [
                str(record.get("bssid", "")),
                f"CH {record['channel']}" if record.get("channel") is not None else "",
                str(record.get("encryption") or "Unknown security"),
                f"{len(record.get('clients', []))} clients",
            ]
        elif kind == "clients":
            name = str(record.get("client_mac", ""))
            count = int(record.get("access_point_count", 0))
            parts = [f"{count} associated AP{'s' if count != 1 else ''}"]
        else:
            name = str(record.get("name") or "‹unknown›")
            radios = record.get("radio_types") or []
            parts = [
                str(record.get("identifier", "")),
                " + ".join(str(item) for item in radios),
                str(record.get("address_type") or ""),
                str(record.get("protocol", {}).get("type", "")),
            ]
        return name, "  ·  ".join(part for part in parts if part)

    def _identity(self, kind: str, record: dict[str, Any]) -> str:
        field = {
            "aps": "bssid",
            "clients": "client_mac",
            "bluetooth": "identifier",
        }[kind]
        return str(record.get(field, ""))

    def _table(self, kind: str) -> DataTable:
        return self.query_one(f"#offline-{kind}", DataTable)

    def _kind_for_table(self, table: DataTable) -> str | None:
        for kind in self._records:
            if table.id == f"offline-{kind}":
                return kind
        return None


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        if not value and prefix:
            return [(prefix, "-")]
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten(child, field))
        return rows
    if isinstance(value, list):
        if not value:
            return [(prefix, "-")]
        for index, child in enumerate(value, start=1):
            rows.extend(_flatten(child, f"{prefix}[{index}]"))
        return rows
    if value is None or value == "":
        rendered = "-"
    elif prefix.endswith(("first_seen", "last_seen", "started_at", "ended_at")):
        rendered = _timestamp(value)
    elif isinstance(value, bool):
        rendered = "yes" if value else "no"
    else:
        rendered = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return [(prefix, rendered)]


def _timestamp(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return datetime.fromtimestamp(float(value)).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S",
        )
    except (OSError, OverflowError, TypeError, ValueError):
        return str(value)


def _record_position(record: dict[str, Any]) -> str:
    positions = record.get("positions")
    if not isinstance(positions, list) or not positions:
        return "·"
    position = max(
        (item for item in positions if isinstance(item, dict)),
        key=lambda item: float(item.get("observed_at", 0)),
        default=None,
    )
    if position is None:
        return "·"
    try:
        return (
            f"{float(position['latitude']):.5f}, "
            f"{float(position['longitude']):.5f} "
            f"±{float(position['accuracy_m']):.0f}m"
        )
    except (KeyError, TypeError, ValueError):
        return "·"


def _title(kind: str) -> str:
    return {
        "aps": "ACCESS POINTS",
        "clients": "CLIENTS",
        "bluetooth": "BT / BLE DEVICES",
    }[kind]
