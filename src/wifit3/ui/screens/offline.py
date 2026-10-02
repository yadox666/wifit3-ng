from __future__ import annotations

import json
import webbrowser
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static, Tab, Tabs

from wifit3.models.location import SignalPosition
from wifit3.ui.location_format import (
    best_position,
    google_maps_search_url,
    latest_position,
)
from wifit3.ui.notification_center import WifiteHeader

from wifit3.targeting import TargetCandidate, offline_record_candidate
from wifit3.ui.screens.clear_history import ClearHistoryModal, HistoryClearSelection
from wifit3.ui.screens.offline_filter import OfflineFilterBar, OfflineFilters, record_matches

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


_COLUMNS = {
    "aps": (
        ("marker", ""), ("ssid", "SSID"), ("bssid", "BSSID"), ("channel", "CH"),
        ("encryption", "SECURITY"), ("clients", "CLIENTS"),
        ("session", "SESSION"), ("last_seen", "LAST SEEN"), ("location", "GPS"),
    ),
    "clients": (
        ("marker", ""), ("client_mac", "CLIENT"), ("access_point_count", "APS"),
        ("last_ssid", "LAST SSID"), ("last_bssid", "LAST BSSID"),
        ("channel", "CH"), ("session", "SESSION"),
        ("last_seen", "LAST SEEN"), ("location", "GPS"),
    ),
    "bluetooth": (
        ("marker", ""), ("name", "NAME"), ("identifier", "IDENTIFIER"),
        ("radios", "RADIO"), ("address_type", "ADDRESS"),
        ("protocol", "PROTOCOL"), ("session", "SESSION"),
        ("last_seen", "LAST SEEN"), ("location", "GPS"),
    ),
}


class _OfflineDataTable(DataTable):
    def on_click(self, event: events.Click) -> None:
        coordinate = self.hover_coordinate
        if coordinate is None:
            return
        try:
            cell_key = self.coordinate_to_cell_key(coordinate)
        except Exception:
            return
        if cell_key.column_key.value != "location":
            return
        open_maps = getattr(self.screen, "_open_maps_from_table", None)
        if callable(open_maps) and open_maps(cell_key.row_key.value):
            self.screen._block_next_row_select = True
            event.stop()


class OfflineDatabaseView(Screen):
    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("r", "reload", "Reload"),
        Binding("c", "clear_db", "Clear-DB"),
        Binding("shift+t", "targets_editor", "Targets"),
        Binding("f", "focus_filter", "Filter"),
        Binding("/", "focus_filter", "Filter", show=False),
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
        self._filters = OfflineFilters()
        self._sort: dict[str, tuple[str, bool]] = {
            kind: ("last_seen", True) for kind in self._records
        }
        self._table_map_urls: dict[str, str] = {}
        self._block_next_row_select = False

    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Vertical(id="offline-body"):
            yield Static("OFFLINE DATABASE", id="offline-title")
            yield Static(
                "No radios are started · select a row and press Enter to inspect every field",
                id="offline-hint",
            )
            yield OfflineFilterBar()
            yield Tabs(
                Tab("ACCESS POINTS", id="offline-tab-aps"),
                Tab("CLIENTS", id="offline-tab-clients"),
                Tab("BT / BLE", id="offline-tab-bluetooth"),
                id="offline-tabs",
            )
            yield _OfflineDataTable(
                id="offline-aps", cursor_type="row", zebra_stripes=True,
            )
            yield _OfflineDataTable(
                id="offline-clients", cursor_type="row", zebra_stripes=True,
            )
            yield _OfflineDataTable(
                id="offline-bluetooth", cursor_type="row", zebra_stripes=True,
            )
        yield Footer()

    def on_mount(self) -> None:
        self._configure_tables()
        self.query_one(OfflineFilterBar).set_kind(self._active)
        self.reload()

    def on_screen_resume(self) -> None:
        self.query_one(OfflineFilterBar).refresh_target_options()
        self.reload()

    def _configure_tables(self) -> None:
        for kind in self._records:
            table = self._table(kind)
            for key, label in _COLUMNS[kind]:
                table.add_column(label, key=key)
            table.display = kind == self._active
            self._update_column_headers(kind)

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

    def action_targets_editor(self) -> None:
        candidate = self._selected_target_candidate()
        if candidate is None:
            self.app.open_targets_editor()
            return
        self.app.open_targets_editor(prefill=candidate)

    def _selected_target_candidate(self) -> TargetCandidate | None:
        table = self._table(self._active)
        identity = self._selected_identity(table, self._active)
        if identity is None:
            return None
        for record in self._records[self._active]:
            if self._identity(self._active, record) == identity:
                return offline_record_candidate(self._active, record)
        return None

    def action_clear_db(self) -> None:
        self.app.push_screen(ClearHistoryModal(), self._clear_history)

    def _clear_history(self, selection: HistoryClearSelection | None) -> None:
        if selection is None:
            return
        cleared: list[str] = []
        errors: list[str] = []
        if selection.wifi:
            for label, action in (
                ("Wi-Fi database", self.app.ap_history_store.clear),
                ("hidden SSIDs", self.app.hidden_ssid_store.clear),
                ("association profiles", self.app.wifi_profile_store.clear),
                ("Enterprise history", self.app.enterprise_session_store.clear),
                (
                    "Wi-Fi saved targets",
                    lambda: self.app.target_store.clear_medium("wifi"),
                ),
            ):
                try:
                    action()
                except Exception as exc:
                    errors.append(f"{label}: {exc}")
            if not errors:
                cleared.append("Wi-Fi")
        if selection.bluetooth:
            bluetooth_errors = len(errors)
            try:
                self.app.bluetooth_history_store.clear()
                self.app.bluetooth_manager.forget_devices()
                self.app.target_store.clear_medium("bluetooth")
            except Exception as exc:
                errors.append(f"Bluetooth / BLE database: {exc}")
            if len(errors) == bluetooth_errors:
                cleared.append("Bluetooth / BLE")
        if cleared:
            self.reload()
            self.notify(
                f"Cleared {' and '.join(cleared)} history. Capture artifacts were kept.",
                title="History databases",
            )
        if errors:
            self.notify(
                "\n".join(errors),
                title="History deletion incomplete",
                severity="error",
            )

    def action_back(self) -> None:
        self.app.switch_screen("splash")

    def action_focus_filter(self) -> None:
        self.query_one(OfflineFilterBar).focus_text()

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
        if self._block_next_row_select:
            self._block_next_row_select = False
            return
        kind = self._kind_for_table(event.data_table)
        if kind is not None:
            self._toggle_record(kind, str(event.row_key.value))

    def _toggle_record(self, kind: str, row_key: str) -> None:
        prefix = f"{kind}:"
        if not row_key.startswith(prefix) or ":detail:" in row_key:
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
        self.query_one(OfflineFilterBar).set_kind(kind)
        for table_kind in self._records:
            self._table(table_kind).display = table_kind == kind
        self._render_table(kind)
        self._table(kind).focus()

    def on_offline_filter_bar_filter_changed(
        self, message: OfflineFilterBar.FilterChanged,
    ) -> None:
        self._filters = message.filters
        self._expanded = None
        self._render_table(self._active)

    def _render_table(
        self, kind: str, *, selected_identity: str | None = None,
    ) -> None:
        table = self._table(kind)
        table.clear()
        self._table_map_urls = {
            key: value
            for key, value in self._table_map_urls.items()
            if not key.startswith(f"{kind}:")
        }
        all_records = self._records[kind]
        records = [
            record for record in all_records
            if record_matches(
                kind, record, self._filters, target_store=self.app.target_store,
            )
        ]
        sort_key, reverse = self._sort[kind]
        records.sort(
            key=lambda record: self._record_sort_value(kind, record, sort_key),
            reverse=reverse,
        )
        for record in records:
            identity = self._identity(kind, record)
            expanded = self._expanded == (kind, identity)
            marker = Text("▾" if expanded else "▸", style="bold cyan")
            row_key = f"{kind}:{identity}"
            map_url = google_maps_search_url(
                self._signal_positions(record),
                prefer_best=kind == "aps",
            )
            if map_url is not None:
                self._table_map_urls[row_key] = map_url
            table.add_row(
                *self._row_values(kind, record, marker, map_url is not None),
                key=row_key,
            )
            if expanded:
                for index, (field, value) in enumerate(_flatten(record)):
                    cells: list[Any] = [
                        Text("│", style="dim cyan"),
                        Text(field, style="dim"),
                        Text(value, style="cyan"),
                    ]
                    cells.extend(
                        "" for _ in range(len(_COLUMNS[kind]) - len(cells))
                    )
                    table.add_row(
                        *cells,
                        key=f"detail:{kind}:{identity}:{index}",
                    )
        total = len(all_records)
        shown = len(records)
        if shown == total:
            count_label = f"{shown:,} records"
        else:
            count_label = f"{shown:,} / {total:,} records"
        table.border_title = f"{_title(kind)} · {count_label}"
        if not all_records:
            cells = [
                "", Text("No saved records", style="italic dim"),
                Text("Start a scan later to populate this view", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS[kind]) - len(cells)))
            table.add_row(*cells, key=f"empty:{kind}")
        elif not records:
            cells = [
                "", Text("No matches", style="italic dim"),
                Text("Relax the search or clear the filter text", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS[kind]) - len(cells)))
            table.add_row(*cells, key=f"empty-filter:{kind}")
        self._update_column_headers(kind)
        if selected_identity is not None:
            try:
                table.move_cursor(
                    row=table.get_row_index(f"{kind}:{selected_identity}"),
                )
            except Exception:
                pass

    def _row_values(
        self,
        kind: str,
        record: dict[str, Any],
        marker: Text,
        has_map: bool,
    ) -> tuple[Any, ...]:
        position = Text(
            _record_position(
                record,
                prefer_best=kind == "aps",
                with_globe=has_map,
            ),
            style="cyan",
        )
        if kind == "aps":
            return (
                marker,
                Text(str(record.get("ssid") or "‹hidden›"), style="bold"),
                str(record.get("bssid") or "·"),
                str(record.get("channel") or "·"),
                str(record.get("encryption") or "Unknown"),
                str(len(record.get("clients", []))),
                _session_label(record),
                Text(_timestamp(record.get("last_seen")), style="dim"),
                position,
            )
        if kind == "clients":
            latest = self._latest_access_point(record)
            return (
                marker,
                Text(str(record.get("client_mac") or "·"), style="bold"),
                str(record.get("access_point_count", 0)),
                str(latest.get("ssid") or "·"),
                str(latest.get("bssid") or "·"),
                str(latest.get("channel") or "·"),
                _session_label(record),
                Text(_timestamp(record.get("last_seen")), style="dim"),
                position,
            )
        protocol = record.get("protocol") or {}
        return (
            marker,
            Text(str(record.get("name") or "‹unknown›"), style="bold"),
            str(record.get("identifier") or "·"),
            " + ".join(str(item) for item in record.get("radio_types") or []) or "·",
            str(record.get("address_type") or "·"),
            str(protocol.get("label") or protocol.get("type") or "·"),
            _session_label(record),
            Text(_timestamp(record.get("last_seen")), style="dim"),
            position,
        )

    def on_data_table_header_selected(
        self, event: DataTable.HeaderSelected,
    ) -> None:
        kind = self._kind_for_table(event.data_table)
        key = str(event.column_key.value)
        if kind is None or key == "marker":
            return
        current_key, current_reverse = self._sort[kind]
        self._sort[kind] = (
            key,
            not current_reverse if current_key == key else False,
        )
        selected_identity = self._selected_identity(event.data_table, kind)
        self._render_table(kind, selected_identity=selected_identity)

    def _selected_identity(
        self, table: DataTable, kind: str,
    ) -> str | None:
        if table.row_count == 0:
            return None
        try:
            row_key = str(
                table.coordinate_to_cell_key(
                    table.cursor_coordinate,
                ).row_key.value
            )
        except Exception:
            return None
        prefix = f"{kind}:"
        if not row_key.startswith(prefix):
            return None
        identity = row_key.removeprefix(prefix)
        return identity.split(":detail:", maxsplit=1)[0]

    def _update_column_headers(self, kind: str) -> None:
        table = self._table(kind)
        sort_key, reverse = self._sort[kind]
        arrow = "▼" if reverse else "▲"
        for key, label in _COLUMNS[kind]:
            suffix = f" {arrow}" if key == sort_key else ""
            table.columns[key].label = Text(f"{label}{suffix}")
        table.refresh()

    def _latest_access_point(self, record: dict[str, Any]) -> dict[str, Any]:
        access_points = record.get("access_points") or []
        if not access_points:
            return {}
        return max(
            access_points,
            key=lambda item: _numeric(item.get("last_seen")),
        )

    def _record_sort_value(
        self, kind: str, record: dict[str, Any], key: str,
    ) -> tuple[bool, Any]:
        latest = self._latest_access_point(record) if kind == "clients" else {}
        if key == "clients":
            value: Any = len(record.get("clients", []))
        elif key in {"access_point_count", "channel", "last_seen"}:
            source = latest if kind == "clients" and key == "channel" else record
            value = _numeric(source.get(key))
        elif key == "location":
            positions = self._signal_positions(record)
            selected = (
                best_position(positions)
                if kind == "aps"
                else latest_position(positions)
            )
            value = selected.observed_at if selected is not None else 0.0
        elif key.startswith("last_"):
            value = latest.get(key.removeprefix("last_"))
        elif key == "radios":
            value = " ".join(record.get("radio_types") or [])
        elif key == "protocol":
            protocol = record.get("protocol") or {}
            value = protocol.get("label") or protocol.get("type")
        elif key == "session":
            value = record.get("session_name")
        else:
            value = record.get(key)
        if isinstance(value, str):
            value = value.casefold()
        return value not in (None, "", 0.0), value if value is not None else ""

    def _signal_positions(
        self, record: dict[str, Any],
    ) -> list[SignalPosition]:
        return _signal_positions(record)

    def _open_maps_from_table(self, row_key: str) -> bool:
        url = self._table_map_urls.get(row_key)
        if url is None:
            return False
        try:
            webbrowser.open(url)
        except Exception as exc:
            self.notify(
                f"Could not open the map: {exc}",
                title="GPS location",
                severity="error",
            )
        return True

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


def _session_label(record: dict[str, Any]) -> Text:
    name = str(record.get("session_name") or "Legacy")
    count = int(record.get("session_count") or 0)
    suffix = f" +{count - 1}" if count > 1 else ""
    style = "cyan" if count else "dim"
    return Text(f"{name}{suffix}", style=style)


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


def _record_position(
    record: dict[str, Any],
    *,
    prefer_best: bool = False,
    with_globe: bool = False,
) -> str:
    positions = _signal_positions(record)
    position = (
        best_position(positions) if prefer_best else latest_position(positions)
    )
    if position is None:
        return "·"
    globe = "  🌐" if with_globe else ""
    return (
        f"{position.latitude:.5f}, {position.longitude:.5f} "
        f"±{position.accuracy_m:.0f}m{globe}"
    )


def _signal_positions(record: dict[str, Any]) -> list[SignalPosition]:
    positions: list[SignalPosition] = []
    for raw in record.get("positions") or []:
        if not isinstance(raw, dict):
            continue
        try:
            positions.append(
                SignalPosition(
                    latitude=float(raw["latitude"]),
                    longitude=float(raw["longitude"]),
                    altitude_m=_optional_float(raw.get("altitude_m")),
                    accuracy_m=float(raw.get("accuracy_m", 0.0)),
                    observed_at=float(raw.get("observed_at", 0.0)),
                    source=str(raw.get("source") or "unknown"),
                    rssi=_optional_int(raw.get("rssi")),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return positions


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _title(kind: str) -> str:
    return {
        "aps": "ACCESS POINTS",
        "clients": "CLIENTS",
        "bluetooth": "BT / BLE DEVICES",
    }[kind]
