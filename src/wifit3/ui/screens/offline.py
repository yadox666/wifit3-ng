from __future__ import annotations

import json
import webbrowser
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, Iterable

from rich.markup import escape
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import ActiveBinding, Binding
from wifit3.ui.binding_display import active_bindings_for_focus
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static, Tab, Tabs
from textual.widgets.data_table import CellKey, RowKey

from wifit3.models.location import SignalPosition
from wifit3.bluetooth.gatt_metadata import (
    format_gatt_identity_line,
    gatt_identity_parts,
)
from wifit3.ui.location_format import (
    best_position,
    google_maps_search_url,
    latest_position,
)
from wifit3.ui.notification_center import WifiteHeader

from wifit3.targeting import TargetCandidate, is_target_entry, offline_record_candidate
from wifit3.ui.screens.clear_history import ClearHistoryModal, HistoryClearSelection
from wifit3.ui.catalog_format import (
    catalog_class_cell,
    catalog_expand_rows,
    catalog_family_cell,
)
from wifit3.ui.data_table_columns import offline_column_caps, reclamp_offline_table
from wifit3.ui.mac_format import mac_address_text
from wifit3.ui.offline_bluetooth_panels import offline_bluetooth_use_secondary_panel
from wifit3.ui.offline_bluetooth_table import (
    OFFLINE_BLUETOOTH_COLUMNS,
    offline_bluetooth_device,
    offline_bluetooth_row_cells,
    offline_bluetooth_sort_value,
)
from wifit3.ui.bluetooth_detail import advertised_services_tooltip
from wifit3.ui.target_filter import match_offline_record
from wifit3.ui.target_markers import target_group_cell
from wifit3.ui.screens.offline_filter import OfflineFilterBar, OfflineFilters, record_matches

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


_OFFLINE_TAB_LABELS = {
    "aps": ("offline-tab-aps", "ACCESS POINTS"),
    "clients": ("offline-tab-clients", "WIFI-CLIENTS"),
    "bluetooth": ("offline-tab-bluetooth", "BT/BLE DEVICES"),
}

_COLUMNS = {
    "aps": (
        ("ssid", "SSID"), ("bssid", "BSSID"), ("channel", "CH"),
        ("encryption", "SECURITY"), ("clients", "CLIENTS"),
        ("catalog_class", "CLASS"), ("catalog_family", "FAMILY"),
        ("session", "SESSION"), ("last_seen", "LAST SEEN"), ("location", "GPS"),
        ("target", "TARGET"),
    ),
    "clients": (
        ("client_mac", "CLIENT"),
        ("access_point_count", "APS"),
        ("last_ssid", "LAST SSID"), ("last_bssid", "LAST BSSID"),
        ("channel", "CH"), ("session", "SESSION"),
        ("last_seen", "LAST SEEN"), ("location", "GPS"),
        ("target", "TARGET"),
    ),
    "bluetooth": OFFLINE_BLUETOOTH_COLUMNS,
}

class _OfflineDataTable(DataTable):
    def __init__(self, *args, **kwargs) -> None:
        self._service_tooltips: dict[str, str] = {}
        super().__init__(*args, **kwargs)

    def set_service_tooltip(self, row_key: str, value: str) -> None:
        self._service_tooltips[row_key] = value

    def clear(self, columns: bool = False):
        self._service_tooltips.clear()
        return super().clear(columns=columns)

    def watch_hover_coordinate(self, old, value) -> None:
        super().watch_hover_coordinate(old, value)
        try:
            cell_key = self.coordinate_to_cell_key(value)
        except Exception:
            self.tooltip = None
            return
        self.tooltip = (
            self._service_tooltips.get(str(cell_key.row_key.value))
            if cell_key.column_key.value == "services"
            else None
        )

    def _offline_kind(self) -> str:
        return (self.id or "offline-aps").removeprefix("offline-")

    def _reclamp_capped_columns(self) -> None:
        reclamp_offline_table(self, self._offline_kind())

    def _update_dimensions(self, new_rows: Iterable[RowKey]) -> None:
        super()._update_dimensions(new_rows)
        self._reclamp_capped_columns()

    def _update_column_widths(self, updated_cells: set[CellKey]) -> None:
        super()._update_column_widths(updated_cells)
        self._reclamp_capped_columns()

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
        Binding("n", "targets_editor", "Targets"),
        Binding("f", "focus_filter", "Filter"),
        Binding("/", "focus_filter", "Filter", show=False),
        Binding("y", "open_catalog", "Catalog", show=True),
        Binding("g", "assign_catalog_family", "Family", show=True),
    ]

    CSS = """
    OfflineDatabaseView #offline-body {
        height: 1fr;
        padding: 0 1;
    }
    OfflineDatabaseView Tabs {
        margin-top: 0;
    }
    OfflineDatabaseView DataTable {
        height: 3fr;
        border: round $primary;
        border-title-color: $accent;
        border-title-style: bold;
    }
    OfflineDatabaseView #offline-bluetooth-stack {
        height: 3fr;
        display: none;
    }
    OfflineDatabaseView.-bt-active #offline-aps,
    OfflineDatabaseView.-bt-active #offline-clients {
        display: none;
    }
    OfflineDatabaseView.-bt-active #offline-bluetooth-stack {
        display: block;
    }
    OfflineDatabaseView.-bt-active #offline-detail-scroll {
        height: 1fr;
        min-height: 8;
    }
    OfflineDatabaseView #offline-bluetooth {
        height: 2fr;
        min-height: 6;
    }
    OfflineDatabaseView #offline-bluetooth-secondary-separator {
        height: 1;
        background: $primary-darken-1;
        margin: 0 1;
    }
    OfflineDatabaseView #offline-bluetooth-secondary {
        height: 1fr;
        min-height: 5;
    }
    OfflineDatabaseView #offline-detail-scroll {
        height: 2fr;
        border: round $accent;
        border-title-color: $accent;
        border-title-style: bold;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }
    OfflineDatabaseView #offline-detail {
        height: auto;
        width: 100%;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._records: dict[str, list[dict[str, Any]]] = {
            "aps": [], "clients": [], "bluetooth": [],
        }
        self._active = "aps"
        self._detail_focus: tuple[str, str] | None = None
        self._filters = OfflineFilters()
        self._sort: dict[str, tuple[str, bool]] = {
            "aps": ("last_seen", True),
            "clients": ("last_seen", True),
            "bluetooth": ("last_seen", True),
        }
        self._table_map_urls: dict[str, str] = {}
        self._block_next_row_select = False

    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Vertical(id="offline-body"):
            yield OfflineFilterBar()
            yield Tabs(
                Tab("ACCESS POINTS (0)", id="offline-tab-aps"),
                Tab("WIFI-CLIENTS (0)", id="offline-tab-clients"),
                Tab("BT/BLE DEVICES (0)", id="offline-tab-bluetooth"),
                id="offline-tabs",
            )
            yield _OfflineDataTable(
                id="offline-aps", cursor_type="row", zebra_stripes=True,
            )
            yield _OfflineDataTable(
                id="offline-clients", cursor_type="row", zebra_stripes=True,
            )
            with Vertical(id="offline-bluetooth-stack"):
                yield _OfflineDataTable(
                    id="offline-bluetooth", cursor_type="row", zebra_stripes=True,
                )
                yield Static("", id="offline-bluetooth-secondary-separator")
                yield _OfflineDataTable(
                    id="offline-bluetooth-secondary",
                    cursor_type="row",
                    zebra_stripes=True,
                )
            yield VerticalScroll(
                Static("", id="offline-detail", markup=True),
                id="offline-detail-scroll",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._configure_tables()
        self.query_one(OfflineFilterBar).set_kind(self._active)
        self.reload()

    def on_screen_resume(self) -> None:
        bar = self.query_one(OfflineFilterBar)
        bar.refresh_target_options()
        bar.refresh_catalog_class_options()
        self.reload()

    @property
    def active_bindings(self) -> dict[str, ActiveBinding]:
        focused = self.focused
        if focused is not None and focused.id == "offline-filter-text":
            return active_bindings_for_focus(self, self._table(self._active))
        return super().active_bindings

    def _configure_tables(self) -> None:
        caps = offline_column_caps()
        for kind in self._records:
            tables = self._tables_for_kind(kind)
            for table in tables:
                for key, label in _COLUMNS[kind]:
                    width = caps.get(kind, {}).get(key)
                    table.add_column(label, key=key, width=width)
                self._update_column_headers(kind, table=table)
            self._sync_kind_visibility(kind)
        self.set_class(self._active == "bluetooth", "-bt-active")

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
        self._detail_focus = None
        for kind in self._records:
            if kind == "bluetooth":
                self._render_bluetooth_tables()
            else:
                self._render_table(kind)
        self._sync_detail_panel()

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

    def action_open_catalog(self) -> None:
        from wifit3.ui.screens.catalog import open_catalog

        open_catalog(self)

    def action_assign_catalog_family(self) -> None:
        if self._active == "clients":
            self.notify(
                "Family assignment applies to access points and BT/BLE devices.",
                title="Catalog",
                severity="warning",
            )
            return
        table = self._table(self._active)
        identity = self._selected_identity(table, self._active)
        if identity is None:
            self.notify("Select a row first.", title="Catalog", severity="warning")
            return
        record = self._record_for_identity(self._active, identity)
        if record is None:
            return
        if self._active == "aps":
            subject = f"{record.get('ssid') or '‹hidden›'} · {record.get('bssid')}"
        else:
            subject = (
                f"{record.get('name') or '‹unknown›'} · {record.get('identifier')}"
            )
        from wifit3.ui.screens.catalog_assign_modal import CatalogAssignModal

        def _done(family_id: str | None) -> None:
            if family_id is None:
                return
            pinned = family_id.strip() or None
            if self._active == "aps":
                ok, message = self.app.ap_history_store.assign_catalog_family(
                    identity,
                    pinned,
                )
            else:
                ok, message = self.app.bluetooth_history_store.assign_catalog_family(
                    identity,
                    pinned,
                )
            if not ok:
                self.notify(message, title="Catalog", severity="warning")
                return
            self.reload()
            self.notify(message, title="Catalog")

        self.app.push_screen(CatalogAssignModal(subject=subject), _done)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._block_next_row_select:
            self._block_next_row_select = False
            return
        kind = self._kind_for_table(event.data_table)
        if kind is not None:
            self._apply_detail_from_row(kind, str(event.row_key.value))

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted,
    ) -> None:
        kind = self._kind_for_table(event.data_table)
        if kind is None or event.row_key is None:
            return
        self._apply_detail_from_row(kind, str(event.row_key.value))

    def _apply_detail_from_row(self, kind: str, row_key: str) -> None:
        if row_key.startswith("empty"):
            return
        identity: str | None = None
        if row_key.startswith(f"{kind}:"):
            identity = row_key.removeprefix(f"{kind}:")
        elif kind == "bluetooth" and row_key.startswith("bluetooth-secondary:"):
            identity = row_key.removeprefix("bluetooth-secondary:")
        if identity is None:
            return
        self._detail_focus = (kind, identity)
        if kind == self._active:
            self._sync_detail_panel()

    @on(Tabs.TabActivated, "#offline-tabs")
    def _tab_activated(self, event: Tabs.TabActivated) -> None:
        if event.tab is None or event.tab.id is None:
            return
        kind = event.tab.id.removeprefix("offline-tab-")
        if kind not in self._records:
            return
        self._active = kind
        self._detail_focus = None
        self.query_one(OfflineFilterBar).set_kind(kind)
        self.set_class(kind == "bluetooth", "-bt-active")
        for table_kind in self._records:
            self._sync_kind_visibility(table_kind, active=table_kind == kind)
        if kind == "bluetooth":
            self._render_bluetooth_tables()
            self._table("bluetooth").focus()
        else:
            self._render_table(kind)
            self._table(kind).focus()

    def on_offline_filter_bar_filter_changed(
        self, message: OfflineFilterBar.FilterChanged,
    ) -> None:
        self._filters = message.filters
        self._detail_focus = None
        if self._active == "bluetooth":
            self._render_bluetooth_tables()
        else:
            self._render_table(self._active)

    def _sync_detail_panel(self) -> None:
        panel = self.query_one("#offline-detail", Static)
        scroll = self.query_one("#offline-detail-scroll", VerticalScroll)
        if self._detail_focus is None or self._detail_focus[0] != self._active:
            scroll.border_title = ""
            panel.update("[dim]Select a row to inspect stored fields.[/dim]")
            return
        kind, identity = self._detail_focus
        record = self._record_for_identity(kind, identity)
        if record is None:
            panel.update("[dim]Record is no longer visible with the current filter.[/dim]")
            scroll.border_title = ""
            return
        scroll.border_title = _detail_title(kind, record)
        panel.update(_detail_panel_markup(kind, record))

    def _record_for_identity(
        self, kind: str, identity: str,
    ) -> dict[str, Any] | None:
        for record in self._records[kind]:
            if self._identity(kind, record) == identity:
                return record
        return None

    def _tables_for_kind(self, kind: str) -> list[DataTable]:
        if kind == "bluetooth":
            return [
                self.query_one("#offline-bluetooth", DataTable),
                self.query_one("#offline-bluetooth-secondary", DataTable),
            ]
        return [self._table(kind)]

    def _sync_kind_visibility(self, kind: str, *, active: bool | None = None) -> None:
        is_active = active if active is not None else kind == self._active
        if kind == "bluetooth":
            stack = self.query_one("#offline-bluetooth-stack")
            stack.display = is_active
            for table in self._tables_for_kind("bluetooth"):
                table.display = is_active
            separator = self.query_one(
                "#offline-bluetooth-secondary-separator", Static,
            )
            separator.display = False
        else:
            self._table(kind).display = is_active

    def _table_bluetooth_secondary(self) -> DataTable:
        return self.query_one("#offline-bluetooth-secondary", DataTable)

    def _bluetooth_row_key(self, identity: str, *, secondary: bool) -> str:
        prefix = "bluetooth-secondary" if secondary else "bluetooth"
        return f"{prefix}:{identity}"

    def _render_bluetooth_tables(self, *, selected_identity: str | None = None) -> None:
        main_table = self._table("bluetooth")
        secondary_table = self._table_bluetooth_secondary()
        main_table.clear()
        secondary_table.clear()
        self._table_map_urls = {
            key: value
            for key, value in self._table_map_urls.items()
            if not key.startswith("bluetooth:")
            and not key.startswith("bluetooth-secondary:")
        }
        all_records = self._records["bluetooth"]
        records = [
            record for record in all_records
            if record_matches(
                "bluetooth", record, self._filters, target_store=self.app.target_store,
            )
        ]
        sort_key, reverse = self._sort["bluetooth"]
        records.sort(
            key=lambda record: self._record_sort_value("bluetooth", record, sort_key),
            reverse=reverse,
        )
        main_records = [
            record for record in records
            if not offline_bluetooth_use_secondary_panel(record)
        ]
        secondary_records = [
            record for record in records
            if offline_bluetooth_use_secondary_panel(record)
        ]
        main_shown = self._fill_offline_bluetooth_table(
            main_table, main_records, secondary=False,
        )
        secondary_shown = self._fill_offline_bluetooth_table(
            secondary_table, secondary_records, secondary=True,
        )
        separator = self.query_one(
            "#offline-bluetooth-secondary-separator", Static,
        )
        secondary_table.display = self._active == "bluetooth" and bool(secondary_shown)
        separator.display = secondary_table.display
        main_table.border_title = (
            f"Known devices · rows {len(main_shown)}"
            if main_shown
            else ""
        )
        secondary_table.border_title = (
            f"Private / sparse IDs · rows {len(secondary_shown)}"
            if secondary_shown
            else ""
        )
        self._update_tab_label(
            "bluetooth",
            len(all_records),
            len(records),
            main_count=len(main_shown),
            secondary_count=len(secondary_shown),
        )
        for table in (main_table, secondary_table):
            self._update_column_headers("bluetooth", table=table)
            if isinstance(table, _OfflineDataTable):
                table._reclamp_capped_columns()
        self._bluetooth_empty_state(main_table, main_records, records, all_records)
        self._bluetooth_empty_state(
            secondary_table,
            secondary_records,
            records,
            all_records,
            secondary=True,
        )
        focus_table = main_table
        if selected_identity is not None:
            for table in (main_table, secondary_table):
                row_key = self._bluetooth_row_key(
                    selected_identity,
                    secondary=table is secondary_table,
                )
                try:
                    table.move_cursor(row=table.get_row_index(row_key))
                    focus_table = table
                    break
                except Exception:
                    continue
        if self._active == "bluetooth":
            identity = selected_identity or self._selected_identity(focus_table, "bluetooth")
            if identity is not None:
                self._detail_focus = ("bluetooth", identity)
            self._sync_detail_panel()

    def _bluetooth_empty_state(
        self,
        table: DataTable,
        panel_records: list[dict[str, Any]],
        filtered: list[dict[str, Any]],
        all_records: list[dict[str, Any]],
        *,
        secondary: bool = False,
    ) -> None:
        if panel_records:
            return
        if not all_records:
            if secondary:
                return
            cells = [
                Text("No saved records", style="italic dim"),
                Text("Start a scan later to populate this view", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS["bluetooth"]) - len(cells)))
            table.add_row(*cells, key="empty:bluetooth")
            return
        if not filtered:
            if secondary:
                return
            cells = [
                Text("No matches", style="italic dim"),
                Text("Relax the search or clear the filter text", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS["bluetooth"]) - len(cells)))
            table.add_row(*cells, key="empty-filter:bluetooth")
            return
        if secondary and filtered:
            cells = [
                Text("No sparse rows", style="italic dim"),
                Text("Filtered devices all have names or GATT", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS["bluetooth"]) - len(cells)))
            table.add_row(*cells, key="empty-secondary:bluetooth")

    def _fill_offline_bluetooth_table(
        self,
        table: DataTable,
        records: list[dict[str, Any]],
        *,
        secondary: bool,
    ) -> list[dict[str, Any]]:
        shown: list[dict[str, Any]] = []
        for record in records:
            identity = self._identity("bluetooth", record)
            row_key = self._bluetooth_row_key(identity, secondary=secondary)
            map_url = google_maps_search_url(self._signal_positions(record))
            if map_url is not None:
                self._table_map_urls[row_key] = map_url
            matched_target = match_offline_record(
                self.app.target_store, "bluetooth", record,
            )
            table.add_row(
                *self._target_tinted_row(
                    self._row_values(
                        "bluetooth",
                        record,
                        map_url is not None,
                        matched_target,
                    ),
                    matched_target,
                ),
                key=row_key,
            )
            if isinstance(table, _OfflineDataTable):
                table.set_service_tooltip(
                    row_key,
                    advertised_services_tooltip(
                        offline_bluetooth_device(record),
                    ),
                )
            shown.append(record)
        return shown

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
            row_key = f"{kind}:{identity}"
            map_url = google_maps_search_url(
                self._signal_positions(record),
                prefer_best=kind == "aps",
            )
            if map_url is not None:
                self._table_map_urls[row_key] = map_url
            matched_target = match_offline_record(self.app.target_store, kind, record)
            table.add_row(
                *self._target_tinted_row(
                    self._row_values(
                        kind, record, map_url is not None, matched_target,
                    ),
                    matched_target,
                ),
                key=row_key,
            )
        self._update_tab_label(kind, len(all_records), len(records))
        table.border_title = ""
        if not all_records:
            cells = [
                Text("No saved records", style="italic dim"),
                Text("Start a scan later to populate this view", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS[kind]) - len(cells)))
            table.add_row(*cells, key=f"empty:{kind}")
        elif not records:
            cells = [
                Text("No matches", style="italic dim"),
                Text("Relax the search or clear the filter text", style="dim"),
            ]
            cells.extend("" for _ in range(len(_COLUMNS[kind]) - len(cells)))
            table.add_row(*cells, key=f"empty-filter:{kind}")
        self._update_column_headers(kind)
        if isinstance(table, _OfflineDataTable):
            table._reclamp_capped_columns()
        if selected_identity is not None:
            try:
                table.move_cursor(
                    row=table.get_row_index(f"{kind}:{selected_identity}"),
                )
            except Exception:
                pass
        if kind == self._active:
            identity = selected_identity or self._selected_identity(table, kind)
            if identity is not None:
                self._detail_focus = (kind, identity)
            self._sync_detail_panel()

    @staticmethod
    def _target_tinted_row(
        cells: tuple[Any, ...],
        matched_target: Any,
    ) -> tuple[Any, ...]:
        if not is_target_entry(matched_target):
            return cells
        return tuple(_offline_target_cell(cell) for cell in cells)

    def _row_values(
        self,
        kind: str,
        record: dict[str, Any],
        has_map: bool,
        matched_target: Any = None,
    ) -> tuple[Any, ...]:
        position = Text(
            _record_position(
                record,
                prefer_best=kind == "aps",
                with_globe=has_map,
            ),
            style="cyan",
        )
        target_cell = target_group_cell(matched_target)
        if kind == "aps":
            return (
                Text(str(record.get("ssid") or "‹hidden›"), style="bold"),
                mac_address_text(str(record.get("bssid") or "·")),
                str(record.get("channel") or "·"),
                str(record.get("encryption") or "Unknown"),
                str(len(record.get("clients", []))),
                catalog_class_cell(record),
                catalog_family_cell(record),
                _session_label(record),
                Text(_timestamp(record.get("last_seen")), style="dim"),
                position,
                target_cell,
            )
        if kind == "clients":
            latest = self._latest_access_point(record)
            return (
                mac_address_text(str(record.get("client_mac") or "·"), style="bold"),
                str(record.get("access_point_count", 0)),
                str(latest.get("ssid") or "·"),
                mac_address_text(str(latest.get("bssid") or "·")),
                str(latest.get("channel") or "·"),
                _session_label(record),
                Text(_timestamp(record.get("last_seen")), style="dim"),
                position,
                target_cell,
            )
        return offline_bluetooth_row_cells(
            record,
            location_cell=position,
            target_cell=target_cell,
        )

    def on_data_table_header_selected(
        self, event: DataTable.HeaderSelected,
    ) -> None:
        kind = self._kind_for_table(event.data_table)
        key = str(event.column_key.value)
        if kind is None:
            return
        current_key, current_reverse = self._sort[kind]
        self._sort[kind] = (
            key,
            not current_reverse if current_key == key else False,
        )
        selected_identity = self._selected_identity(event.data_table, kind)
        if kind == "bluetooth":
            self._render_bluetooth_tables(selected_identity=selected_identity)
        else:
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
        for prefix in (f"{kind}:", f"{kind}-secondary:"):
            if row_key.startswith(prefix):
                return row_key.removeprefix(prefix)
        return None

    def _update_column_headers(
        self, kind: str, *, table: DataTable | None = None,
    ) -> None:
        targets = [table] if table is not None else self._tables_for_kind(kind)
        sort_key, reverse = self._sort[kind]
        arrow = "▼" if reverse else "▲"
        for target in targets:
            for key, label in _COLUMNS[kind]:
                suffix = f" {arrow}" if key == sort_key else ""
                target.columns[key].label = Text(f"{label}{suffix}")
            target.refresh()

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
        if kind == "bluetooth":
            value = offline_bluetooth_sort_value(record, key)
            return value not in (None, "", 0.0), value if value is not None else ""
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
        elif key == "catalog_class":
            value = catalog_class_cell(record).plain.removeprefix("·").strip()
        elif key == "catalog_family":
            value = catalog_family_cell(record).plain.removeprefix("◆").strip()
        elif key == "gatt_identity":
            value = format_gatt_identity_line(gatt_identity_parts(record))
        elif key == "session":
            value = record.get("session_name")
        elif key == "target":
            matched = match_offline_record(self.app.target_store, kind, record)
            value = matched.alias if matched is not None else ""
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

    def _update_tab_label(
        self,
        kind: str,
        total: int,
        shown: int,
        *,
        main_count: int | None = None,
        secondary_count: int | None = None,
    ) -> None:
        tab_id, base = _OFFLINE_TAB_LABELS[kind]
        if kind == "bluetooth" and main_count is not None and secondary_count is not None:
            body = f"{main_count:,}+{secondary_count:,}"
            if kind == self._active and shown != total:
                label = f"{base} ({body}/{total:,})"
            else:
                label = f"{base} ({body})"
        elif kind == self._active and shown != total:
            label = f"{base} ({shown:,}/{total:,})"
        else:
            label = f"{base} ({total:,})"
        self.query_one(f"#{tab_id}", Tab).label = label

    def _table(self, kind: str) -> DataTable:
        return self.query_one(f"#offline-{kind}", DataTable)

    def _kind_for_table(self, table: DataTable) -> str | None:
        if table.id in {"offline-bluetooth", "offline-bluetooth-secondary"}:
            return "bluetooth"
        for kind in self._records:
            if table.id == f"offline-{kind}":
                return kind
        return None


def _manual_catalog_family_id(kind: str, record: dict[str, Any]) -> str:
    if kind == "aps":
        caps = record.get("capabilities")
        if isinstance(caps, dict):
            return str(caps.get("catalog_family_id") or "").strip()
        return ""
    if kind == "bluetooth":
        catalog = record.get("catalog")
        if isinstance(catalog, dict):
            return str(catalog.get("family_id") or "").strip()
        return ""
    return ""


def _detail_title(kind: str, record: dict[str, Any]) -> str:
    if kind == "aps":
        label = str(record.get("ssid") or "‹hidden›")
        mac = str(record.get("bssid") or "")
    elif kind == "clients":
        label = str(record.get("client_mac") or "")
        mac = ""
    else:
        label = str(record.get("name") or "‹unknown›")
        mac = str(record.get("identifier") or "")
    if mac:
        return f"{label} · {mac}"
    return label


def _detail_panel_markup(kind: str, record: dict[str, Any]) -> str:
    manual = _manual_catalog_family_id(kind, record)
    if kind == "aps":
        from wifit3.ui.offline_ap_detail import offline_ap_detail_markup

        return offline_ap_detail_markup(
            record,
            manual_catalog_family_id=manual,
        )
    if kind == "clients":
        from wifit3.ui.offline_client_detail import offline_client_detail_markup

        return offline_client_detail_markup(record)
    if kind == "bluetooth":
        from wifit3.ui.offline_bluetooth_detail import offline_bluetooth_detail_markup

        return offline_bluetooth_detail_markup(
            record,
            manual_catalog_family_id=manual,
        )
    rows = [
        *catalog_expand_rows(record),
        *_flatten(record),
    ]
    manual = _manual_catalog_family_id(kind, record)
    if not rows and not manual:
        return "[dim]No extra fields stored for this record.[/dim]"
    lines: list[str] = []
    if manual:
        lines.append(
            f"[dim]Manual catalog family:[/dim] [cyan]{escape(manual)}[/cyan] "
            f"[dim]([bold]g[/bold] to change · Clear manual in picker)[/dim]",
        )
    for field, value in rows:
        text = str(value)
        if len(text) > 240:
            text = f"{text[:237]}…"
        lines.append(f"[dim]{escape(field)}:[/dim] [cyan]{escape(text)}[/cyan]")
    return "\n".join(lines)


def _offline_target_cell(cell: Any) -> Any:
    style = "bold red"
    if isinstance(cell, Text):
        painted = cell.copy()
        painted.stylize(style)
        return painted
    return Text(str(cell), style=style)


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

