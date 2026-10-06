import logging
import time
from dataclasses import replace
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult, RenderResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import Reactive
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, RichLog, Select, Static
from textual.widgets.data_table import ColumnKey
from textual.widgets._header import HeaderClock

from wifit3.ui.notification_center import WifiteHeader
from wifit3.ui.screens.confirm_active import (
    ConfirmEndScanModal,
    END_BLUETOOTH_SCAN_BODY,
)

from wifit3.bluetooth.gatt_metadata import display_model_label
from wifit3.bluetooth.assigned_numbers import manufacturer_label, service_label, service_name
from wifit3.bluetooth.classification import device_classification
from wifit3.models import BluetoothDevice
from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO
from wifit3.persist.config import Config
from wifit3.persist.targets import SavedTarget, TargetStoreError
from wifit3.targeting import (
    TargetCandidate,
    bluetooth_candidate,
    is_target_entry,
    is_whitelisted_entry,
    match_bluetooth_device,
)
from wifit3.ui.bluetooth_detail import (
    _is_anonymous_apple,
    advertised_services_tooltip,
    bluetooth_manufacturer_label,
    displayed_service_uuids,
    device_detail_lines,
)
from wifit3.ui.catalog_format import catalog_class_cell, catalog_family_cell
from wifit3.ui.mac_format import bluetooth_identifier_text
from wifit3.ui.search_input import SearchInput
from wifit3.ui.bluetooth_export import export_bluetooth_bundle
from wifit3.ui.location_format import format_position
from wifit3.ui.signal_bar import dbm_style
from wifit3.ui.target_filter import (
    bluetooth_matches_target_filter,
    build_target_select_options,
    refresh_target_select,
)
from wifit3.ui.target_markers import target_row_prefix, whitelist_row_prefix
from wifit3.ui.vault.global_tracker import GlobalJobTracker

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

logger = logging.getLogger(__name__)


# Keep in sync with ``scanner.STALE_DURATION_S`` (AP row dimming).
_AP_STALE_DURATION_S = 20.0
_BT_SCREEN_PERSISTENCE_FACTOR = 5
STALE_DURATION_S = _AP_STALE_DURATION_S * _BT_SCREEN_PERSISTENCE_FACTOR
_BT_EXPIRY_FACTOR = _BT_SCREEN_PERSISTENCE_FACTOR


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def _is_timeout_error(error: BaseException) -> bool:
    current: BaseException | None = error
    visited = set()
    while current is not None and id(current) not in visited:
        if isinstance(current, TimeoutError):
            return True
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _connection_error_message(error: BaseException) -> str:
    if _is_timeout_error(error):
        return (
            "BLE GATT connection timed out. The device may currently accept "
            "Bluetooth Classic only."
        )
    return str(error) or type(error).__name__


def _device_has_expired(device: BluetoothDevice, age: float) -> bool:
    expiry = Config.scanner_ap_expiry
    if expiry < 0:
        return False
    expiry *= _BT_EXPIRY_FACTOR
    named = device.name.strip().casefold() not in {"", "<unknown>", "unknown"}
    if CLASSIC_RADIO in device.radio_types and named:
        # Classic inquiry rows: keep named BT sightings longer (device may stop
        # answering inquiry while connected to a phone).
        expiry = max(expiry, 180.0 * _BT_EXPIRY_FACTOR)
    elif (
        BLE_RADIO in device.radio_types
        and CLASSIC_RADIO not in device.radio_types
        and named
    ):
        # BLE-only rows (mouse, keyboard, TV): advertising can be sparse while bonded.
        expiry = max(expiry, 120.0 * _BT_EXPIRY_FACTOR)
    return age >= expiry


def _short_identifier(identifier: str) -> str:
    if len(identifier) <= 18:
        return identifier
    return f"{identifier[:8]}…{identifier[-4:]}"


def _group_anonymous_apple_devices(devices: list[BluetoothDevice]) -> list[BluetoothDevice]:
    apple = [device for device in devices if _is_anonymous_apple(device)]
    if len(apple) < 2:
        return devices
    strongest = max(apple, key=lambda device: device.rssi)
    grouped = replace(
        strongest,
        identifier="approximate:apple:004c",
        name=f"Apple devices (~{len(apple)} IDs)",
        service_uuids=tuple(sorted({uuid for device in apple for uuid in device.service_uuids})),
        service_data_uuids=tuple(
            sorted({uuid for device in apple for uuid in device.service_data_uuids})
        ),
        manufacturer_data_bytes=max(device.manufacturer_data_bytes for device in apple),
        service_data_bytes=max(device.service_data_bytes for device in apple),
        advertisement_count=sum(device.advertisement_count for device in apple),
        advertisement_interval=None,
        first_seen=min(device.first_seen for device in apple),
        last_seen=max(device.last_seen for device in apple),
        approximate_group=True,
        group_size=len(apple),
    )
    apple_ids = {device.identifier for device in apple}
    result = []
    inserted = False
    for device in devices:
        if device.identifier in apple_ids:
            if not inserted:
                result.append(grouped)
                inserted = True
        else:
            result.append(device)
    return result


class _BluetoothScanTable(DataTable):
    """DataTable that can move the cursor without scrolling the viewport."""

    _suppress_scroll: bool = False

    def __init__(self, *args, **kwargs) -> None:
        self._service_tooltips: dict[str, str] = {}
        super().__init__(*args, **kwargs)

    def set_service_tooltip(self, row_key: str, value: str) -> None:
        self._service_tooltips[row_key] = value

    def remove_row(self, row_key) -> None:
        self._service_tooltips.pop(str(getattr(row_key, "value", row_key)), None)
        super().remove_row(row_key)

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

    def _scroll_cursor_into_view(self, animate: bool = False) -> None:
        if self._suppress_scroll:
            return
        super()._scroll_cursor_into_view(animate=animate)

    def pin_cursor_row(self, row: int) -> None:
        self._suppress_scroll = True
        self.move_cursor(row=row, animate=False)
        self.call_after_refresh(self._release_scroll)

    def _release_scroll(self) -> None:
        self._suppress_scroll = False


class _BluetoothSortReadout(HeaderClock):
    """Header right slot showing the active BLE table sort."""

    DEFAULT_CSS = "_BluetoothSortReadout { width: auto; }"
    summary: Reactive[str] = Reactive("", layout=True)

    def render(self) -> RenderResult:
        body = (self.summary or "").strip()
        if body:
            return Text(f"{body}  |  ")
        return Text("")


class _BluetoothScannerHeader(WifiteHeader):
    def __init__(self) -> None:
        super().__init__(show_clock=False, trailing=_BluetoothSortReadout)


class BluetoothScannerView(Screen):
    """Nearby BLE and Classic devices observed through system and USB adapters."""

    app: "WifiteApp"

    BINDINGS = [
        # Some terminals report Shift+L as the printable uppercase key instead
        # of the modifier chord. Accept both representations.
        Binding("escape", "back_to_wifi", "Exit"),
        Binding("enter", "connect", "Focus", show=False, priority=True),
        Binding("s", "cycle_sort", "Sort Col"),
        Binding("o", "toggle_sort_dir", "Sort Asc/Desc"),
        Binding("n", "targets_editor", "Targets"),
        Binding("x", "export_scan", "Export"),
        Binding("f", "focus_filter", "Filter"),
        Binding("y", "open_catalog", "Catalog"),
        Binding("ctrl+l", "toggle_log", "Toggle Log"),
    ]

    CSS = """
    #bluetooth-filters { height: 3; padding: 0 1; }
    #bluetooth-filter-power { width: 14; margin-right: 1; }
    #bluetooth-filter-type { width: 14; margin-right: 1; }
    #bluetooth-filter-target { width: 18; margin-right: 1; }
    #bluetooth-filter-text { width: 1fr; }
    #bluetooth-filter-text.-has-text { background: $surface-darken-2; }
    #bluetooth-scan-stack { height: 1fr; }
    #bluetooth-table { height: 2fr; }
    #bluetooth-private-separator { height: 1; background: $primary-darken-1; margin: 0 1; }
    #bluetooth-private-table { height: 1fr; min-height: 5; }
    #bluetooth-log { height: 15; min-height: 15; }
    """

    _COLUMNS = [
        ("name", "DEVICE"),
        ("model", "MODEL"),
        ("catalog_class", "CLASS"),
        ("catalog_family", "FAMILY"),
        ("category", "RADIO / TYPE"),
        ("manufacturer", "MANUFACTURER"),
        ("rssi", "POWER"),
        ("advertisements", "#ADV"),
        ("interval", "LATEST GAP"),
        ("first_seen", "FIRST SEEN"),
        ("last_seen", "LAST SEEN"),
        ("services", "ADVERTISED SERVICES"),
        ("identifier", "ADDRESS / ID"),
        ("location", "GPS"),
    ]
    _COLUMN_WIDTHS = {
        "name": 22,
        "model": 8,
        "catalog_class": 16,
        "catalog_family": 22,
        "rssi": 8,
        "category": 30,
        "advertisements": 8,
        "interval": 10,
        "first_seen": 10,
        "last_seen": 10,
        "manufacturer": 20,
        "services": 23,
        "identifier": 17,
        "location": 25,
    }

    def __init__(self) -> None:
        super().__init__()
        self._rows: dict[str, tuple] = {}
        self._devices: dict[str, BluetoothDevice] = {}
        self._private_rows: dict[str, tuple] = {}
        self._private_devices: dict[str, BluetoothDevice] = {}
        self._sort_idx = next(
            idx for idx, (key, _label) in enumerate(self._COLUMNS) if key == "first_seen"
        )
        self._sort_reverse = True
        self._filter_text = ""
        self._min_signal = -100
        self._category = "All"
        self._target_filter_id = ""
        self._target_navigation_pending = False
        self._logged_device_models: set[str] = set()
        self._last_enrichment_key: tuple | None = None
        self._model_column_width = self._COLUMN_WIDTHS["model"]
        self._last_sort_time: float = 0.0

    def compose(self) -> ComposeResult:
        yield _BluetoothScannerHeader()
        with Vertical():
            with Horizontal(id="bluetooth-filters"):
                yield Select(
                    [("Any power", -100), ("≥ -80 dBm", -80), ("≥ -70 dBm", -70),
                     ("≥ -60 dBm", -60), ("≥ -50 dBm", -50)],
                    value=-100, allow_blank=False, compact=True,
                    id="bluetooth-filter-power",
                )
                yield Select(
                    [(category, category) for category in (
                        "All", "Audio", "Wearable", "Input", "Beacon", "Health",
                        "Phone", "Computer", "Network", "Sensor", "Display",
                        "Appliance", "Vehicle", "Ambiguous", "Other", "Unknown",
                    )],
                    value="All", allow_blank=False, compact=True,
                    id="bluetooth-filter-type",
                )
                yield Select(
                    build_target_select_options(None),
                    value="",
                    allow_blank=False,
                    compact=True,
                    id="bluetooth-filter-target",
                )
                yield SearchInput(
                    placeholder="device, manufacturer, service, family, address…",
                    compact=True,
                    id="bluetooth-filter-text",
                )
            with Vertical(id="bluetooth-scan-stack"):
                table = _BluetoothScanTable(cursor_type="row", id="bluetooth-table")
                for key, label in self._COLUMNS:
                    table.add_column(label, key=key, width=self._COLUMN_WIDTHS[key])
                yield table
                yield Static("", id="bluetooth-private-separator")
                private_table = _BluetoothScanTable(
                    cursor_type="row", id="bluetooth-private-table",
                )
                for key, label in self._COLUMNS:
                    private_table.add_column(
                        label, key=key, width=self._COLUMN_WIDTHS[key],
                    )
                yield private_table
            yield RichLog(id="bluetooth-log", markup=True, highlight=True)
        yield GlobalJobTracker()
        yield Footer()

    def on_mount(self) -> None:
        refresh_target_select(
            self.query_one("#bluetooth-filter-target", Select),
            getattr(self.app, "target_store", None),
        )
        self._update_column_headers()
        self._update_sort_readout()
        self.query_one("#bluetooth-table", DataTable).focus()
        self.query_one("#bluetooth-log", RichLog).write(
            (
                "[bold green]Bluetooth Classic USB + system BLE scanners initialized[/bold green]\n"
                if (
                    self.app.bluetooth_manager.is_usb_scanning
                    and self.app.bluetooth_manager.is_os_ble_scanning
                )
                else (
                    "[bold green]Bluetooth USB HCI scanner initialized[/bold green]\n"
                    if self.app.bluetooth_manager.is_usb_scanning
                    else "[bold green]Bluetooth LE scanner initialized[/bold green]\n"
                )
            )
            + "[dim]The RADIO marker distinguishes Classic BT from BLE observations.[/dim]\n"
            + "[dim]Use BT/BLE Scan with OS BLE enabled on splash - the dongle alone misses "
            "most BLE devices (mouse, keyboard, TV).[/dim]\n"
            + "[dim]Your Mac’s own mouse/keyboard often do not appear while connected to "
            "this computer (no public advertisements). Disconnect or use pairing mode "
            "to see them.[/dim]\n"
            + "[dim]Speakers (e.g. Vieta Pro): pairing mode, not connected to phone; "
            "they show as [bold]BT[/bold] (Classic), not BLE - confirm the name appears "
            "in macOS System Settings → Bluetooth, then watch USB inquiry in the title. "
            "Filter: “Any power”.[/dim]\n"
            + "[dim]Table title shows live source health (OS BLE + USB inquiry).[/dim]\n"
            + "[dim]USB lab: Shift+L on a row (Ctrl+L toggles this log).[/dim]"
        )
        self.set_interval(0.2, self.refresh_table)
        # The passive model-enrichment sweep only runs while this screen is live.
        self.app.bluetooth_manager.resume_device_information_sweep()

    def on_screen_resume(self) -> None:
        # Returning from Focus/Lab re-enables passive model enrichment.
        self.app.bluetooth_manager.resume_device_information_sweep()

    async def on_screen_suspend(self) -> None:
        # Entering Focus/Lab (or leaving the scanner) stops enrichment immediately.
        await self.app.bluetooth_manager.pause_device_information_sweep()

    async def on_unmount(self) -> None:
        await self.app.bluetooth_manager.pause_device_information_sweep()

    def refresh_table(self) -> None:
        if self.app.screen is not self:
            return
        self._maybe_auto_lock_target()
        main_table = self.query_one("#bluetooth-table", DataTable)
        private_table = self.query_one("#bluetooth-private-table", DataTable)
        now = time.time()
        discovered = [
            device for device in self.app.bluetooth_manager.devices()
            if not _device_has_expired(device, now - device.last_seen)
            and self._matches_filter(device)
        ]
        main_list = [device for device in discovered if not _is_anonymous_apple(device)]
        private_list = [device for device in discovered if _is_anonymous_apple(device)]
        main_visible = {device.identifier: device for device in main_list}
        private_visible = {device.identifier: device for device in private_list}

        manager = self.app.bluetooth_manager
        health = manager.hci_health
        parts: list[str] = []
        if manager.is_os_ble_scanning:
            parts.append(
                f"OS BLE · packets {manager.observations_by_radio[BLE_RADIO]}"
            )
        if health is not None and manager.is_usb_scanning:
            parts.append(
                f"USB · Classic {health.classic_observations} · "
                f"inquiry {health.inquiry_completions} · HCI BLE {health.ble_observations}"
            )
        elif manager.is_usb_scanning:
            parts.append("USB HCI active")
        model_segment = self._enrichment_title_segment(manager)
        if parts:
            main_table.border_title = (
                " · ".join(parts) + f" · rows {len(main_visible)}{model_segment}"
            )
        elif manager.is_os_ble_scanning:
            main_table.border_title = (
                f"OS BLE · packets {manager.observations_by_radio[BLE_RADIO]} · "
                f"rows {len(main_visible)}{model_segment}"
            )
        else:
            main_table.border_title = ""
        private_table.border_title = (
            f"Private / rotating IDs · rows {len(private_visible)}"
        )
        private_table.display = bool(private_visible)
        self.query_one("#bluetooth-private-separator", Static).display = bool(
            private_visible,
        )
        self._log_enrichment_status(manager)
        self._sync_device_table(
            main_table,
            main_visible,
            self._rows,
            self._devices,
            now,
            show_detail_when_first=True,
        )
        self._sync_model_column_width(main_table, main_visible)
        self._sync_device_table(
            private_table,
            private_visible,
            self._private_rows,
            self._private_devices,
            now,
            show_detail_when_first=False,
        )
        self._sync_model_column_width(private_table, private_visible)
        if self._should_sort():
            self._apply_sort(scroll_to_cursor=False)

    def _sync_device_table(
        self,
        table: DataTable,
        visible: dict[str, BluetoothDevice],
        rows: dict[str, tuple],
        devices: dict[str, BluetoothDevice],
        now: float,
        *,
        show_detail_when_first: bool,
    ) -> None:
        for identifier in set(rows) - set(visible):
            try:
                table.remove_row(identifier)
            except Exception:
                pass
            rows.pop(identifier, None)
            devices.pop(identifier, None)
        for identifier, device in visible.items():
            devices[identifier] = device
            if isinstance(table, _BluetoothScanTable):
                table.set_service_tooltip(
                    identifier,
                    advertised_services_tooltip(device),
                )
            self._log_learned_model(device)
            values = self._row_values(device, now)
            previous = rows.get(identifier)
            if previous is None:
                table.add_row(*values, key=identifier)
                rows[identifier] = values
                if show_detail_when_first and table.row_count == 1:
                    self._show_device_details(device)
            elif previous != values:
                for (key, _label), value in zip(self._COLUMNS, values):
                    table.update_cell(identifier, key, value)
                rows[identifier] = values

    def _sync_model_column_width(
        self,
        table: DataTable,
        visible: dict[str, BluetoothDevice],
    ) -> None:
        header_width = len("MODEL")
        if visible:
            max_field = max(
                len(display_model_label(device) or "")
                for device in visible.values()
            )
        else:
            max_field = 1
        width = max(8, header_width + 1, max_field)
        if width == self._model_column_width:
            return
        self._model_column_width = width
        self._COLUMN_WIDTHS["model"] = width
        table.columns[ColumnKey("model")].width = width

    def _enrichment_title_segment(self, manager) -> str:
        getter = getattr(manager, "_enrichment_unavailable_reason", None)
        if getter is None:
            return ""
        reason = getter()
        if reason:
            return " · models OFF"
        return f" · models {manager.enrichment_successes}/{manager.enrichment_attempts}"

    def _log_enrichment_status(self, manager) -> None:
        reason = getattr(manager, "_enrichment_unavailable_reason", None)
        if reason is None:
            return
        # Log when sweep availability or success count changes (not every failure).
        key = (reason(), getattr(manager, "enrichment_successes", 0))
        if key == getattr(self, "_last_enrichment_key", None):
            return
        self._last_enrichment_key = key
        self.query_one("#bluetooth-log", RichLog).write(
            f"[dim]{escape(manager.device_information_status())}[/dim]"
        )

    def _log_learned_model(self, device: BluetoothDevice) -> None:
        if not device.model_number:
            return
        if device.identifier in self._logged_device_models:
            return
        self._logged_device_models.add(device.identifier)
        extras = [
            part
            for part in (
                f"fw {device.firmware_revision}" if device.firmware_revision else "",
                f"hw {device.hardware_revision}" if device.hardware_revision else "",
                f"sw {device.software_revision}" if device.software_revision else "",
            )
            if part
        ]
        suffix = f"  [dim]({', '.join(extras)})[/dim]" if extras else ""
        name = device.name if device.name != "<Unknown>" else device.identifier
        model_label = display_model_label(device)
        self.query_one("#bluetooth-log", RichLog).write(
            f"[bold cyan]Model learned[/bold cyan] {escape(name)} → "
            f"[bold]{escape(model_label)}[/bold]{suffix}"
        )

    def _scan_tables(self) -> tuple[DataTable, DataTable]:
        return (
            self.query_one("#bluetooth-table", DataTable),
            self.query_one("#bluetooth-private-table", DataTable),
        )

    def _update_column_headers(self) -> None:
        sort_key, _ = self._COLUMNS[self._sort_idx]
        arrow = "▼" if self._sort_reverse else "▲"
        for table in self._scan_tables():
            for key, label in self._COLUMNS:
                if key in {"rssi", "advertisements", "interval", "first_seen", "last_seen"}:
                    text = f"{arrow} {label}" if key == sort_key else f"  {label}"
                    table.columns[key].label = Text(text, justify="right")
                else:
                    text = f"{label} {arrow}" if key == sort_key else f"{label}  "
                    table.columns[key].label = Text(text)

    def _sort_summary(self) -> str:
        _key, label = self._COLUMNS[self._sort_idx]
        direction = ">" if self._sort_reverse else "<"
        return f"Sorted: {label} ({direction})"

    def _update_sort_readout(self) -> None:
        self.query_one(_BluetoothSortReadout).summary = self._sort_summary()

    def _announce_sort(self) -> None:
        _key, label = self._COLUMNS[self._sort_idx]
        direction = "descending" if self._sort_reverse else "ascending"
        self.notify(f"Sorted by {label} {direction}", title="Sort changed")
        self._update_sort_readout()

    def _should_sort(self) -> bool:
        delay = Config.scanner_sort_delay
        if delay < 0:
            return False
        return (time.time() - self._last_sort_time) >= delay

    def _apply_sort(self, *, scroll_to_cursor: bool = True) -> None:
        self._last_sort_time = time.time()
        focused = self._focused_scan_table()
        for table, devices in (
            (self._scan_tables()[0], self._devices),
            (self._scan_tables()[1], self._private_devices),
        ):
            is_focused = table is focused
            self._apply_sort_to_table(
                table,
                devices,
                scroll_to_cursor=scroll_to_cursor and is_focused,
                restore_cursor=is_focused or scroll_to_cursor,
            )

    def _apply_sort_to_table(
        self,
        table: DataTable,
        devices: dict[str, BluetoothDevice],
        *,
        scroll_to_cursor: bool = True,
        restore_cursor: bool = True,
    ) -> None:
        if table.row_count == 0:
            return
        try:
            selected_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            cursor_row = table.cursor_coordinate.row
        except Exception:
            selected_key = None
            cursor_row = None
        sort_key, _ = self._COLUMNS[self._sort_idx]
        reverse = self._sort_reverse
        devices_by_cell = {}
        for identifier, device in devices.items():
            try:
                devices_by_cell[id(table.get_cell(identifier, sort_key))] = device
            except Exception:
                continue

        def sort_value(cells: tuple[Text, Text]) -> tuple:
            value_cell, identifier_cell = cells
            device = devices_by_cell.get(id(value_cell))
            value = value_cell.plain.strip()
            is_empty = value in {"", "·", "‹unnamed›"}
            if sort_key == "first_seen" and device is not None:
                normalized: int | float | str = -device.first_seen
                is_empty = False
            elif sort_key == "last_seen" and device is not None:
                normalized = -device.last_seen
                is_empty = False
            elif is_empty:
                normalized = 0
            elif sort_key == "rssi":
                normalized = int(value.split()[0])
            elif sort_key in {"advertisements", "interval"}:
                normalized = int(value.split()[0])
            elif sort_key in {"first_seen", "last_seen"}:
                normalized = 0
            else:
                normalized = value.casefold()
            tiebreak = (
                device.identifier.casefold()
                if device is not None
                else identifier_cell.plain.casefold()
            )
            return (int(is_empty != reverse), normalized, tiebreak)

        table.sort(sort_key, "identifier", key=sort_value, reverse=reverse)
        if not restore_cursor or selected_key is None:
            return
        try:
            new_row = table.get_row_index(selected_key)
        except Exception:
            return
        if cursor_row is not None and new_row == cursor_row:
            return
        if scroll_to_cursor:
            table.move_cursor(row=new_row, animate=False)
        elif isinstance(table, _BluetoothScanTable):
            table.pin_cursor_row(new_row)

    def action_cycle_sort(self) -> None:
        self._sort_idx = (self._sort_idx + 1) % len(self._COLUMNS)
        self._update_column_headers()
        self._apply_sort()
        self._announce_sort()

    @on(DataTable.HeaderSelected, "#bluetooth-table, #bluetooth-private-table")
    def sort_from_header(self, event: DataTable.HeaderSelected) -> None:
        """Select a sort column with a mouse click or terminal touch."""
        key = str(event.column_key.value)
        index = next(
            (index for index, (column_key, _label) in enumerate(self._COLUMNS)
             if column_key == key),
            None,
        )
        if index is None:
            return
        if index == self._sort_idx:
            self.action_toggle_sort_dir()
            return
        self._sort_idx = index
        self._sort_reverse = False
        self._update_column_headers()
        self._apply_sort()
        self._announce_sort()

    def action_toggle_sort_dir(self) -> None:
        self._sort_reverse = not self._sort_reverse
        self._update_column_headers()
        self._apply_sort()
        self._announce_sort()

    def _row_values(self, device: BluetoothDevice, now: float) -> tuple:
        age = max(0.0, now - device.last_seen)
        first_age = max(0.0, now - device.first_seen)
        is_stale = age > STALE_DURATION_S
        manufacturer = bluetooth_manufacturer_label(device)
        classification = device_classification(device)
        all_services = displayed_service_uuids(device)
        service_names = [service_name(uuid) for uuid in all_services]
        last_seen = "now" if age < 1 else f"{int(age)}s ago"
        first_seen = "now" if first_age < 1 else f"{int(first_age)}s ago"
        name = device.name
        name_cell = Text(no_wrap=True)
        if device.approximate_group:
            name_cell.append("≈ ", style="yellow bold")
        if name == "<Unknown>":
            name_cell.append("‹unnamed›", style="dim italic")
        else:
            name_cell.append(_clip(name, 22), style="bold")
        if device.signature_watch or device.catalog_attention:
            name_cell = Text("◆ ", style="bold yellow") + name_cell
        if device.baseline_status == "new":
            name_cell = Text("+ ", style="bold cyan") + name_cell
        elif device.baseline_status == "changed":
            name_cell = Text("Δ ", style="bold yellow") + name_cell
        advertisements_cell = Text(
            str(device.advertisement_count), style="bold", justify="right", no_wrap=True,
        )
        interval_cell = Text(
            f"{device.advertisement_interval * 1000:.0f} ms"
            if device.advertisement_interval is not None else "·",
            style="dim",
            justify="right",
            no_wrap=True,
        )
        first_seen_cell = Text(first_seen, style="dim", justify="right", no_wrap=True)
        last_seen_cell = Text(last_seen, style="dim", justify="right", no_wrap=True)
        manufacturer_cell = Text(
            _clip(manufacturer, 24) if manufacturer else "·",
            style="" if manufacturer else "dim",
            no_wrap=True,
        )
        services_cell = Text(no_wrap=True)
        for index, service in enumerate(service_names[:2]):
            if index:
                services_cell.append("  ·  ", style="dim")
            services_cell.append(_clip(service, 18))
        if len(service_names) > 2:
            services_cell.append(f"  +{len(service_names) - 2}", style="cyan")
        if not service_names:
            services_cell.append("·", style="dim")
        services_cell.truncate(self._COLUMN_WIDTHS["services"], overflow="ellipsis")
        if device.approximate_group:
            identifier_cell = Text(
                f"≈ {device.group_size} rotating IDs",
                style="dim",
                no_wrap=True,
            )
        else:
            identifier_cell = bluetooth_identifier_text(
                device,
                shortener=_short_identifier,
            )
        signal_cell = Text(
            f"{device.rssi} dBm", style=dbm_style(device.rssi), justify="right",
        )
        model_text = display_model_label(device)
        model_cell = Text(
            model_text if model_text else "·",
            style="bold" if model_text else "dim",
            no_wrap=False,
        )
        category_cell = Text(no_wrap=True)
        category_cell.append(
            f"{device.radio_label} {classification.detail}",
            style="cyan",
        )
        category_cell.truncate(self._COLUMN_WIDTHS["category"], overflow="ellipsis")
        class_cell = catalog_class_cell(device)
        family_cell = catalog_family_cell(device)
        cells = [
            name_cell,
            model_cell,
            class_cell,
            family_cell,
            category_cell,
            manufacturer_cell,
            signal_cell,
            advertisements_cell,
            interval_cell,
            first_seen_cell,
            last_seen_cell,
            services_cell,
            identifier_cell,
            Text(
                format_position(device.positions),
                style="" if device.positions else "dim",
                no_wrap=True,
            ),
        ]
        if is_stale:
            for cell in cells:
                cell.stylize("dim")
        matched = None
        if not device.approximate_group:
            store = getattr(self.app, "target_store", None)
            if store is not None:
                matched = match_bluetooth_device(store, device)
                if matched is not None:
                    self.app.record_target_sighting(
                        matched,
                        f"Bluetooth {device.name or device.identifier}",
                    )
        if is_target_entry(matched):
            marked = target_row_prefix()
            marked.append_text(cells[0])
            cells[0] = marked
        elif is_whitelisted_entry(matched):
            marked = whitelist_row_prefix()
            marked.append_text(cells[0])
            cells[0] = marked
        return tuple(cells)

    def _matches_filter(self, device: BluetoothDevice) -> bool:
        store = getattr(self.app, "target_store", None)
        if not bluetooth_matches_target_filter(store, device, self._target_filter_id):
            return False
        if device.rssi < self._min_signal:
            return False
        classification = device_classification(device)
        category = classification.category
        if self._category != "All" and category != self._category:
            return False
        services = set(device.service_uuids) | set(device.service_data_uuids)
        searchable = " ".join((
            device.name,
            device.identifier,
            manufacturer_label(device.manufacturer_ids, device.identifier),
            category,
            classification.detail,
            classification.source,
            device.hardware_vendor,
            device.hardware_product,
            device.modalias,
            device.radio_label,
            device.decode_state,
            device.protocol_type,
            device.catalog_class,
            device.catalog_live,
            device.catalog_attention,
            " ".join(device.catalog_labels),
            *(service_label(uuid) for uuid in services),
        )).casefold()
        return all(token in searchable for token in self._filter_text.casefold().split())

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        if event.data_table.id not in {"bluetooth-table", "bluetooth-private-table"}:
            return
        key = str(event.row_key.value)
        device = self._devices.get(key) or self._private_devices.get(key)
        if device is not None:
            self._show_device_details(device)

    def _show_device_details(self, device: BluetoothDevice) -> None:
        log = self.query_one("#bluetooth-log", RichLog)
        log.clear()
        hint = getattr(
            self.app.bluetooth_manager, "device_information_hint", None,
        )
        for line in device_detail_lines(
            device,
            apple_expanded=_is_anonymous_apple(device),
            device_information_hint=hint,
        ):
            log.write(line)

    def _focused_scan_table(self) -> DataTable:
        focused = self.focused
        if isinstance(focused, DataTable) and focused.id == "bluetooth-private-table":
            return focused
        return self.query_one("#bluetooth-table", DataTable)

    def _selected_device(self) -> BluetoothDevice | None:
        table = self._focused_scan_table()
        if table.row_count == 0:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None
        identifier = str(key)
        device = self._devices.get(identifier) or self._private_devices.get(identifier)
        if device is not None:
            return device
        for candidate in self.app.bluetooth_manager.devices():
            if candidate.identifier == identifier:
                return candidate
        return None


    def action_connect(self) -> None:
        device = self._selected_device()
        if device is None:
            return
        if device.approximate_group:
            self.notify("Expand the Apple group and select one identifier first.", severity="warning")
            return
        if not device.is_connectable_with_bleak:
            self.app.bluetooth_manager.select_classic_focus(device.identifier)
            self.app.push_screen("bluetooth-focus")
            return
        self.connect_device(device)

    def action_targets_editor(self) -> None:
        device = self._selected_device()
        if device is None:
            self.app.open_targets_editor()
            return
        if device.approximate_group:
            self.notify(
                "Expand the approximate group and select one identifier first.",
                severity="warning",
            )
            return
        self.app.open_targets_editor(prefill=bluetooth_candidate(device))

    def _maybe_auto_lock_target(self) -> None:
        if (
            self._target_navigation_pending
            or self.app.locked_target is not None
            or not self.app.auto_lock_armed
            or not Config.auto_lock_targets
        ):
            return
        matches = []
        for device in self.app.bluetooth_manager.devices():
            if device.approximate_group or not device.is_connectable_with_bleak:
                continue
            target = match_bluetooth_device(self.app.target_store, device)
            if is_target_entry(target):
                matches.append((device.first_seen, target, device))
        if matches:
            _seen, target, device = min(matches, key=lambda item: item[0])
            self.lock_target(target, bluetooth_candidate(device), device)

    @work(exclusive=True, group="bluetooth-target-lock")
    async def lock_target(
        self,
        target: SavedTarget,
        candidate: TargetCandidate,
        device: BluetoothDevice,
    ) -> None:
        self._target_navigation_pending = True
        try:
            self.app.target_store.update_member_missing(
                target,
                medium=candidate.medium,
                kind=candidate.kind,
                identifier=candidate.identifier,
                details=candidate.details,
                match_mode=candidate.match_mode,
            )
            if not device.is_connectable_with_bleak:
                self.app.bluetooth_manager.select_classic_focus(device.identifier)
                self.app.push_screen("bluetooth-focus")
                return
            if not self.app.mark_target_locked(target):
                return
            self.app.bluetooth_manager.select_focus(device.identifier)
            self.app.start_bluetooth_target_capture(target, device)
            await self.app.bluetooth_manager.stop()
            log = self.query_one("#bluetooth-log", RichLog)
            log.clear()
            log.write(
                f"[bold cyan]Connecting locked target {escape(target.alias)}…[/bold cyan]"
            )
            try:
                await self.app.bluetooth_manager.connect(device)
            except Exception as exc:
                self.app.stop_bluetooth_target_capture()
                if await self._open_classic_timeout_fallback(device, exc, log):
                    return
                message = _connection_error_message(exc)
                self.app.bluetooth_manager.select_focus(device.identifier, error=message)
                log.write(
                    f"[bold yellow]GATT unavailable:[/bold yellow] {escape(message)}\n"
                    "[cyan]Opening locked target in observation mode.[/cyan]"
                )
                try:
                    await self.app.bluetooth_manager.resume_scan()
                except Exception:
                    pass
                self.notify(
                    "GATT is unavailable; opened Focus with discovery data.",
                    title="Bluetooth observation mode",
                    severity="warning",
                )
                self.app.push_screen("bluetooth-focus")
                return
            self.app.push_screen("bluetooth-focus")
        except TargetStoreError as exc:
            self.notify(str(exc), title="Targets", severity="error")
        finally:
            self._target_navigation_pending = False

    @work(exclusive=True)
    async def connect_device(self, device: BluetoothDevice) -> None:
        log = self.query_one("#bluetooth-log", RichLog)
        log.clear()
        log.write(f"[bold cyan]Connecting to {escape(device.name)}…[/bold cyan]")
        self.app.bluetooth_manager.select_focus(device.identifier)
        await self.app.bluetooth_manager.stop()
        try:
            await self.app.bluetooth_manager.connect(device)
        except Exception as exc:
            if await self._open_classic_timeout_fallback(device, exc, log):
                return
            message = _connection_error_message(exc)
            self.app.bluetooth_manager.select_focus(device.identifier, error=message)
            log.write(
                f"[bold yellow]GATT unavailable:[/bold yellow] {escape(message)}\n"
                "[cyan]Opening device Focus in observation mode.[/cyan]"
            )
            try:
                await self.app.bluetooth_manager.resume_scan()
            except Exception:
                pass
            self.notify(
                "GATT is unavailable; opened Focus with discovery data and Device Lab access.",
                title="Bluetooth observation mode",
                severity="warning",
            )
            self.app.push_screen("bluetooth-focus")
            return
        self.app.push_screen("bluetooth-focus")

    async def _open_classic_timeout_fallback(
        self,
        device: BluetoothDevice,
        error: BaseException,
        log: RichLog,
    ) -> bool:
        if not _is_timeout_error(error):
            return False
        classic = self.app.bluetooth_manager.classic_focus_fallback(device)
        if classic is None:
            return False
        try:
            await self.app.bluetooth_manager.resume_scan()
        except Exception as exc:
            logger.debug("Could not resume Classic scan after BLE timeout", exc_info=True)
            self.notify(
                str(exc) or type(exc).__name__,
                title="Bluetooth scan failed",
                severity="error",
            )
            return False
        self.app.bluetooth_manager.select_classic_focus(classic.identifier)
        log.write(
            "[bold yellow]BLE GATT timed out; opening read-only "
            "Classic/SDP mode in unified Bluetooth Focus.[/bold yellow]"
        )
        self.notify(
            "BLE GATT timed out. Switched the unified focus to Classic/SDP mode.",
            title="Bluetooth Classic",
            severity="warning",
        )
        self.app.push_screen("bluetooth-focus")
        return True

    def action_toggle_log(self) -> None:
        log = self.query_one("#bluetooth-log", RichLog)
        log.display = not log.display

    def action_export_scan(self) -> None:
        devices = self.app.bluetooth_manager.devices()
        if not devices:
            self.notify("No Bluetooth devices to export", severity="warning")
            return
        try:
            paths = list(export_bluetooth_bundle(devices))
        except OSError as exc:
            self.notify(str(exc), title="Export failed", severity="error")
            return
        self.notify(
            ", ".join(path.suffix.lstrip(".").upper() for path in paths),
            title="Bluetooth scan exported",
            timeout=8,
        )

    def action_focus_filter(self) -> None:
        self.query_one("#bluetooth-filter-text", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "bluetooth-filter-text":
            self._filter_text = event.value
            self.refresh_table()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "bluetooth-filter-power":
            self._min_signal = int(event.value)
        elif event.select.id == "bluetooth-filter-target":
            self._target_filter_id = str(event.value or "")
            self.refresh_table()
        elif event.select.id == "bluetooth-filter-type":
            self._category = str(event.value)
        else:
            return
        self.refresh_table()

    def action_open_catalog(self) -> None:
        from wifit3.ui.screens.catalog import open_catalog

        open_catalog(self)

    def action_back_to_wifi(self) -> None:
        self.app.push_screen(
            ConfirmEndScanModal(END_BLUETOOTH_SCAN_BODY),
            self._on_end_scan_confirmed,
        )

    def _on_end_scan_confirmed(self, confirmed: bool) -> None:
        if confirmed:
            self.stop_and_return()

    @work(exclusive=True)
    async def stop_and_return(self) -> None:
        await self.app.bluetooth_manager.stop()
        self.app.stop_bluetooth_target_capture()
        self.app.locked_target_id = None
        self.app.auto_lock_armed = True
        self.app.switch_screen("splash")

