import logging
import time
from dataclasses import replace
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import ComposeResult, RenderResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import Reactive
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, RichLog, Select
from textual.widgets.data_table import ColumnKey
from textual.widgets._header import HeaderClock

from wifit3.ui.notification_center import WifiteHeader

from wifit3.bluetooth.apple_identifiers import format_device_model_number
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
from wifit3.ui.bluetooth_export import export_bluetooth_bundle, export_btsnoop
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


STALE_DURATION_S = 10.0


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
    named = device.name.strip().casefold() not in {"", "<unknown>", "unknown"}
    if expiry >= 0 and CLASSIC_RADIO in device.radio_types and named:
        # Classic inquiry rows: keep named BT sightings longer (device may stop
        # answering inquiry while connected to a phone).
        expiry = max(expiry, 180.0)
    elif (
        expiry >= 0
        and BLE_RADIO in device.radio_types
        and CLASSIC_RADIO not in device.radio_types
        and named
    ):
        # BLE-only rows (mouse, keyboard, TV): advertising can be sparse while bonded.
        expiry = max(expiry, 120.0)
    return expiry >= 0 and age >= expiry


def _short_identifier(identifier: str) -> str:
    if len(identifier) <= 18:
        return identifier
    return f"{identifier[:8]}…{identifier[-4:]}"


def _is_anonymous_apple(device: BluetoothDevice) -> bool:
    return 0x004C in device.manufacturer_ids and device.name == "<Unknown>"


def _discovery_source_label(source: str) -> str:
    if source == "system+usb-hci":
        return "system BLE + dedicated USB HCI"
    if source == "usb-hci":
        return "dedicated USB HCI"
    return "system BLE"


def _address_kind_label(address_type: str) -> str:
    """Short, user-facing stability/privacy label for a Bluetooth address."""
    return {
        "public": "public/stable (OUI-based, trackable)",
        "public-identity": "public identity/stable (trackable)",
        "random-identity": "random identity/stable after bonding",
        "random-static": "random static (stable until changed/restarted)",
        "resolvable-private": "private rotating (RPA; IRK-resolvable)",
        "non-resolvable-private": "private random (NRPA; non-resolvable)",
        "random-reserved": "random/reserved pattern",
        "random": "random (privacy subtype unknown)",
        "anonymous": "anonymous (no device address)",
        "platform-opaque": "OS-opaque UUID (MAC hidden)",
        "unknown": "unknown",
        "": "unknown",
    }.get(address_type, address_type)


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
        Binding("escape", "back_to_wifi", "Wi-Fi"),
        Binding("enter", "connect", "Focus", show=False, priority=True),
        Binding("a", "toggle_apple_group", "random dev-Ids"),
        Binding("s", "cycle_sort", "Sort Col"),
        Binding("o", "toggle_sort_dir", "Sort Asc/Desc"),
        Binding("shift+t", "targets_editor", "Targets"),
        Binding("x", "export_scan", "Export"),
        Binding("f", "focus_filter", "Filter"),
        Binding("ctrl+l", "toggle_log", "Toggle Log"),
    ]

    CSS = """
    #bluetooth-filters { height: 3; padding: 0 1; }
    #bluetooth-filter-power { width: 14; margin-right: 1; }
    #bluetooth-filter-type { width: 14; margin-right: 1; }
    #bluetooth-filter-target { width: 18; margin-right: 1; }
    #bluetooth-filter-text { width: 1fr; }
    #bluetooth-log { height: 15; min-height: 15; }
    """

    _COLUMNS = [
        ("name", "DEVICE"),
        ("model", "MODEL"),
        ("rssi", "POWER"),
        ("category", "RADIO / TYPE"),
        ("advertisements", "OBS"),
        ("interval", "LATEST GAP"),
        ("first_seen", "FIRST SEEN"),
        ("last_seen", "LAST SEEN"),
        ("manufacturer", "MANUFACTURER"),
        ("services", "ADVERTISED SERVICES"),
        ("identifier", "ADDRESS / ID"),
        ("location", "GPS"),
    ]
    _COLUMN_WIDTHS = {
        "name": 22,
        "model": 8,
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
        self._apple_expanded = False
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
                yield Input(
                    placeholder="device, manufacturer, service, address…",
                    compact=True,
                    id="bluetooth-filter-text",
                )
            table = DataTable(cursor_type="row", id="bluetooth-table")
            for key, label in self._COLUMNS:
                table.add_column(label, key=key, width=self._COLUMN_WIDTHS[key])
            yield table
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
            + "[dim]Use BT/BLE Scan with OS BLE enabled on splash — the dongle alone misses "
            "most BLE devices (mouse, keyboard, TV).[/dim]\n"
            + "[dim]Your Mac’s own mouse/keyboard often do not appear while connected to "
            "this computer (no public advertisements). Disconnect or use pairing mode "
            "to see them.[/dim]\n"
            + "[dim]Speakers (e.g. Vieta Pro): pairing mode, not connected to phone; "
            "they show as [bold]BT[/bold] (Classic), not BLE — confirm the name appears "
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
        table = self.query_one("#bluetooth-table", DataTable)
        now = time.time()
        discovered = [
            device for device in self.app.bluetooth_manager.devices()
            if not _device_has_expired(device, now - device.last_seen)
            and self._matches_filter(device)
        ]
        displayed = discovered if self._apple_expanded else _group_anonymous_apple_devices(discovered)
        visible = {device.identifier: device for device in displayed}

        for identifier in set(self._rows) - set(visible):
            try:
                table.remove_row(identifier)
            except Exception:
                pass
            self._rows.pop(identifier, None)
            self._devices.pop(identifier, None)

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
            table.border_title = (
                " · ".join(parts) + f" · rows {len(visible)}{model_segment}"
            )
        elif manager.is_os_ble_scanning:
            table.border_title = (
                f"OS BLE · packets {manager.observations_by_radio[BLE_RADIO]} · "
                f"rows {len(visible)}{model_segment}"
            )
        self._log_enrichment_status(manager)
        self._sync_model_column_width(table, visible)
        for identifier, device in visible.items():
            self._devices[identifier] = device
            self._log_learned_model(device)
            values = self._row_values(device, now)
            previous = self._rows.get(identifier)
            if previous is None:
                table.add_row(*values, key=identifier)
                self._rows[identifier] = values
                if table.row_count == 1:
                    self._show_device_details(device)
            elif previous != values:
                for (key, _label), value in zip(self._COLUMNS, values):
                    table.update_cell(identifier, key, value)
                self._rows[identifier] = values
        self._apply_sort()

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

    def _update_column_headers(self) -> None:
        table = self.query_one("#bluetooth-table", DataTable)
        sort_key, _ = self._COLUMNS[self._sort_idx]
        arrow = "▼" if self._sort_reverse else "▲"
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

    def _apply_sort(self) -> None:
        table = self.query_one("#bluetooth-table", DataTable)
        if table.row_count == 0:
            return
        try:
            selected_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            selected_key = None
        sort_key, _ = self._COLUMNS[self._sort_idx]
        reverse = self._sort_reverse
        # The "Ns ago" label is truncated to whole seconds, so sorting on it
        # reshuffles devices that were first seen close together. Use the
        # stored timestamps; first_seen never changes for a device.
        devices_by_cell = {}
        for identifier, device in self._devices.items():
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
                # A visible age is presentation only (seconds/minutes/hours).
                # Timestamp-backed rows are handled above; never infer their
                # order from formatted text.
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
        if selected_key is not None:
            try:
                table.move_cursor(row=table.get_row_index(selected_key), animate=False)
            except Exception:
                pass

    def action_cycle_sort(self) -> None:
        self._sort_idx = (self._sort_idx + 1) % len(self._COLUMNS)
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
        manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier)
        classification = device_classification(device)
        all_services = sorted(set(device.service_uuids) | set(device.service_data_uuids))
        service_names = [service_name(uuid) for uuid in all_services]
        last_seen = "now" if age < 1 else f"{int(age)}s ago"
        first_seen = "now" if first_age < 1 else f"{int(first_age)}s ago"
        name = (
            "Apple private ID"
            if self._apple_expanded and _is_anonymous_apple(device) else device.name
        )
        name_cell = Text(no_wrap=True)
        if device.approximate_group:
            name_cell.append("≈ ", style="yellow bold")
        if name == "<Unknown>":
            name_cell.append("‹unnamed›", style="dim italic")
        else:
            name_cell.append(_clip(name, 22), style="bold")
        if device.signature_watch:
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
        identifier_cell = Text(
            f"≈ {device.group_size} rotating IDs"
            if device.approximate_group else _short_identifier(device.identifier),
            style="dim",
            no_wrap=True,
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
        cells = [
            name_cell,
            model_cell,
            signal_cell,
            Text(
                _clip(
                    f"{device.radio_label} {classification.detail}",
                    self._COLUMN_WIDTHS["category"],
                ),
                style="cyan",
                no_wrap=True,
            ),
            advertisements_cell,
            interval_cell,
            first_seen_cell,
            last_seen_cell,
            manufacturer_cell,
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
            *(service_label(uuid) for uuid in services),
        )).casefold()
        return all(token in searchable for token in self._filter_text.casefold().split())

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        device = self._devices.get(str(event.row_key.value))
        if device is not None:
            self._show_device_details(device)

    def _show_device_details(self, device: BluetoothDevice) -> None:
        log = self.query_one("#bluetooth-log", RichLog)
        log.clear()
        manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier) or "Unknown"
        classification = device_classification(device)
        category = classification.category
        services = sorted(set(device.service_uuids) | set(device.service_data_uuids))
        service_details = ", ".join(service_label(uuid) for uuid in services) or "None advertised"
        tx_power = f"{device.tx_power} dBm" if device.tx_power is not None else "not advertised"
        interval = (
            f"{device.advertisement_interval * 1000:.0f} ms"
            if device.advertisement_interval is not None else "waiting for another packet"
        )
        duration = max(0.0, device.last_seen - device.first_seen)
        identifier = (
            f"approximately {device.group_size} recently observed rotating identifiers"
            if device.approximate_group else device.identifier
        )
        log.write(f"[bold]{device.name}[/bold]  [dim]{identifier}[/dim]")
        log.write(
            f"Radio: [bold cyan]{device.radio_label}[/bold cyan]  "
            f"Discovery: [bold]{escape(_discovery_source_label(device.discovery_source))}[/bold]"
        )
        if device.approximate_group:
            log.write(
                "[bold yellow]Approximate privacy group:[/bold yellow] identifiers cannot be "
                "proven to belong to the same physical device. Press [bold]Enter[/bold] to expand."
            )
        elif self._apple_expanded and _is_anonymous_apple(device):
            log.write("[dim]Expanded Apple privacy identifier; press Enter to collapse the group.[/dim]")
        log.write(f"Manufacturer: [bold]{manufacturer}[/bold]")
        if device.hardware_product or device.hardware_vendor:
            hardware = " ".join(
                part
                for part in (device.hardware_vendor, device.hardware_product)
                if part
            )
            log.write(
                f"Hardware identity: [bold]{escape(hardware)}[/bold]  "
                f"Source: {escape(device.hardware_source or 'BlueZ Device ID')}"
            )
        if device.modalias:
            log.write(f"BlueZ modalias: {escape(device.modalias)}")
        device_information = [
            (
                "Model",
                format_device_model_number(device.model_number, detail=True)
                if device.model_number
                else device.model_number,
            ),
            ("GATT name", device.gatt_device_name),
            ("Manufacturer (GATT)", device.manufacturer_name),
            ("PnP ID", device.pnp_id),
            ("Firmware", device.firmware_revision),
            ("Hardware", device.hardware_revision),
            ("Software", device.software_revision),
            ("Serial", device.serial_number),
        ]
        if any(value for _, value in device_information):
            log.write(
                "[bold cyan]GATT identity[/bold cyan] "
                "[dim](GAP 0x1800 + Device Information 0x180A)[/dim]"
            )
            for label, value in device_information:
                if value:
                    log.write(f"  {label}: [bold]{escape(value)}[/bold]")
        hint = getattr(
            self.app.bluetooth_manager, "device_information_hint", None,
        )
        if hint is not None:
            log.write(f"Model (GATT 0x2A24): [bold]{escape(hint(device))}[/bold]")
        log.write(
            f"Probable type: [bold cyan]{escape(classification.detail)}[/bold cyan]  "
            f"Category: [bold]{category}[/bold]  "
            f"Evidence: {escape(classification.source)} ({classification.confidence})"
        )
        if classification.ambiguous:
            log.write(
                "[bold yellow]Ambiguous classification:[/bold yellow] equally strong "
                "advertised evidence disagrees."
            )
        baseline_labels = {
            "new": "[bold cyan]new identifier[/bold cyan]",
            "returning": "[green]seen previously[/green]",
            "changed": "[bold yellow]advertising profile changed[/bold yellow]",
            "unavailable": "[dim]history unavailable[/dim]",
        }
        address_kind = _address_kind_label(device.address_type)
        log.write(
            f"Baseline: {baseline_labels.get(device.baseline_status, escape(device.baseline_status))}  "
            f"Address type: [bold]{escape(device.address_type)}[/bold]  "
            f"MAC kind: [bold]{escape(address_kind)}[/bold]"
        )
        if device.similar_identifier_count > 1 and not device.approximate_group:
            log.write(
                f"[yellow]Privacy history:[/yellow] {device.similar_identifier_count} identifiers "
                "shared this advertising profile; this does not prove they are one device."
            )
        log.write(
            f"Signal: [{dbm_style(device.rssi)}]{device.rssi} dBm[/]  TX: {tx_power}  "
            f"Observations: {device.advertisement_count}  Latest gap: {interval}"
        )
        if device.rssi_average is not None:
            log.write(
                f"Signal window: average [bold]{device.rssi_average:.1f} dBm[/bold]  "
                f"range {device.rssi_min}…{device.rssi_max} dBm  "
                f"trend [bold]{device.rssi_trend}[/bold]  samples {device.rssi_samples}"
            )
        log.write(
            f"Observed for: {duration:.1f}s  Discovery payload: "
            f"manufacturer {device.manufacturer_data_bytes} B, service {device.service_data_bytes} B"
        )
        if device.class_of_device is not None:
            log.write(f"Classic class of device: [bold]0x{device.class_of_device:06x}[/bold]")
            log.write(
                f"Classic inquiry: page scan repetition {device.page_scan_repetition_mode}, "
                f"clock offset {device.clock_offset}"
            )
        if device.appearance is not None:
            log.write(f"BLE Appearance: [bold]0x{device.appearance:04x}[/bold]")
        log.write(f"Advertised services: {service_details}")
        if device.payload_fingerprint:
            log.write(
                f"Payload fingerprint: [dim]{device.payload_fingerprint}[/dim]  "
                f"Profile: [dim]{device.profile_fingerprint}[/dim]"
            )
        if device.is_connectable_with_bleak:
            log.write("[dim]A complete GATT service list requires connecting to the device.[/dim]")
        else:
            log.write(
                "[dim]This Classic-only observation has no BLE GATT endpoint. "
                "Press Enter for Classic identity, HCI health, and read-only SDP Focus.[/dim]"
            )
        if device.related_identifiers:
            log.write(
                f"[yellow]Probable BT/BLE relation ({device.correlation_confidence}):[/yellow] "
                f"{', '.join(device.related_identifiers)} · "
                f"{', '.join(device.correlation_evidence)}"
            )

    def action_toggle_selected_group(self) -> None:
        table = self.query_one("#bluetooth-table", DataTable)
        if table.row_count == 0:
            return
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return
        device = self._devices.get(str(key))
        if device is not None and (device.approximate_group or _is_anonymous_apple(device)):
            self.action_toggle_apple_group()

    def action_toggle_apple_group(self) -> None:
        self._apple_expanded = not self._apple_expanded
        self.refresh_table()
        target = next(
            (
                device for device in self._devices.values()
                if (_is_anonymous_apple(device) if self._apple_expanded else device.approximate_group)
            ),
            None,
        )
        if target is not None:
            self._show_device_details(target)

    def _selected_device(self) -> BluetoothDevice | None:
        table = self.query_one("#bluetooth-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None
        identifier = str(key)
        device = self._devices.get(identifier)
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
            self.app.target_store.update_missing(target, candidate.details)
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
            records = self.app.bluetooth_manager.hci_capture_records
            if records:
                paths.append(export_btsnoop(records))
        except OSError as exc:
            self.notify(str(exc), title="Export failed", severity="error")
            return
        self.notify(
            ", ".join(path.suffix.lstrip(".").upper() for path in paths),
            title="Bluetooth scan exported",
            timeout=6,
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

    def action_back_to_wifi(self) -> None:
        self.stop_and_return()

    @work(exclusive=True)
    async def stop_and_return(self) -> None:
        await self.app.bluetooth_manager.stop()
        self.app.stop_bluetooth_target_capture()
        self.app.locked_target_id = None
        self.app.auto_lock_armed = True
        self.app.switch_screen("splash")

