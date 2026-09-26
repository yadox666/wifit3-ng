import time
from dataclasses import replace
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, RichLog, Select

from wifit3.bluetooth.assigned_numbers import manufacturer_label, service_label, service_name
from wifit3.bluetooth.classification import device_category
from wifit3.models import BluetoothDevice
from wifit3.persist.config import Config
from wifit3.persist.targets import SavedTarget, TargetStoreError
from wifit3.targeting import TargetCandidate, bluetooth_candidate
from wifit3.ui.bluetooth_export import export_bluetooth_snapshot
from wifit3.ui.signal_bar import dbm_style
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.ui.screens.new_target import NewTargetModal, NewTargetResult

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


STALE_DURATION_S = 10.0
EVICT_DURATION_S = 30.0


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def _short_identifier(identifier: str) -> str:
    if len(identifier) <= 18:
        return identifier
    return f"{identifier[:8]}…{identifier[-4:]}"


def _is_anonymous_apple(device: BluetoothDevice) -> bool:
    return 0x004C in device.manufacturer_ids and device.name == "<Unknown>"


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


class BluetoothScannerView(Screen):
    """Nearby Bluetooth Low Energy devices observed through the system adapter."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "back_to_wifi", "Wi-Fi"),
        Binding("enter", "toggle_selected_group", "Expand/Collapse", show=False, priority=True),
        Binding("a", "toggle_apple_group", "Apple IDs"),
        Binding("c", "connect", "Connect"),
        Binding("s", "cycle_sort", "Sort Col"),
        Binding("o", "toggle_sort_dir", "Sort Asc/Desc"),
        Binding("n", "new_target", "New Target"),
        Binding("x", "export_scan", "Export CSV"),
        Binding("f", "focus_filter", "Filter"),
        Binding("l", "toggle_log", "Toggle Log"),
    ]

    CSS = """
    #bluetooth-filters { height: 3; padding: 0 1; }
    #bluetooth-filter-power { width: 14; margin-right: 1; }
    #bluetooth-filter-type { width: 14; margin-right: 1; }
    #bluetooth-filter-text { width: 1fr; }
    """

    _COLUMNS = [
        ("name", "DEVICE"),
        ("rssi", "POWER"),
        ("category", "TYPE"),
        ("advertisements", "ADV"),
        ("interval", "INTERVAL"),
        ("first_seen", "FIRST SEEN"),
        ("last_seen", "LAST SEEN"),
        ("manufacturer", "MANUFACTURER"),
        ("services", "ADVERTISED SERVICES"),
        ("identifier", "ADDRESS / ID"),
    ]
    _COLUMN_WIDTHS = {
        "name": 22,
        "rssi": 8,
        "category": 12,
        "advertisements": 8,
        "interval": 10,
        "first_seen": 10,
        "last_seen": 10,
        "manufacturer": 20,
        "services": 23,
        "identifier": 17,
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
        self._target_navigation_pending = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
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
                        "Phone", "Computer", "Other", "Unknown",
                    )],
                    value="All", allow_blank=False, compact=True,
                    id="bluetooth-filter-type",
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
        self._update_column_headers()
        self.query_one("#bluetooth-table", DataTable).focus()
        self.query_one("#bluetooth-log", RichLog).write(
            "[bold green]Bluetooth LE scanner initialized[/bold green]\n"
            "[dim]Services are capabilities declared in advertisements; select a row for details.[/dim]"
        )
        self.set_interval(0.2, self.refresh_table)

    def refresh_table(self) -> None:
        if self.app.screen is not self:
            return
        self._maybe_auto_lock_target()
        table = self.query_one("#bluetooth-table", DataTable)
        now = time.time()
        discovered = [
            device for device in self.app.bluetooth_manager.devices()
            if now - device.last_seen < EVICT_DURATION_S and self._matches_filter(device)
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

        for identifier, device in visible.items():
            self._devices[identifier] = device
            values = self._row_values(device, now)
            previous = self._rows.get(identifier)
            if previous is None:
                table.add_row(*values, key=identifier)
                if table.row_count == 1:
                    self._show_device_details(device)
            elif previous != values:
                for (key, _label), value in zip(self._COLUMNS, values):
                    table.update_cell(identifier, key, value)
            self._rows[identifier] = values
        self._apply_sort()

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

        def sort_value(cells: tuple[Text, Text]) -> tuple:
            value_cell, identifier_cell = cells
            value = value_cell.plain.strip()
            is_empty = value in {"", "·", "‹unnamed›"}
            if is_empty:
                normalized: int | str = 0
            elif sort_key == "rssi":
                normalized = int(value.split()[0])
            elif sort_key in {"advertisements", "interval"}:
                normalized = int(value.split()[0])
            elif sort_key in {"first_seen", "last_seen"}:
                normalized = 0 if value == "now" else int(value.split("s", 1)[0])
            else:
                normalized = value.casefold()
            return (int(is_empty != reverse), normalized, identifier_cell.plain.casefold())

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

    def action_toggle_sort_dir(self) -> None:
        self._sort_reverse = not self._sort_reverse
        self._update_column_headers()
        self._apply_sort()

    def _row_values(self, device: BluetoothDevice, now: float) -> tuple:
        age = max(0.0, now - device.last_seen)
        first_age = max(0.0, now - device.first_seen)
        is_stale = age > STALE_DURATION_S
        manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier)
        category = device_category(device)
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
        cells = [
            name_cell,
            signal_cell,
            Text(category, style="cyan", no_wrap=True),
            advertisements_cell,
            interval_cell,
            first_seen_cell,
            last_seen_cell,
            manufacturer_cell,
            services_cell,
            identifier_cell,
        ]
        if is_stale:
            for cell in cells:
                cell.stylize("dim")
        store = getattr(self.app, "target_store", None)
        is_target = (
            not device.approximate_group
            and store is not None
            and store.find("bluetooth", "device", device.identifier) is not None
        )
        if is_target:
            cells[0] = Text("! ", style="bold red") + cells[0]
            for cell in cells:
                cell.stylize("bold red")
        return tuple(cells)

    def _matches_filter(self, device: BluetoothDevice) -> bool:
        if device.rssi < self._min_signal:
            return False
        category = device_category(device)
        if self._category != "All" and category != self._category:
            return False
        services = set(device.service_uuids) | set(device.service_data_uuids)
        searchable = " ".join((
            device.name,
            device.identifier,
            manufacturer_label(device.manufacturer_ids, device.identifier),
            category,
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
        category = device_category(device)
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
        if device.approximate_group:
            log.write(
                "[bold yellow]Approximate privacy group:[/bold yellow] identifiers cannot be "
                "proven to belong to the same physical device. Press [bold]Enter[/bold] to expand."
            )
        elif self._apple_expanded and _is_anonymous_apple(device):
            log.write("[dim]Expanded Apple privacy identifier; press Enter to collapse the group.[/dim]")
        log.write(f"Manufacturer: [bold]{manufacturer}[/bold]")
        log.write(f"Probable type: [bold cyan]{category}[/bold cyan] [dim](advertisement inference)[/dim]")
        if device.similar_identifier_count > 1 and not device.approximate_group:
            log.write(
                f"[yellow]Privacy history:[/yellow] {device.similar_identifier_count} identifiers "
                "shared this advertising profile; this does not prove they are one device."
            )
        log.write(
            f"Signal: [{dbm_style(device.rssi)}]{device.rssi} dBm[/]  TX: {tx_power}  "
            f"Advertisements: {device.advertisement_count}  Latest interval: {interval}"
        )
        log.write(
            f"Observed for: {duration:.1f}s  Advertisement data: "
            f"manufacturer {device.manufacturer_data_bytes} B, service {device.service_data_bytes} B"
        )
        log.write(f"Advertised services: {service_details}")
        log.write("[dim]A complete GATT service list requires connecting to the device.[/dim]")

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
        return self._devices.get(str(key))

    def action_connect(self) -> None:
        device = self._selected_device()
        if device is None:
            return
        if device.approximate_group:
            self.notify("Expand the Apple group and select one identifier first.", severity="warning")
            return
        self.connect_device(device)

    def action_new_target(self) -> None:
        device = self._selected_device()
        if device is None:
            self.notify("Select a Bluetooth device first", severity="warning")
            return
        if device.approximate_group:
            self.notify(
                "Expand the approximate group and select one identifier first.",
                severity="warning",
            )
            return
        candidate = bluetooth_candidate(device)
        existing = self.app.target_store.find(
            candidate.medium, candidate.kind, candidate.identifier
        )
        if existing is not None:
            self.lock_target(existing, candidate, device)
            return

        def completed(result: NewTargetResult | None) -> None:
            if result is None:
                return
            try:
                target = self.app.target_store.upsert(
                    alias=result.alias,
                    medium=candidate.medium,
                    kind=candidate.kind,
                    identifier=candidate.identifier,
                    details=candidate.details,
                )
            except TargetStoreError as exc:
                self.notify(str(exc), title="Targets", severity="error")
                return
            self.notify(f"Target {target.alias} saved", title="Targets")
            if result.lock:
                self.lock_target(target, candidate, device)

        self.app.push_screen(NewTargetModal(candidate), completed)

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
            if device.approximate_group:
                continue
            target = self.app.target_store.find(
                "bluetooth", "device", device.identifier,
            )
            if target is not None and target.enabled:
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
            if not self.app.mark_target_locked(target):
                return
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
                log.write(f"[bold red]Connection failed:[/bold red] {escape(str(exc))}")
                self.notify(str(exc), title="Bluetooth connection failed", severity="error")
                try:
                    await self.app.bluetooth_manager.start()
                except Exception:
                    pass
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
        await self.app.bluetooth_manager.stop()
        try:
            await self.app.bluetooth_manager.connect(device)
        except Exception as exc:
            log.write(f"[bold red]Connection failed:[/bold red] {escape(str(exc))}")
            self.notify(str(exc), title="Bluetooth connection failed", severity="error")
            try:
                await self.app.bluetooth_manager.start()
            except Exception:
                pass
            return
        self.app.push_screen("bluetooth-focus")

    def action_toggle_log(self) -> None:
        log = self.query_one("#bluetooth-log", RichLog)
        log.display = not log.display

    def action_export_scan(self) -> None:
        devices = self.app.bluetooth_manager.devices()
        if not devices:
            self.notify("No Bluetooth devices to export", severity="warning")
            return
        try:
            path = export_bluetooth_snapshot(devices)
        except OSError as exc:
            self.notify(str(exc), title="Export failed", severity="error")
            return
        self.notify(path.name, title="Bluetooth CSV exported", timeout=6)

    def action_focus_filter(self) -> None:
        self.query_one("#bluetooth-filter-text", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "bluetooth-filter-text":
            self._filter_text = event.value
            self.refresh_table()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "bluetooth-filter-power":
            self._min_signal = int(event.value)
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

