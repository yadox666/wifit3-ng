from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from wifit3.bluetooth.assigned_numbers import manufacturer_label
from wifit3.bluetooth.exposure import (
    ExposureFinding,
    ExposureSeverity,
    assess_exposure,
    severity_counts,
)
from wifit3.models import BluetoothInspection
from wifit3.persist.config import Config
from wifit3.ui.recording_indicator import recording_indicator
from wifit3.ui.signal_bar import dbm_style
from wifit3.ui.vault.global_tracker import GlobalJobTracker

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

_SEVERITY_STYLES = {
    ExposureSeverity.HIGH: ("HIGH", "bold red"),
    ExposureSeverity.MEDIUM: ("MED", "yellow"),
    ExposureSeverity.LOW: ("LOW", "cyan"),
}


def _exposure_cell(finding: ExposureFinding | None) -> Text | str:
    if finding is None:
        return ""
    label, style = _SEVERITY_STYLES[finding.severity]
    return Text(label, style=style)


def _exposure_detail(finding: ExposureFinding | None) -> str:
    if finding is None:
        return "[dim]none observed[/dim]"
    label, style = _SEVERITY_STYLES[finding.severity]
    detail = f"[{style}]{label}[/] {escape(finding.reason)}"
    if finding.severity > ExposureSeverity.LOW:
        detail += "\n[dim]Advertised only: the device may still reject unencrypted writes.[/dim]"
    return detail


class _BluetoothTrafficDashboard(Static):
    _ROWS = [
        ("advertisements", "advs", "yellow"),
        ("gatt_reads", "reads", "cyan"),
        ("read_bytes", "rx B", "blue"),
        ("notifications", "notify", "green"),
        ("notification_bytes", "ntf B", "magenta"),
        ("errors", "errors", "red"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._inspection: BluetoothInspection | None = None
        self._previous: dict[str, int] = {}
        self._history = {key: deque([0] * 128, maxlen=128) for key, _label, _color in self._ROWS}

    def on_mount(self) -> None:
        self.set_interval(0.4, self._sample)

    def bind(self, inspection: BluetoothInspection | None) -> None:
        if inspection is self._inspection:
            return
        self._inspection = inspection
        self._previous = {}
        self._history = {
            key: deque([0] * 128, maxlen=128) for key, _label, _color in self._ROWS
        }
        self._sample()

    def _sample(self) -> None:
        if self.is_mounted and self.app.screen is not self.screen:
            return
        traffic = self._inspection.traffic if self._inspection is not None else None
        for key, _label, _color in self._ROWS:
            if key == "advertisements" and self._inspection is not None:
                current = self._inspection.device.advertisement_count
            else:
                current = getattr(traffic, key, 0) if traffic is not None else 0
            previous = self._previous.get(key, current)
            self._history[key].append(max(0, current - previous))
            self._previous[key] = current
        self._paint()

    def _paint(self) -> None:
        width = max(8, (self.content_size.width or 40) - 14)
        lines = []
        for key, label, color in self._ROWS:
            values = list(self._history[key])[-width:]
            peak = max(max(values, default=0), 1)
            bars = "".join("▁▂▃▄▅▆▇█"[min(7, round(value * 7 / peak))] for value in values)
            if key == "advertisements" and self._inspection is not None:
                total = self._inspection.device.advertisement_count
            else:
                total = getattr(self._inspection.traffic, key, 0) if self._inspection else 0
            line = Text(f"{label:>6} ", style=color)
            line.append(bars, style=color if any(values) else f"dim {color}")
            line.append(f" {total:>6}", style=color)
            lines.append(line)
        self.update(Text("\n").join(lines))


class BluetoothFocusView(Screen):
    """Read-only GATT inspection for one explicitly selected BLE device."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "read_selected", "Read selected"),
    ]

    CSS = """
    BluetoothFocusView { layout: vertical; background: $surface; }
    #bt-top { height: 3; }
    #bt-top Button { height: 3; width: auto; min-width: 0; margin-right: 1; }
    #bt-status { width: 1fr; height: 3; content-align: center middle; text-align: center; }
    #ble-recording { width: 24; height: 3; content-align: center middle; text-align: center; }
    #bt-mid { height: 11; }
    #bt-device { width: 34; height: 100%; border: round $primary; padding: 0 1; }
    #bt-traffic { width: 1fr; height: 100%; border: round $primary; padding: 1; }
    #bt-connection { width: 30; height: 100%; border: round $primary; padding: 0 1; }
    #bt-bottom { height: 1fr; }
    #gatt-table { width: 2fr; height: 100%; }
    #gatt-detail { width: 1fr; height: 100%; border: round $primary; padding: 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._table_signature = None
        self._reconnecting = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="bt-top"):
            yield Button("‹ Bluetooth", id="bt-back")
            yield Static("", id="bt-status")
            yield Static("", id="ble-recording")
        with Horizontal(id="bt-mid"):
            device = Static("", id="bt-device")
            device.border_title = "DEVICE"
            yield device
            traffic = _BluetoothTrafficDashboard(id="bt-traffic")
            traffic.border_title = "GATT TRAFFIC"
            yield traffic
            connection = Static("", id="bt-connection")
            connection.border_title = "CONNECTION"
            yield connection
        with Horizontal(id="bt-bottom"):
            table = DataTable(cursor_type="row", id="gatt-table")
            table.add_columns("SERVICE", "CHARACTERISTIC", "PROPERTIES", "VALUE", "EXPOSURE")
            yield table
            detail = Static("", id="gatt-detail")
            detail.border_title = "CHARACTERISTIC"
            yield detail
        yield GlobalJobTracker()
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.25, self._refresh)
        self.query_one("#gatt-table", DataTable).focus()
        self._refresh()

    def on_screen_resume(self) -> None:
        self._table_signature = None
        self._refresh()

    def _inspection(self) -> BluetoothInspection | None:
        connection = self.app.bluetooth_manager.connection
        return connection.inspection if connection is not None else None

    def _refresh(self) -> None:
        if self.app.screen is not self:
            return
        self.query_one("#ble-recording", Static).update(recording_indicator(
            "BLE EVENT RECORDING",
            getattr(self.app, "bluetooth_target_capture", None) is not None,
        ))
        inspection = self._inspection()
        self.query_one("#bt-traffic", _BluetoothTrafficDashboard).bind(inspection)
        if inspection is None:
            self.query_one("#bt-status", Static).update("[red]No Bluetooth connection[/red]")
            return
        locked = getattr(self.app, "locked_target", None)
        if (
            not inspection.connected
            and not inspection.connecting
            and not self._reconnecting
            and locked is not None
            and locked.medium == "bluetooth"
            and locked.identifier.casefold() == inspection.device.identifier.casefold()
        ):
            self.reconnect_target(inspection.device)
        self._update_summary(inspection)
        self._sync_table(inspection)

    def _update_summary(self, inspection: BluetoothInspection) -> None:
        device = inspection.device
        manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier) or "Unknown"
        state = "CONNECTED" if inspection.connected else "CONNECTING" if inspection.connecting else "DISCONNECTED"
        state_color = "green" if inspection.connected else "yellow" if inspection.connecting else "red"
        locked = getattr(self.app, "locked_target", None)
        target_status = (
            f"  [bold cyan]TARGET · {escape(locked.alias)}[/bold cyan]"
            if locked is not None and locked.medium == "bluetooth" else ""
        )
        self.query_one("#bt-status", Static).update(
            f"[bold {state_color}]● {state}[/bold {state_color}]  "
            f"{escape(device.name)}{target_status}"
        )
        identity_confidence = (
            "Approximate advertisement group"
            if device.approximate_group else "Exact platform identifier"
        )
        self.query_one("#bt-device", Static).update(
            f"[bold]{escape(device.name)}[/bold]\n\n"
            f"[dim]Manufacturer[/dim]\n{escape(manufacturer)}\n\n"
            f"[dim]Signal[/dim]  [{dbm_style(device.rssi)}]{device.rssi} dBm[/]\n"
            f"[dim]Identifier[/dim]\n{escape(device.identifier)}"
            f"\n[dim]Identity confidence[/dim]\n{identity_confidence}"
        )
        characteristic_count = sum(len(service.characteristics) for service in inspection.services)
        connected_for = (
            max(0, int(time.time() - inspection.connected_at))
            if inspection.connected_at is not None else 0
        )
        traffic = inspection.traffic
        capture = self.app.bluetooth_target_capture
        capture_status = (
            f"\n[dim]Target capture[/dim] {capture.count} events"
            if capture is not None else ""
        )
        counts = severity_counts(assess_exposure(inspection))
        exposure = " ".join(
            f"[{style}]{label[0]}{counts[severity]}[/]"
            for severity, (label, style) in sorted(_SEVERITY_STYLES.items(), reverse=True)
        )
        self.query_one("#bt-connection", Static).update(
            f"[dim]Connected[/dim]  {connected_for}s\n"
            f"[dim]Services[/dim]   {len(inspection.services)}\n"
            f"[dim]Characteristics[/dim] {characteristic_count}\n"
            f"[dim]Exposure[/dim] {exposure}\n\n"
            f"[dim]GATT reads[/dim] {traffic.gatt_reads}\n"
            f"[dim]RX bytes[/dim]   {traffic.read_bytes + traffic.notification_bytes}\n"
            f"[dim]Notifications[/dim] {traffic.notifications}\n"
            f"[dim]Errors[/dim]     {traffic.errors}"
            f"{capture_status}"
        )

    def _sync_table(self, inspection: BluetoothInspection) -> None:
        signature = tuple(
            (
                characteristic.handle,
                characteristic.value,
                characteristic.read_error,
                characteristic.notifications,
            )
            for service in inspection.services
            for characteristic in service.characteristics
        )
        if signature == self._table_signature:
            return
        self._table_signature = signature
        table = self.query_one("#gatt-table", DataTable)
        table.clear(columns=False)
        findings = {finding.handle: finding for finding in assess_exposure(inspection)}
        for service in inspection.services:
            for characteristic in service.characteristics:
                if characteristic.value:
                    value = Text(characteristic.value)
                elif characteristic.read_error:
                    value = Text(characteristic.read_error, style="red")
                else:
                    value = ""
                table.add_row(
                    service.name,
                    characteristic.name,
                    ", ".join(characteristic.properties),
                    value,
                    _exposure_cell(findings.get(characteristic.handle)),
                    key=str(characteristic.handle),
                )
        if table.row_count:
            table.move_cursor(row=0, animate=False)
            self._show_characteristic(str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None:
            self._show_characteristic(str(event.row_key.value))

    def _show_characteristic(self, handle: str) -> None:
        inspection = self._inspection()
        if inspection is None:
            return
        findings = {finding.handle: finding for finding in assess_exposure(inspection)}
        for service in inspection.services:
            for characteristic in service.characteristics:
                if str(characteristic.handle) != handle:
                    continue
                value = escape(characteristic.value) if characteristic.value else "[dim]not read[/dim]"
                self.query_one("#gatt-detail", Static).update(
                    f"[bold]{escape(characteristic.name)}[/bold]\n"
                    f"[dim]{escape(characteristic.uuid)}[/dim]\n\n"
                    f"[dim]Service[/dim]\n{escape(service.name)}\n\n"
                    f"[dim]Properties[/dim]\n{escape(', '.join(characteristic.properties))}\n\n"
                    f"[dim]Value[/dim]\n{value}\n\n"
                    f"[dim]Notifications[/dim] {characteristic.notifications} "
                    f"({characteristic.notification_bytes} B)\n\n"
                    f"[dim]Exposure[/dim]\n{_exposure_detail(findings.get(characteristic.handle))}"
                )
                return

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bt-back":
            self.action_go_back()

    def action_go_back(self) -> None:
        self.disconnect_and_return()

    def action_read_selected(self) -> None:
        self.read_selected()

    @work(exclusive=True, group="target-reconnect")
    async def reconnect_target(self, device) -> None:
        self._reconnecting = True
        started = time.monotonic()
        try:
            while time.monotonic() - started < Config.target_reacquire_timeout:
                if self.app.screen is not self:
                    return
                try:
                    await self.app.bluetooth_manager.connect(device)
                    self.notify("Bluetooth target reacquired", title="Target lock")
                    return
                except Exception:
                    await asyncio.sleep(2)
            self.notify(
                "Bluetooth target was not reacquired",
                title="Target lock released",
                severity="warning",
            )
            self.app.locked_target_id = None
            self.app.stop_bluetooth_target_capture()
        finally:
            self._reconnecting = False

    @work(exclusive=True)
    async def read_selected(self) -> None:
        connection = self.app.bluetooth_manager.connection
        table = self.query_one("#gatt-table", DataTable)
        if connection is None or not table.row_count:
            return
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        try:
            await connection.read_characteristic(int(row_key.value))
        except Exception as exc:
            self.notify(str(exc), title="GATT read failed", severity="error")

    @work(exclusive=True)
    async def disconnect_and_return(self) -> None:
        await self.app.bluetooth_manager.disconnect()
        self.app.stop_bluetooth_target_capture()
        try:
            await self.app.bluetooth_manager.start()
        except Exception as exc:
            self.notify(str(exc), title="Bluetooth scan failed", severity="error")
        self.app.pop_screen()

