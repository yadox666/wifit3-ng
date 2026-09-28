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
from textual.containers import Horizontal, Vertical
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


def gatt_ascii(value_hex: str) -> str | None:
    """Printable ASCII when every hex byte converts, ignoring trailing NULs."""
    parts = value_hex.split(" ")
    if not parts or any(len(part) != 2 for part in parts):
        return None
    try:
        raw = bytes(int(part, 16) for part in parts)
    except ValueError:
        return None
    if raw.hex(" ") != value_hex:
        return None
    text = raw.rstrip(b"\x00")
    if not text or any(byte < 0x20 or byte > 0x7E for byte in text):
        return None
    return text.decode("ascii")


def gatt_display_value(value: str, value_hex: str, *, ascii_mode: bool) -> str:
    """Characteristic text, using ASCII only for an undecoded printable dump."""
    if not ascii_mode or not value_hex or value != value_hex:
        return value
    return gatt_ascii(value_hex) or value


def _exposure_detail(finding: ExposureFinding | None) -> str:
    if finding is None:
        return "[dim]none observed[/dim]"
    label, style = _SEVERITY_STYLES[finding.severity]
    detail = f"[{style}]{label}[/] {escape(finding.reason)}"
    if finding.severity > ExposureSeverity.LOW:
        detail += "\n[dim]Advertised only: the device may still reject unencrypted writes.[/dim]"
    return detail


def _local_adapter_art(backend: str) -> Text:
    source = (
        "████████████████████████████████████████████████████████",
        "██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██",
        "██▒▒██████████████████▓▓▓▓██████████████████████████▒▒██",
        "██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒██",
        "██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒██",
        "██▒▒██▒▒                                        ▒▒██▒▒██",
        "██▒▒██▒▒       Wifit3-ng                   BLE  ▒▒██▒▒██",
        "██▒▒██▒▒                                        ▒▒██▒▒██",
        "██▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒██",
        "██▒▒████████████████████████████████████████████████▒▒██",
        "██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██",
        "████████████████████████████████████████████████████▓▓▓▓",
        "████▒▒░░░░░░░░░░░░░░░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██▒▒",
        "████░░░░██░░██░░██░░██░░▓▓░░██░░██░░██░░██░░██░░██░░██░░▓▓░░████",
        "████▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████",
        "████▒▒░░░░██░░██░░██░░██░░██░░██░░██░░██░░██░░██░░██░░██░░██░░██░░░░████",
        "████▒▒░░░░░░░░░░░░░░░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░░░░░░░▒▒████",
        "████░░░░░░██▓▓▓▓░░██░░██▒▒░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████▓▓██░░▓▓▓▓░░██░░██▓▓▓▓░░░░████",
        "██▒▒░░░░░░▒▒▒▒▒▒░░░░░░░░▒▒░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▒░░░░▒▒▒▒░░▒▒░░▒▒▒▒▒▒░░░░▒▒██",
        "██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██",
    )

    def compact(line: str) -> str:
        result = []
        index = 0
        while index < len(line):
            char = line[index]
            if char in "█▒░▓ " and index + 1 < len(line) and line[index + 1] == char:
                result.append(char)
                index += 2
            else:
                result.append(char)
                index += 1
        return "".join(result)

    lines = [compact(line) for line in source]
    width = max(len(line) for line in lines)
    text_row = ("█▒█▒" + "  Wifit3-ng  BLE    " + "▒█▒█").center(width)
    lines[next(index for index, line in enumerate(lines) if "Wifit3-ng" in line)] = text_row
    art = Text(no_wrap=True)
    for line in lines:
        rendered = Text(f"{line:^{width}}", style="grey70")
        for label, style in (("Wifit3-ng", "bold cyan"), ("BLE", "bold rgb(0,120,255)")):
            start = rendered.plain.find(label)
            if start >= 0:
                rendered.stylize(style, start, start + len(label))
        art.append(rendered)
        art.append("\n")
    label = "THIS LAPTOP"
    left = (width - len(label)) // 2
    art.append(" " * left)
    art.append(label, style="bold black on cyan")
    art.append(" " * (width - left - len(label)))
    art.append("\n")
    backend_label = f"{backend} • BLE CENTRAL"
    if len(backend_label) > width:
        backend_label = backend_label[: width - 1] + "…"
    art.append(f"{backend_label:^{width}}", style="cyan")
    return art


def _bluetooth_device_art(
    inspection: BluetoothInspection | None,
    *,
    fallback_name: str = "BLUETOOTH DEVICE",
    fallback_identifier: str = "Waiting for connection",
) -> Text:
    width = 30

    def centered(value: str) -> str:
        clipped = value if len(value) <= width else value[: width - 1] + "…"
        return f"{clipped:^{width}}"

    device = inspection.device if inspection is not None else None
    name = device.name if device is not None else fallback_name
    identifier = device.identifier if device is not None else fallback_identifier
    manufacturer = (
        manufacturer_label(device.manufacturer_ids, device.identifier) or "Unknown"
        if device is not None else "REMOTE BLE ENDPOINT"
    )
    art = Text(no_wrap=True)
    logo_rows = (
        "     ████████████████████",
        "  ████████████  ████████████",
        " █████████████    ███████████",
        "██████████████  ██  ██████████",
        "██████████████  ███   ████████",
        "███████   ████  ████   ███████",
        "█████████   ██  ██   █████████",
        "███████████        ███████████",
        "█████████████    █████████████",
        "█████████████     ████████████",
        "███████████        ███████████",
        "█████████   ██  ███  █████████",
        "███████   ████  ████   ███████",
        "██████████████  ███   ████████",
        "██████████████  ██  ██████████",
        " █████████████     ██████████",
        "  ████████████  ████████████",
        "     ████████████████████",
    )
    for line in logo_rows:
        art.append(f"{line:<{width}}", style="bold rgb(0,120,255)")
        art.append("\n")
    name = f" {name} "
    name = name if len(name) <= width else name[: width - 1] + "…"
    left = (width - len(name)) // 2
    art.append(" " * left)
    art.append(name, style="bold white on rgb(0,90,220)")
    art.append(" " * (width - left - len(name)))
    art.append("\n")
    art.append(centered(manufacturer), style="cyan")
    art.append("\n")
    if device is not None:
        art.append(centered(f"{device.rssi} dBm"), style=dbm_style(device.rssi))
        art.append("\n")
    art.append(centered(identifier), style="dim")
    return art


class _BluetoothTrafficDashboard(Static):
    _BLOCKS = " ▁▂▃▄▅▆▇█"
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

    def on_resize(self) -> None:
        self._paint()

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
        two_rows = (self.content_size.height or 12) // len(self._ROWS) >= 2
        lines: list[Text] = []
        for key, label, color in self._ROWS:
            values = list(self._history[key])[-width:]
            peak = max(max(values, default=0), 1)
            if key == "advertisements" and self._inspection is not None:
                total = self._inspection.device.advertisement_count
            else:
                total = getattr(self._inspection.traffic, key, 0) if self._inspection else 0
            row_style = color if any(values) else f"dim {color}"
            levels = [
                0 if value <= 0 else max(1, min(16, round(value * 16 / peak)))
                for value in values
            ]
            if two_rows:
                upper = "".join(self._BLOCKS[max(0, level - 8)] for level in levels)
                lines.append(self._traffic_row("", upper, "", row_style))
                lower = "".join(self._BLOCKS[max(1, min(8, level))] for level in levels)
            else:
                lower = "".join(
                    self._BLOCKS[max(1, min(8, round(level / 2)))] for level in levels
                )
            lines.append(self._traffic_row(label, lower, str(total), row_style))
        height = self.content_size.height or len(lines)
        top_padding = max(0, (height - len(lines)) // 2)
        self.update(Text("\n").join([Text("")] * top_padding + lines))

    @staticmethod
    def _traffic_row(label: str, bars: str, total: str, style: str) -> Text:
        line = Text()
        line.append(f"{label:>6} ", style=style if label else "")
        line.append(bars, style=style)
        line.append(" ")
        line.append(f"{total:<6}", style=style if total else "")
        return line


class BluetoothFocusView(Screen):
    """Read-only GATT inspection for one explicitly selected BLE device."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "read_selected", "Read selected"),
        Binding("a", "toggle_ascii", "ASCII"),
    ]

    CSS = """
    BluetoothFocusView { layout: vertical; background: $surface; }
    #bt-top { height: 3; }
    #bt-top Button { height: 3; width: auto; min-width: 0; margin-right: 1; }
    #bt-status { width: 1fr; height: 3; content-align: center middle; text-align: center; }
    #ble-recording { width: 24; height: 3; content-align: center middle; text-align: center; }
    #bt-mid { height: 22; }
    #bt-local {
        width: 40; height: 100%; padding: 0;
        content-align: center middle; background: transparent;
    }
    #bt-center { width: 1fr; height: 100%; }
    #bt-connection {
        width: 100%; height: 4; padding: 0 1;
        content-align: center middle; background: transparent;
    }
    #bt-traffic { width: 100%; height: 1fr; padding: 0 2; background: transparent; }
    #bt-device {
        width: 40; height: 100%; padding: 0;
        content-align: center middle; background: transparent;
    }
    #bt-bottom { height: 1fr; }
    #gatt-table { width: 2fr; height: 100%; }
    #gatt-detail { width: 1fr; height: 100%; border: round $primary; padding: 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._table_signature = None
        self._reconnecting = False
        self._show_ascii = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="bt-top"):
            yield Button("‹ Bluetooth", id="bt-back")
            yield Static("", id="bt-status")
            yield Static("", id="ble-recording")
        with Horizontal(id="bt-mid"):
            local = Static("", id="bt-local")
            yield local
            with Vertical(id="bt-center"):
                connection = Static("", id="bt-connection")
                yield connection
                traffic = _BluetoothTrafficDashboard(id="bt-traffic")
                yield traffic
            device = Static("", id="bt-device")
            yield device
        with Horizontal(id="bt-bottom"):
            table = DataTable(cursor_type="row", id="gatt-table")
            table.add_columns(
                ("SERVICE", "service"),
                ("CHARACTERISTIC", "characteristic"),
                ("PROPERTIES", "properties"),
                ("VALUE", "value"),
                ("EXPOSURE", "exposure"),
            )
            yield table
            detail = Static("", id="gatt-detail")
            detail.border_title = "CHARACTERISTIC"
            yield detail
        yield GlobalJobTracker()
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.25, self._refresh)
        self.query_one("#gatt-table", DataTable).focus()
        self._distribute()
        self._refresh()

    def on_resize(self) -> None:
        self._distribute()

    def _distribute(self) -> None:
        if not self.is_mounted:
            return
        pad = max(0, round((self.size.width - 120) * 0.1))
        self.query_one("#bt-mid").styles.padding = (0, pad, 0, pad)

    def on_screen_resume(self) -> None:
        self._table_signature = None
        self._refresh()

    def _inspection(self) -> BluetoothInspection | None:
        connection = self.app.bluetooth_manager.connection
        return connection.inspection if connection is not None else None

    def _refresh(self) -> None:
        if self.app.screen is not self:
            return
        self.query_one("#bt-local", Static).update(
            _local_adapter_art(self.app.bluetooth_manager.backend_name)
        )
        self.query_one("#ble-recording", Static).update(recording_indicator(
            "BLE EVENT RECORDING",
            getattr(self.app, "bluetooth_target_capture", None) is not None,
        ))
        inspection = self._inspection()
        self.query_one("#bt-traffic", _BluetoothTrafficDashboard).bind(inspection)
        if inspection is None:
            self.query_one("#bt-status", Static).update("[red]No Bluetooth connection[/red]")
            locked = getattr(self.app, "locked_target", None)
            fallback_name = (
                locked.alias
                if locked is not None and locked.medium == "bluetooth"
                else "BLUETOOTH DEVICE"
            )
            fallback_identifier = (
                locked.identifier
                if locked is not None and locked.medium == "bluetooth"
                else "Waiting for connection"
            )
            self.query_one("#bt-device", Static).update(_bluetooth_device_art(
                None,
                fallback_name=fallback_name,
                fallback_identifier=fallback_identifier,
            ))
            self.query_one("#bt-connection", Static).update(
                "[cyan]╼━━━━━━━━━━━━[/cyan][bold red]━━╳━━━━━━━━━━━━[/bold red]\n"
                "[bold cyan]BLE / GATT[/bold cyan]  [bold red]DISCONNECTED[/bold red]"
            )
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
        self.query_one("#bt-device", Static).update(_bluetooth_device_art(inspection))
        characteristic_count = sum(len(service.characteristics) for service in inspection.services)
        connected_for = (
            max(0, int(time.time() - inspection.connected_at))
            if inspection.connected_at is not None else 0
        )
        state_duration = f" {connected_for}s" if inspection.connected else ""
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
            f"[cyan]╼━━━━━━━━━━━━[/cyan]"
            f"[bold {state_color}]━━●━━━━━━━━━━━━▶[/bold {state_color}]\n"
            f"[bold cyan]BLE / GATT[/bold cyan]  "
            f"[bold {state_color}]{state}{state_duration}[/bold {state_color}]  "
            f"[bold bright_blue]→ {escape(device.name)}[/bold bright_blue]\n"
            f"[dim]Link[/dim] {device.rssi} dBm  •  "
            f"[dim]Services[/dim] {len(inspection.services)}  •  "
            f"[dim]Characteristics[/dim] {characteristic_count}\n"
            f"[dim]RX[/dim] {traffic.read_bytes + traffic.notification_bytes} B  •  "
            f"[dim]Reads[/dim] {traffic.gatt_reads}  •  "
            f"[dim]Notify[/dim] {traffic.notifications}  •  "
            f"[dim]Errors[/dim] {traffic.errors}  •  "
            f"[dim]Exposure[/dim] {exposure}"
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
                    value = Text(self._shown_value(characteristic))
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
                value = self._value_markup(characteristic)
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

    def action_toggle_ascii(self) -> None:
        self._show_ascii = not self._show_ascii
        detail = self.query_one("#gatt-detail", Static)
        detail.border_title = "CHARACTERISTIC"
        inspection = self._inspection()
        table = self.query_one("#gatt-table", DataTable)
        if inspection is not None:
            for service in inspection.services:
                for characteristic in service.characteristics:
                    if not characteristic.value:
                        continue
                    table.update_cell(
                        str(characteristic.handle),
                        "value",
                        Text(self._shown_value(characteristic)),
                    )
        if table.row_count:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            self._show_characteristic(str(row_key.value))

    def _shown_value(self, characteristic) -> str:
        return gatt_display_value(
            characteristic.value,
            characteristic.value_hex,
            ascii_mode=self._show_ascii,
        )

    def _value_markup(self, characteristic) -> str:
        if not characteristic.value:
            return "[dim]not read[/dim]"
        ascii_value = (
            gatt_ascii(characteristic.value_hex)
            if characteristic.value == characteristic.value_hex
            else None
        )
        if ascii_value is None:
            return escape(characteristic.value)
        return (
            f"[dim]ASCII[/dim]\n{escape(ascii_value)}\n\n"
            f"[dim]Hex[/dim]\n{escape(characteristic.value)}"
        )

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

