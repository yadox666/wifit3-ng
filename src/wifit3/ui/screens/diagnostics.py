from __future__ import annotations

import time

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static


def _age(timestamp: float | None) -> str:
    if timestamp is None:
        return "waiting"
    seconds = max(0, int(time.time() - timestamp))
    return "now" if seconds < 1 else f"{seconds}s"


def _health(interface) -> tuple[str, str]:
    if interface.device_lost:
        return "LOST", "bold red"
    reference = interface.last_frame_at or interface.connected_at
    if reference is not None and time.time() - reference > 15:
        return "SILENT", "yellow"
    if interface.tune_failures:
        return "WARNING", "yellow"
    return "HEALTHY", "bold green"


def _bluetooth_health(manager) -> tuple[str, str]:
    connection = manager.connection
    if connection is not None and connection.inspection.connected:
        return "CONNECTED", "bold green"
    reference = manager.last_advertisement_at or manager.scan_started_at
    if manager.is_scanning and reference is not None and time.time() - reference > 15:
        return "SILENT", "yellow"
    if manager.scan_failures:
        return "WARNING", "yellow"
    return "SCANNING", "bold green"


class AdapterDiagnosticsModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    AdapterDiagnosticsModal { align: center middle; }
    AdapterDiagnosticsModal #diagnostics-dialog {
        width: 94%; height: 80%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    AdapterDiagnosticsModal #diagnostics-title {
        height: 1; text-style: bold; text-align: center; margin-bottom: 1;
    }
    AdapterDiagnosticsModal #diagnostics-table { height: 1fr; }
    AdapterDiagnosticsModal #diagnostics-summary {
        height: auto; min-height: 4; border-top: solid $primary; padding: 1;
    }
    AdapterDiagnosticsModal #diagnostics-actions { height: auto; align: right middle; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="diagnostics-dialog"):
            yield Label("Adapter diagnostics", id="diagnostics-title")
            table = DataTable(cursor_type="row", id="diagnostics-table")
            table.add_columns(
                "ADAPTER", "CHIPSET", "CHANNEL", "VISITED", "RX / ADV", "TX / GATT",
                "LAST RX", "TUNE ERRORS", "STATUS",
            )
            yield table
            yield Static("", id="diagnostics-summary")
            with Horizontal(id="diagnostics-actions"):
                yield Button("Close", id="diagnostics-close")

    def on_mount(self) -> None:
        self.set_interval(1.0, self._refresh)
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one("#diagnostics-table", DataTable)
        table.clear(columns=False)
        array = getattr(self.app, "array", None)
        members = array.members if array is not None else []
        for interface in members:
            status, style = _health(interface)
            table.add_row(
                interface.name,
                interface.chipset or interface.driver.__class__.__name__,
                Text(str(interface.current_channel), justify="right"),
                Text(str(len(interface.visited_channels)), justify="right"),
                Text(str(interface.received_frames), justify="right"),
                Text(str(interface.transmitted_frames), justify="right"),
                Text(_age(interface.last_frame_at), justify="right"),
                Text(str(interface.tune_failures), justify="right"),
                Text(status, style=style),
                key=interface.name,
            )
        bluetooth = getattr(self.app, "bluetooth_manager", None)
        bluetooth_active = bluetooth is not None and (
            bluetooth.is_scanning or bluetooth.connection is not None
        )
        if bluetooth_active:
            status, style = _bluetooth_health(bluetooth)
            connection = bluetooth.connection
            inspection = connection.inspection if connection is not None else None
            gatt_reads = inspection.traffic.gatt_reads if inspection is not None else 0
            reference = bluetooth.last_advertisement_at
            if inspection is not None and inspection.connected_at is not None:
                reference = max(reference or 0, inspection.connected_at)
            table.add_row(
                "System Bluetooth",
                bluetooth.backend_name,
                "BLE",
                Text(str(len(bluetooth.devices())), justify="right"),
                Text(str(bluetooth.received_advertisements), justify="right"),
                Text(str(gatt_reads), justify="right"),
                Text(_age(reference), justify="right"),
                Text(str(bluetooth.scan_failures), justify="right"),
                Text(status, style=style),
                key="bluetooth",
            )
        active_count = len(members) + int(bluetooth_active)
        summary = (
            f"[bold]{active_count} active adapter{'s' if active_count != 1 else ''}[/bold]\n"
            "SILENT means no parsed frame for 15 seconds. It can also indicate an empty channel "
            "or weak reception. BLE uses advertisements as RX activity; hardware is never reset "
            "automatically."
        )
        self.query_one("#diagnostics-summary", Static).update(summary)

    @on(Button.Pressed, "#diagnostics-close")
    def close(self) -> None:
        self.dismiss()
