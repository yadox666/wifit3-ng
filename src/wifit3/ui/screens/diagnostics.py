from __future__ import annotations

import time

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Link, Static

from wifit3.models.bluetooth_device import BLE_RADIO
from wifit3.persist.config import Config
from wifit3.sdr import find_hackrf_devices, probe_hackrf_usb


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


def _bluetooth_health(manager, radio_type: str) -> tuple[str, str]:
    connection = manager.connection
    if (
        radio_type == BLE_RADIO
        and connection is not None
        and connection.inspection.connected
    ):
        return "CONNECTED", "bold green"
    reference = manager.last_observation_by_radio.get(radio_type) or manager.scan_started_at
    if manager.is_scanning and reference is not None and time.time() - reference > 15:
        return "SILENT", "yellow"
    if manager.scan_failures:
        return "WARNING", "yellow"
    return "SCANNING", "bold green"


def _gps_health(manager) -> tuple[str, str]:
    if not manager.dependency_available:
        return "UNAVAILABLE", "bold red"
    fix = manager.latest_fix
    if (
        manager.status is not None
        and fix is not None
        and fix.is_usable(max_accuracy_m=Config.gps_max_accuracy_m)
    ):
        return "FIX", "bold green"
    if manager.status is not None and fix is not None:
        if time.time() - fix.observed_at <= 10 and fix.accuracy_m > Config.gps_max_accuracy_m:
            return "LOW ACCURACY", "yellow"
        return "STALE", "yellow"
    if manager.status is not None:
        return "NO FIX", "yellow"
    return "SEARCHING", "cyan"


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
    AdapterDiagnosticsModal #gps-title {
        height: 1; text-style: bold; margin-top: 1;
    }
    AdapterDiagnosticsModal #gps-table { height: 4; }
    AdapterDiagnosticsModal #gps-map-link {
        height: 1; text-align: right; margin-bottom: 1;
    }
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
                "ADAPTER", "CHIPSET", "CHANNEL", "VISITED", "RX / OBS", "TX / GATT",
                "LAST RX", "TUNE ERRORS", "STATUS",
            )
            yield table
            yield Label("GPS diagnostics", id="gps-title")
            gps_table = DataTable(cursor_type="row", id="gps-table")
            gps_table.add_columns(
                "PORT", "BAUD", "POSITION", "SATELLITES", "ACCURACY", "LAST FIX", "STATUS",
            )
            yield gps_table
            yield Link("Google Maps unavailable", id="gps-map-link", disabled=True)
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
            connection = bluetooth.connection
            inspection = connection.inspection if connection is not None else None
            for radio_type in bluetooth.active_radio_types():
                status, style = _bluetooth_health(bluetooth, radio_type)
                reference = bluetooth.last_observation_by_radio.get(radio_type)
                if (
                    radio_type == BLE_RADIO
                    and inspection is not None
                    and inspection.connected_at is not None
                ):
                    reference = max(reference or 0, inspection.connected_at)
                device_count = sum(
                    radio_type in device.radio_types for device in bluetooth.devices()
                )
                gatt_reads = (
                    inspection.traffic.gatt_reads
                    if radio_type == BLE_RADIO and inspection is not None else 0
                )
                radio_name = "BLE" if radio_type == BLE_RADIO else "Classic"
                source = "USB" if bluetooth.is_usb_radio(radio_type) else "System"
                table.add_row(
                    f"{source} Bluetooth {radio_name}",
                    bluetooth.backend_name_for_radio(radio_type),
                    radio_type,
                    Text(str(device_count), justify="right"),
                    Text(
                        str(bluetooth.observations_by_radio[radio_type]),
                        justify="right",
                    ),
                    Text(str(gatt_reads), justify="right"),
                    Text(_age(reference), justify="right"),
                    Text(str(bluetooth.scan_failures), justify="right"),
                    Text(status, style=style),
                    key=f"bluetooth-{radio_type.casefold()}",
                )
        hackrf_devices = find_hackrf_devices()
        for index, device in enumerate(hackrf_devices):
            health = probe_hackrf_usb(device)
            style = "bold green" if health.ready else (
                "yellow" if health.status == "DISCONNECTED" else "bold red"
            )
            table.add_row(
                "USB SDR",
                device.product_name,
                "IQ",
                "-",
                "-",
                "disabled",
                health.detail,
                "-",
                Text(health.status, style=style),
                key=f"hackrf-{index}",
            )
        active_count = len(members) + int(bluetooth_active) + len(hackrf_devices)
        self._refresh_gps()
        summary = (
            f"[bold]{active_count} active adapter{'s' if active_count != 1 else ''}[/bold]\n"
            "SILENT means no parsed frame for 15 seconds. It can also indicate an empty channel "
            "or weak reception. Bluetooth uses discovery observations as RX activity; hardware "
            "is never reset automatically. HackRF USB READY verifies its firmware control channel, "
            "not RF reception."
        )
        self.query_one("#diagnostics-summary", Static).update(summary)

    def _refresh_gps(self) -> None:
        table = self.query_one("#gps-table", DataTable)
        map_link = self.query_one("#gps-map-link", Link)
        table.clear(columns=False)
        manager = getattr(self.app, "gps_manager", None)
        if manager is None:
            map_link.text = "Google Maps unavailable"
            map_link.url = ""
            map_link.disabled = True
            table.add_row("-", "-", "-", "-", "-", "-", Text("UNAVAILABLE", style="bold red"))
            return
        status, style = _gps_health(manager)
        fix = manager.latest_fix
        detected = manager.status
        port = (
            detected.port if detected is not None
            else manager.configured_port or "Auto-detect"
        )
        baudrate = str(detected.baudrate) if detected is not None else "Auto"
        position = (
            f"{fix.latitude:.6f}, {fix.longitude:.6f}" if fix is not None else "-"
        )
        satellites = str(fix.satellites) if fix and fix.satellites is not None else "-"
        accuracy = f"{fix.accuracy_m:.1f} m" if fix is not None else "-"
        last_fix = _age(fix.observed_at) if fix is not None else "waiting"
        if fix is not None:
            from wifit3.models.location import SignalPosition
            from wifit3.ui.location_format import google_maps_search_url

            map_link.text = "Open position in Google Maps ↗"
            map_link.url = google_maps_search_url([
                SignalPosition(
                    fix.latitude,
                    fix.longitude,
                    fix.altitude_m,
                    fix.accuracy_m,
                    fix.observed_at,
                    fix.source,
                    None,
                ),
            ]) or ""
            map_link.disabled = False
        else:
            map_link.text = "Google Maps unavailable"
            map_link.url = ""
            map_link.disabled = True
        table.add_row(
            port,
            Text(baudrate, justify="right"),
            position,
            Text(satellites, justify="right"),
            Text(accuracy, justify="right"),
            Text(last_fix, justify="right"),
            Text(status, style=style),
            key="gps",
        )

    @on(Button.Pressed, "#diagnostics-close")
    def close(self) -> None:
        self.dismiss()
