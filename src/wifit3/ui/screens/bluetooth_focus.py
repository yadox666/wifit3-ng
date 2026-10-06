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
from textual.widgets import Button, DataTable, Footer, Static

from wifit3.ui.catalog_format import catalog_detail_lines, catalog_status_line
from wifit3.ui.notification_center import WifiteHeader

from wifit3.bluetooth.apple_identifiers import format_device_model_number
from wifit3.bluetooth.assigned_numbers import (
    characteristic_property_detail,
    manufacturer_label,
    service_label,
    uuid_metadata_source,
)
from wifit3.bluetooth.gatt_metadata import compact_uuid, decode_pnp_id
from wifit3.bluetooth.classification import device_classification
from wifit3.bluetooth.exposure import (
    ExposureFinding,
    ExposureSeverity,
    assess_exposure,
    severity_counts,
)
from wifit3.bluetooth.manager import BluetoothScanError
from wifit3.models import BluetoothDevice, BluetoothInspection
from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO
from wifit3.persist.config import Config
from wifit3.targeting import bluetooth_candidate
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


def _address_kind_label(address_type: str) -> str:
    return {
        "public": "public/stable · OUI-based · trackable",
        "public-identity": "public identity · stable · trackable",
        "random-identity": "random identity · stable after bonding",
        "random-static": "random static · stable until changed",
        "resolvable-private": "RPA · private rotating · IRK-resolvable",
        "non-resolvable-private": "NRPA · private random · non-resolvable",
        "random": "random · privacy subtype unknown",
        "random-reserved": "random · reserved bit pattern",
        "anonymous": "anonymous · no device address",
        "platform-opaque": "OS UUID · physical MAC hidden",
        "unknown": "unknown",
        "": "unknown",
    }.get(address_type, address_type)


def _exposure_cell(finding: ExposureFinding | None) -> Text | str:
    if finding is None:
        return ""
    label, style = _SEVERITY_STYLES[finding.severity]
    return Text(label, style=style)


def _read_error_cell(error: str) -> Text:
    """Compact table status; the complete transport error belongs in detail."""
    lowered = error.casefold()
    if "read not permitted" in lowered:
        label = "READ DENIED"
    elif "timeout" in lowered or "timed out" in lowered:
        label = "TIMEOUT"
    elif "authentication" in lowered:
        label = "AUTH REQUIRED"
    elif "authorization" in lowered:
        label = "NOT AUTHORIZED"
    elif "encryption" in lowered:
        label = "ENCRYPTION REQUIRED"
    else:
        label = "READ ERROR"
    return Text(label, style="bold red")


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


def gatt_payload_hex(value_hex: str) -> str | None:
    """When the characteristic holds an ASCII hex string, return decoded binary (spaced hex)."""
    ascii_text = gatt_ascii(value_hex)
    if not ascii_text or len(ascii_text) % 2:
        return None
    if any(ch not in "0123456789abcdefABCDEF" for ch in ascii_text):
        return None
    try:
        return bytes.fromhex(ascii_text).hex(" ")
    except ValueError:
        return None


def gatt_payload_text(payload_hex: str) -> str | None:
    """Printable ASCII view of decoded payload bytes ('.' for non-printable)."""
    parts = payload_hex.split(" ")
    if not parts or any(len(part) != 2 for part in parts):
        return None
    try:
        raw = bytes(int(part, 16) for part in parts)
    except ValueError:
        return None
    if raw.hex(" ") != payload_hex:
        return None
    if not raw:
        return None
    return "".join(
        chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in raw
    )


def gatt_value_detail_markup(value: str, value_hex: str) -> str:
    """Detail panel: distinguish payload hex, printable text, and on-wire raw bytes."""
    if not value:
        return "[dim]not read[/dim]"
    if value_hex and value != value_hex:
        return (
            f"[dim]Decoded[/dim]\n{escape(value)}\n\n"
            f"[dim]Raw bytes[/dim]\n{escape(value_hex)}"
        )
    wire = value_hex or value
    ascii_text = gatt_ascii(wire)
    payload = gatt_payload_hex(wire)
    if payload is not None and ascii_text is not None:
        payload_text = gatt_payload_text(payload) or ""
        return (
            f"[dim]Payload (hex)[/dim]\n{escape(payload)}\n\n"
            f"[dim]ASCII (from payload)[/dim]\n{escape(payload_text)}\n\n"
            f"[dim]Raw bytes[/dim]\n{escape(wire)}"
        )
    if ascii_text is not None:
        return (
            f"[dim]ASCII[/dim]\n{escape(ascii_text)}\n\n"
            f"[dim]Raw bytes[/dim]\n{escape(wire)}"
        )
    return escape(value)


def gatt_display_value(value: str, value_hex: str, *, ascii_mode: bool) -> str:
    """Characteristic text, using ASCII only for an undecoded printable dump."""
    if not ascii_mode or not value_hex or value != value_hex:
        return value
    payload = gatt_payload_hex(value_hex)
    if payload is not None:
        return payload
    return gatt_ascii(value_hex) or value


def _exposure_detail(finding: ExposureFinding | None) -> str:
    if finding is None:
        return "[dim]none observed[/dim]"
    label, style = _SEVERITY_STYLES[finding.severity]
    detail = f"[{style}]{label}[/] {escape(finding.reason)}"
    if finding.severity > ExposureSeverity.LOW:
        detail += "\n[dim]Advertised only: the device may still reject unencrypted writes.[/dim]"
    return detail


def _local_adapter_art(backend: str, transport: str = "BLE") -> Text:
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
    transport = transport[:7].upper()
    text_row = ("█▒█▒" + f"  Wifit3-ng  {transport:<7}" + "▒█▒█").center(width)
    lines[next(index for index, line in enumerate(lines) if "Wifit3-ng" in line)] = text_row
    art = Text(no_wrap=True)
    for line in lines:
        rendered = Text(f"{line:^{width}}", style="grey70")
        for label, style in (
            ("Wifit3-ng", "bold cyan"),
            (transport, "bold rgb(0,120,255)"),
        ):
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
    role = "CENTRAL" if transport == "BLE" else "USB HCI"
    backend_label = f"{backend} • {transport} {role}"
    if len(backend_label) > width:
        backend_label = backend_label[: width - 1] + "…"
    art.append(f"{backend_label:^{width}}", style="cyan")
    return art


def _bluetooth_device_art(
    inspection: BluetoothInspection | None,
    *,
    device: BluetoothDevice | None = None,
    fallback_name: str = "BLUETOOTH DEVICE",
    fallback_identifier: str = "Waiting for connection",
) -> Text:
    width = 30

    def centered(value: str) -> str:
        clipped = value if len(value) <= width else value[: width - 1] + "…"
        return f"{clipped:^{width}}"

    device = inspection.device if inspection is not None else device
    name = device.name if device is not None else fallback_name
    identifier = device.identifier if device is not None else fallback_identifier
    manufacturer = (
        manufacturer_label(device.manufacturer_ids, device.identifier) or "Unknown"
        if device is not None else "REMOTE BLUETOOTH ENDPOINT"
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
    if device is not None and device.catalog_labels:
        family = " · ".join(device.catalog_labels[:2])
        if device.catalog_attention:
            family = f"◆ {family}"
        style = "bold yellow" if device.catalog_attention else "bold cyan"
        art.append(centered(family), style=style)
        art.append("\n")
    if device is not None and device.decode_state:
        art.append(centered(device.decode_state), style="bold yellow")
        art.append("\n")
    elif device is not None and device.catalog_live:
        style = "bold yellow" if device.catalog_live_strong else "yellow"
        art.append(centered(device.catalog_live), style=style)
        art.append("\n")
    if device is not None:
        art.append(centered(f"{device.rssi} dBm"), style=dbm_style(device.rssi))
        art.append("\n")
    art.append(centered(identifier), style="dim")
    return art


def _catalog_block(device) -> str:
    lines = catalog_detail_lines(device)
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _status_with_catalog(primary: str, device) -> str:
    extra = catalog_status_line(device)
    if not extra:
        return primary
    return f"{primary}\n{extra}"


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
    _CLASSIC_ROWS = [
        ("event_packets", "events", "cyan"),
        ("classic_observations", "classic", "blue"),
        ("inquiry_completions", "inquiry", "yellow"),
        ("remote_name_requests", "name >", "magenta"),
        ("remote_name_successes", "name ok", "green"),
        ("read_errors", "errors", "red"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._inspection: BluetoothInspection | None = None
        self._classic_device: BluetoothDevice | None = None
        self._classic_health = None
        self._previous: dict[str, int] = {}
        self._history = {key: deque([0] * 128, maxlen=128) for key, _label, _color in self._ROWS}
        self._classic_previous: dict[str, int] = {}
        self._classic_history = {
            key: deque([0] * 128, maxlen=128)
            for key, _label, _color in self._CLASSIC_ROWS
        }

    def on_mount(self) -> None:
        self.set_interval(0.4, self._sample)

    def on_resize(self) -> None:
        if self._classic_device is not None:
            self._paint_classic()
        else:
            self._paint()

    def bind(self, inspection: BluetoothInspection | None) -> None:
        if (
            inspection is self._inspection
            and self._classic_device is None
        ):
            return
        self._inspection = inspection
        self._classic_device = None
        self._classic_health = None
        self._previous = {}
        self._history = {
            key: deque([0] * 128, maxlen=128) for key, _label, _color in self._ROWS
        }
        self._sample()

    def bind_classic(self, device: BluetoothDevice, health) -> None:
        changed = device is not self._classic_device
        self._inspection = None
        self._classic_device = device
        self._classic_health = health
        if changed:
            self._classic_previous = {}
            self._classic_history = {
                key: deque([0] * 128, maxlen=128)
                for key, _label, _color in self._CLASSIC_ROWS
            }
        self._sample_classic()

    def _sample(self) -> None:
        if self.is_mounted and self.app.screen is not self.screen:
            return
        if self._classic_device is not None:
            self._sample_classic()
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

    def _sample_classic(self) -> None:
        health = self._classic_health
        for key, _label, _color in self._CLASSIC_ROWS:
            current = getattr(health, key, 0) if health is not None else 0
            previous = self._classic_previous.get(key, current)
            self._classic_history[key].append(max(0, current - previous))
            self._classic_previous[key] = current
        self._paint_classic()

    def _paint_classic(self) -> None:
        device = self._classic_device
        if device is None:
            return
        health = self._classic_health
        width = max(8, (self.content_size.width or 40) - 14)
        lines = [Text("CONTROLLER / CLASSIC PACKET FLOW", style="bold cyan")]
        for key, label, color in self._CLASSIC_ROWS:
            values = list(self._classic_history[key])[-width:]
            peak = max(max(values, default=0), 1)
            total = getattr(health, key, 0) if health is not None else 0
            style = color if any(values) else f"dim {color}"
            bars = "".join(
                self._BLOCKS[
                    1 if value <= 0 else max(1, min(8, round(value * 8 / peak)))
                ]
                for value in values
            )
            lines.append(self._traffic_row(label, bars, str(total), style))
        lines.extend([
            Text(""),
            Text(
                f"OBSERVATIONS  {device.advertisement_count}    "
                f"SIGNAL  {device.rssi} dBm",
                style="bold white",
            ),
        ])
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
    """Unified, transport-aware focus for BLE/GATT and Classic/SDP devices."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "read_selected", "Read selected"),
        Binding("a", "toggle_ascii", "ASCII"),
        Binding("y", "open_catalog", "Catalog"),
        Binding("n", "targets_editor", "Targets"),
    ]

    CSS = """
    BluetoothFocusView { layout: vertical; background: $surface; }
    #bt-top { height: 3; }
    #bt-top Button { height: 3; width: auto; min-width: 0; margin-right: 1; }
    #bt-sdp { display: none; }
    #bt-status { width: 1fr; height: 3; content-align: center middle; text-align: center; }
    #ble-recording { width: 24; height: 3; content-align: center middle; text-align: center; }
    #bt-mid { height: 22; }
    #bt-local {
        width: 40; height: 100%; padding: 0;
        content-align: center middle; background: transparent;
    }
    #bt-center { width: 1fr; height: 100%; }
    #bt-connection {
        width: 100%; height: 6; padding: 0 1;
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
        self._classic_sdp_services: dict[str, str] = {}
        self._classic_sdp_trace: tuple[str, ...] = ()
        self._classic_identifier = ""
        self._classic_browsing = False
        self._observed_inspection: BluetoothInspection | None = None

    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Horizontal(id="bt-top"):
            yield Button("‹ Bluetooth", id="bt-back")
            yield Button("Browse SDP", id="bt-sdp", variant="primary")
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
                ("SERVICE / PROFILE", "service"),
                ("UUID / CHARACTERISTIC", "characteristic"),
                ("CAPABILITIES", "properties"),
                ("VALUE / SOURCE", "value"),
                ("POSTURE", "exposure"),
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
        if self._inspection() is None and self._classic_device() is not None:
            # A newly-entered Classic focus performs a fresh public SDP inventory.
            self._classic_identifier = ""
        self._refresh()

    def _inspection(self) -> BluetoothInspection | None:
        connection = self.app.bluetooth_manager.connection
        return connection.inspection if connection is not None else None

    def _classic_device(self) -> BluetoothDevice | None:
        device = self.app.bluetooth_manager.classic_focus_device
        if device is None or CLASSIC_RADIO not in device.radio_types:
            return None
        return device

    def _refresh(self) -> None:
        if self.app.screen is not self:
            return
        inspection = self._inspection()
        classic = self._classic_device() if inspection is None else None
        observation_mode = False
        if inspection is None and classic is None:
            observed = self.app.bluetooth_manager.focus_device
            if observed is not None:
                observation_mode = True
                if (
                    self._observed_inspection is None
                    or self._observed_inspection.device is not observed
                ):
                    self._observed_inspection = BluetoothInspection(device=observed)
                self._observed_inspection.disconnected_reason = (
                    self.app.bluetooth_manager.focus_connection_error
                )
                inspection = self._observed_inspection
        transport = "BLE" if inspection is not None else "CLASSIC" if classic else "BT"
        self.query_one("#bt-local", Static).update(
            _local_adapter_art(self.app.bluetooth_manager.backend_name, transport)
        )
        self.query_one("#ble-recording", Static).update(recording_indicator(
            f"{transport} EVENT RECORDING",
            getattr(self.app, "bluetooth_target_capture", None) is not None,
        ))
        sdp_button = self.query_one("#bt-sdp", Button)
        sdp_button.display = classic is not None
        if classic is not None:
            new_classic_target = classic.identifier != self._classic_identifier
            if new_classic_target:
                self._classic_identifier = classic.identifier
                self._classic_sdp_services.clear()
                self._classic_sdp_trace = ()
                self._table_signature = None
            self.query_one("#bt-traffic", _BluetoothTrafficDashboard).bind_classic(
                classic,
                self.app.bluetooth_manager.hci_health,
            )
            self._update_classic_summary(classic)
            self._sync_classic_table(classic)
            if new_classic_target:
                self.call_after_refresh(self.browse_classic_sdp)
            return
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
            not observation_mode
            and not inspection.connected
            and not inspection.connecting
            and not self._reconnecting
            and locked is not None
            and locked.medium == "bluetooth"
            and locked.identifier.casefold() == inspection.device.identifier.casefold()
        ):
            self.reconnect_target(inspection.device)
        self._update_summary(inspection)
        self._sync_table(inspection)

    def _update_classic_summary(self, device: BluetoothDevice) -> None:
        classification = device_classification(device)
        manufacturer = (
            manufacturer_label(device.manufacturer_ids, device.identifier)
            or "Unknown"
        )
        dual = BLE_RADIO in device.radio_types
        mode = "DUAL MODE · CLASSIC VIEW" if dual else "CLASSIC / BR-EDR"
        if self._classic_browsing:
            status = "[bold yellow]● ENUMERATING SDP[/bold yellow]"
        else:
            status = "[bold cyan]● OBSERVED[/bold cyan]"
        self.query_one("#bt-status", Static).update(
            _status_with_catalog(
                f"{status}  {escape(device.name)}  [dim]{mode}[/dim]",
                device,
            ),
        )
        self.query_one("#bt-device", Static).update(
            _bluetooth_device_art(None, device=device),
        )
        address_kind = _address_kind_label(device.address_type)
        relation = (
            f"\n[dim]Related IDs[/dim] {len(device.related_identifiers)}  •  "
            f"[dim]Correlation[/dim] {escape(device.correlation_confidence or 'none')}"
            if dual or device.related_identifiers else ""
        )
        self.query_one("#bt-connection", Static).update(
            "[cyan]╼━━━━━━━━━━━━[/cyan]"
            "[bold cyan]━━●━━━━━━━━━━━━▶[/bold cyan]\n"
            f"[bold cyan]{mode}[/bold cyan]  [bold green]DISCOVERED[/bold green]  "
            f"[bold bright_blue]→ {escape(device.name)}[/bold bright_blue]\n"
            f"[dim]Signal[/dim] {device.rssi} dBm  •  "
            f"[dim]Observations[/dim] {device.advertisement_count}  •  "
            f"[dim]Services[/dim] {len(device.service_uuids)}\n"
            f"[dim]Type[/dim] {escape(classification.category)} / "
            f"{escape(classification.detail)}  •  "
            f"[dim]Vendor[/dim] {escape(manufacturer)}\n"
            f"[dim]Address[/dim] {escape(device.address_type)} · "
            f"{escape(address_kind)}"
            f"{relation}"
        )

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
            _status_with_catalog(
                f"[bold {state_color}]● {state}[/bold {state_color}]  "
                f"{escape(device.name)}{target_status}",
                device,
            ),
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
        transport_label = self.app.bluetooth_manager.connection_transport_label()
        via = (
            f"[dim]via[/dim] [bold]{escape(transport_label)}[/bold]  "
            if transport_label and inspection.connected else ""
        )
        self.query_one("#bt-connection", Static).update(
            f"[cyan]╼━━━━━━━━━━━━[/cyan]"
            f"[bold {state_color}]━━●━━━━━━━━━━━━▶[/bold {state_color}]\n"
            f"[bold cyan]BLE / GATT[/bold cyan]  "
            f"[bold {state_color}]{state}{state_duration}[/bold {state_color}]  "
            f"{via}"
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
        signature = ("ble",) + tuple(
            (
                characteristic.handle,
                characteristic.value,
                characteristic.read_error,
                characteristic.notifications,
                tuple(
                    (
                        descriptor.handle,
                        descriptor.value,
                        descriptor.read_error,
                    )
                    for descriptor in characteristic.descriptors
                ),
            )
            for service in inspection.services
            for characteristic in service.characteristics
        )
        if signature == self._table_signature:
            return
        self._table_signature = signature
        table = self.query_one("#gatt-table", DataTable)
        table.clear(columns=False)
        table.add_row(
            "DEVICE OVERVIEW",
            inspection.device.identifier,
            inspection.device.radio_label,
            inspection.device.discovery_source,
            "CONNECTED" if inspection.connected else "DISCONNECTED",
            key="ble:overview",
        )
        findings = {finding.handle: finding for finding in assess_exposure(inspection)}
        for service in inspection.services:
            for characteristic in service.characteristics:
                if characteristic.value:
                    value = Text(self._shown_value(characteristic))
                elif characteristic.read_error:
                    value = _read_error_cell(characteristic.read_error)
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
                for descriptor in characteristic.descriptors:
                    descriptor_value = descriptor.value
                    if descriptor.read_error:
                        descriptor_value = _read_error_cell(
                            descriptor.read_error,
                        )
                    table.add_row(
                        f"  ↳ {characteristic.name}",
                        descriptor.name,
                        "GATT descriptor",
                        descriptor_value,
                        "METADATA",
                        key=(
                            f"descriptor:{characteristic.handle}:"
                            f"{descriptor.handle}"
                        ),
                    )
        if table.row_count:
            table.move_cursor(row=0, animate=False)
            self._show_characteristic(str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value))

    def _sync_classic_table(self, device: BluetoothDevice) -> None:
        uuids = tuple(sorted(set(device.service_uuids) | set(self._classic_sdp_services)))
        signature = (
            "classic",
            device.identifier,
            device.advertisement_count,
            self._classic_browsing,
            self._classic_sdp_trace,
            *(
                (uuid, self._classic_sdp_services.get(uuid, ""))
                for uuid in uuids
            ),
        )
        if signature == self._table_signature:
            return
        self._table_signature = signature
        table = self.query_one("#gatt-table", DataTable)
        table.clear(columns=False)
        table.add_row(
            "DEVICE OVERVIEW",
            device.identifier,
            device.radio_label,
            device.discovery_source,
            device.baseline_status,
            key="classic:overview",
        )
        latest_trace = (
            self._classic_sdp_trace[-1]
            if self._classic_sdp_trace
            else "Automatic enumeration pending"
        )
        table.add_row(
            "SDP PROTOCOL TRACE",
            "PDU 0x06 → 0x07",
            "HCI · L2CAP · SDP",
            latest_trace,
            "RUNNING" if self._classic_browsing else "READ-ONLY",
            key="classic:trace",
        )
        for uuid in uuids:
            browsed_name = self._classic_sdp_services.get(uuid, "")
            name = browsed_name or service_label(uuid)
            source = "public SDP browse" if uuid in self._classic_sdp_services else "discovery / cached"
            posture = "READ-ONLY" if uuid in self._classic_sdp_services else "KNOWN"
            capability = (
                "Classic SDP profile"
                if uuid in self._classic_sdp_services
                else "service UUID (transport unconfirmed)"
            )
            table.add_row(
                name,
                uuid,
                capability,
                source,
                posture,
                key=f"classic:{uuid}",
            )
        self._show_classic_overview(device)
        if table.row_count:
            table.move_cursor(row=0, animate=False)
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            self._show_classic_service(str(row_key.value))

    def _show_classic_overview(self, device: BluetoothDevice) -> None:
        classification = device_classification(device)
        manufacturer = (
            manufacturer_label(device.manufacturer_ids, device.identifier)
            or "Unknown"
        )
        duration = max(0.0, device.last_seen - device.first_seen)
        average = (
            f"{device.rssi_average:.1f} dBm"
            if device.rssi_average is not None else "unavailable"
        )
        related = (
            "\n".join(f"  • {escape(identifier)}" for identifier in device.related_identifiers)
            or "  none"
        )
        self.query_one("#gatt-detail", Static).border_title = "DEVICE / CLASSIC"
        self.query_one("#gatt-detail", Static).update(
            f"[bold cyan]{escape(device.name)}[/bold cyan]\n"
            f"[dim]{escape(device.identifier)}[/dim]\n\n"
            f"[bold]Identity[/bold]\n"
            f"[dim]Vendor[/dim] {escape(manufacturer)}\n"
            f"[dim]Category[/dim] {escape(classification.category)} · "
            f"{escape(classification.detail)}\n"
            f"[dim]Evidence[/dim] {escape(classification.source)} "
            f"({escape(classification.confidence)})\n"
            f"[dim]Class of device[/dim] "
            f"{f'0x{device.class_of_device:06x}' if device.class_of_device is not None else 'unknown'}\n\n"
            f"[bold]Address & privacy[/bold]\n"
            f"[dim]Type[/dim] {escape(device.address_type)}\n"
            f"[dim]Kind[/dim] {escape(_address_kind_label(device.address_type))}\n\n"
            f"[bold]Observation[/bold]\n"
            f"[dim]Current / average[/dim] {device.rssi} / {average}\n"
            f"[dim]Samples[/dim] {device.rssi_samples} · "
            f"[dim]Seen for[/dim] {duration:.1f}s\n"
            f"[dim]Page scan repetition[/dim] {device.page_scan_repetition_mode}\n"
            f"[dim]Clock offset[/dim] {device.clock_offset}\n\n"
            f"[bold]BT/BLE correlation[/bold]\n"
            f"[dim]Confidence[/dim] {escape(device.correlation_confidence or 'none')}\n"
            f"{related}\n"
            f"[dim]{escape(', '.join(device.correlation_evidence) or 'No correlation evidence')}[/dim]"
        )

    def _show_classic_service(self, row_key: str) -> None:
        if not row_key.startswith("classic:"):
            return
        uuid = row_key.removeprefix("classic:")
        if uuid == "overview":
            device = self._classic_device()
            if device is not None:
                self._show_classic_overview(device)
            return
        if uuid == "trace":
            trace = (
                "\n".join(
                    f"[cyan]•[/cyan] {escape(line)}"
                    for line in self._classic_sdp_trace
                )
                or "[dim]Automatic SDP enumeration has not produced protocol events yet.[/dim]"
            )
            self.query_one("#gatt-detail", Static).border_title = "SDP PROTOCOL TRACE"
            self.query_one("#gatt-detail", Static).update(
                "[bold]Read-only exchange[/bold]\n"
                "[dim]HCI → ACL → L2CAP PSM 0x0001 → SDP[/dim]\n\n"
                f"{trace}",
            )
            return
        name = self._classic_sdp_services.get(uuid) or service_label(uuid)
        source = (
            "Fresh public SDP browse"
            if uuid in self._classic_sdp_services
            else "Discovery advertisement or cached profile"
        )
        self.query_one("#gatt-detail", Static).border_title = "CLASSIC SERVICE"
        self.query_one("#gatt-detail", Static).update(
            f"[bold cyan]{escape(name)}[/bold cyan]\n"
            f"[dim]{escape(uuid)}[/dim]\n\n"
            f"[dim]Transport[/dim]\nBluetooth Classic / BR/EDR\n\n"
            f"[dim]Source[/dim]\n{escape(source)}\n\n"
            "[dim]Access[/dim]\nPublic, read-only SDP metadata\n\n"
            "[dim]Note[/dim]\nA listed profile is advertised capability; "
            "using that profile may still require pairing or authorization."
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None:
            key = str(event.row_key.value)
            if key.startswith("classic:"):
                self._show_classic_service(key)
            else:
                self._show_characteristic(key)

    def _show_characteristic(self, handle: str) -> None:
        inspection = self._inspection() or self._observed_inspection
        if inspection is None:
            return
        if handle == "ble:overview":
            self._show_ble_overview(inspection)
            return
        if handle.startswith("descriptor:"):
            self._show_descriptor(inspection, handle)
            return
        findings = {finding.handle: finding for finding in assess_exposure(inspection)}
        for service in inspection.services:
            for characteristic in service.characteristics:
                if str(characteristic.handle) != handle:
                    continue
                value = self._value_markup(characteristic)
                property_details = "\n".join(
                    f"  [cyan]•[/cyan] [bold]{escape(property_name)}[/bold] - "
                    f"{escape(characteristic_property_detail(property_name))}"
                    for property_name in characteristic.properties
                ) or "  [dim]none advertised[/dim]"
                source = uuid_metadata_source(
                    characteristic.uuid,
                    kind="characteristic",
                )
                service_source = uuid_metadata_source(
                    service.uuid,
                    kind="service",
                )
                self.query_one("#gatt-detail", Static).border_title = "CHARACTERISTIC"
                self.query_one("#gatt-detail", Static).update(
                    f"[bold]{escape(characteristic.name)}[/bold]\n"
                    f"[dim]{escape(characteristic.uuid)}[/dim]\n\n"
                    f"[dim]Service[/dim]\n{escape(service.name)}\n"
                    f"[dim]Service metadata[/dim] {escape(service_source)}\n\n"
                    f"[dim]Metadata source[/dim]\n{escape(source)}\n\n"
                    f"[dim]Advertised properties[/dim]\n{property_details}\n\n"
                    f"[dim]Value[/dim]\n{value}\n\n"
                    f"[dim]Read result[/dim]\n"
                    f"{('[red]' + escape(characteristic.read_error) + '[/red]') if characteristic.read_error else '[green]No read error[/green]'}\n\n"
                    f"[dim]Notifications[/dim] {characteristic.notifications} "
                    f"({characteristic.notification_bytes} B)\n\n"
                    f"[dim]Exposure[/dim]\n{_exposure_detail(findings.get(characteristic.handle))}"
                )
                return

    def _show_descriptor(
        self,
        inspection: BluetoothInspection,
        row_key: str,
    ) -> None:
        try:
            _prefix, characteristic_handle, descriptor_handle = row_key.split(":")
            characteristic_id = int(characteristic_handle)
            descriptor_id = int(descriptor_handle)
        except ValueError:
            return
        for service in inspection.services:
            for characteristic in service.characteristics:
                if characteristic.handle != characteristic_id:
                    continue
                for descriptor in characteristic.descriptors:
                    if descriptor.handle != descriptor_id:
                        continue
                    value = descriptor.value or "[dim]not read[/dim]"
                    if descriptor.read_error:
                        value = f"[red]{escape(descriptor.read_error)}[/red]"
                    self.query_one("#gatt-detail", Static).border_title = (
                        "GATT DESCRIPTOR"
                    )
                    self.query_one("#gatt-detail", Static).update(
                        f"[bold cyan]{escape(descriptor.name)}[/bold cyan]\n"
                        f"[dim]{escape(descriptor.uuid)}[/dim]\n\n"
                        f"[dim]Handle[/dim] 0x{descriptor.handle:04x}\n"
                        f"[dim]Characteristic[/dim] "
                        f"{escape(characteristic.name)} "
                        f"(0x{characteristic.handle:04x})\n"
                        f"[dim]Service[/dim] {escape(service.name)}\n\n"
                        f"[dim]Decoded value[/dim]\n{value}\n\n"
                        f"[dim]Raw bytes[/dim]\n"
                        f"{escape(descriptor.value_hex or 'unavailable')}\n\n"
                        "[dim]Source[/dim]\n"
                        "Live ATT/GATT descriptor discovery; label from "
                        "Bluetooth SIG Assigned Numbers."
                    )
                    return

    def _show_ble_overview(self, inspection: BluetoothInspection) -> None:
        device = inspection.device
        classification = device_classification(device)
        manufacturer = (
            manufacturer_label(device.manufacturer_ids, device.identifier)
            or "Unknown"
        )
        characteristic_count = sum(
            len(service.characteristics) for service in inspection.services
        )
        related = (
            "\n".join(f"  • {escape(identifier)}" for identifier in device.related_identifiers)
            or "  none"
        )
        state = (
            "connected" if inspection.connected
            else "connecting" if inspection.connecting
            else "disconnected"
        )
        self.query_one("#gatt-detail", Static).border_title = "DEVICE / BLE"
        self.query_one("#gatt-detail", Static).update(
            f"[bold cyan]{escape(device.name)}[/bold cyan]\n"
            f"[dim]{escape(device.identifier)}[/dim]\n\n"
            f"[bold]Connection[/bold]\n"
            f"[dim]State[/dim] {state}\n"
            f"[dim]Reason[/dim] {escape(inspection.disconnected_reason or 'none')}\n"
            f"[dim]Services / characteristics[/dim] "
            f"{len(inspection.services)} / {characteristic_count}\n\n"
            f"[bold]Identity[/bold]\n"
            f"[dim]Vendor[/dim] {escape(manufacturer)}\n"
            f"[dim]Category[/dim] {escape(classification.category)} · "
            f"{escape(classification.detail)}\n"
            f"[dim]Protocol[/dim] {escape(device.protocol_type or 'unknown')} "
            f"({escape(device.protocol_confidence or 'n/a')})\n"
            + _catalog_block(device)
            + "\n"
            f"[bold]Address & privacy[/bold]\n"
            f"[dim]Type[/dim] {escape(device.address_type)}\n"
            f"[dim]Kind[/dim] {escape(_address_kind_label(device.address_type))}\n\n"
            f"[bold]Observation[/bold]\n"
            f"[dim]Signal[/dim] {device.rssi} dBm · "
            f"[dim]Samples[/dim] {device.rssi_samples}\n"
            f"[dim]Advertisements[/dim] {device.advertisement_count}\n"
            f"[dim]Payload / profile[/dim] "
            f"{escape(device.payload_fingerprint or 'none')} / "
            f"{escape(device.profile_fingerprint or 'none')}\n\n"
            f"[bold]BT/BLE correlation[/bold]\n"
            f"[dim]Confidence[/dim] {escape(device.correlation_confidence or 'none')}\n"
            f"{related}"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bt-back":
            self.action_go_back()
        elif event.button.id == "bt-sdp":
            self.browse_classic_sdp()

    def action_targets_editor(self) -> None:
        inspection = self._inspection()
        device = inspection.device if inspection is not None else (
            self._classic_device() or self.app.bluetooth_manager.focus_device
        )
        self.app.open_targets_editor(
            prefill=bluetooth_candidate(device) if device is not None else None,
        )


    def action_open_catalog(self) -> None:
        from wifit3.ui.screens.catalog import open_catalog

        open_catalog(self)

    def action_go_back(self) -> None:
        self.disconnect_and_return()

    def action_read_selected(self) -> None:
        if self._classic_device() is not None and self._inspection() is None:
            self.browse_classic_sdp()
            return
        self.read_selected()

    def action_toggle_ascii(self) -> None:
        if self._inspection() is None:
            return
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
        short = compact_uuid(characteristic.uuid)
        if short == "2a24" and characteristic.value and not self._show_ascii:
            friendly = format_device_model_number(characteristic.value)
            if friendly:
                return friendly
        return gatt_display_value(
            characteristic.value,
            characteristic.value_hex,
            ascii_mode=self._show_ascii,
        )

    def _value_markup(self, characteristic) -> str:
        markup = gatt_value_detail_markup(
            characteristic.value or "",
            characteristic.value_hex or "",
        )
        short = compact_uuid(characteristic.uuid)
        if short == "2a24" and characteristic.value:
            product = format_device_model_number(characteristic.value, detail=True)
            if product:
                markup += f"\n\n[dim]Product name[/dim]\n[bold cyan]{escape(product)}[/bold cyan]"
        elif short == "2a50" and characteristic.value_hex:
            try:
                raw = bytes.fromhex(characteristic.value_hex.replace(" ", ""))
            except ValueError:
                raw = b""
            decoded = decode_pnp_id(raw, detail=True)
            if decoded:
                markup += f"\n\n[dim]PnP identity[/dim]\n[bold cyan]{escape(decoded)}[/bold cyan]"
        return markup

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
                    self.app.notify(
                        "Bluetooth target reacquired",
                        title="Target lock",
                        persist=True,
                    )
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
        if not str(row_key.value).isdigit():
            self.notify(
                "Select a readable GATT characteristic first.",
                severity="warning",
            )
            return
        handle = int(row_key.value)
        characteristic = next(
            (
                characteristic
                for service in connection.inspection.services
                for characteristic in service.characteristics
                if characteristic.handle == handle
            ),
            None,
        )
        if characteristic is None or "read" not in characteristic.properties:
            properties = (
                ", ".join(characteristic.properties)
                if characteristic is not None and characteristic.properties
                else "none advertised"
            )
            self.notify(
                "No ATT request was sent: this characteristic does not advertise "
                f"the read property ({properties}).",
                title="GATT read not permitted locally",
                severity="warning",
            )
            return
        try:
            await connection.read_characteristic(handle)
        except Exception as exc:
            self.notify(str(exc), title="GATT read failed", severity="error")

    @work(exclusive=True, group="classic-sdp")
    async def browse_classic_sdp(self) -> None:
        device = self._classic_device()
        if device is None:
            self.notify(
                "SDP is available only for Bluetooth Classic devices.",
                severity="warning",
            )
            return
        self._classic_browsing = True
        self._table_signature = None
        self.query_one("#bt-status", Static).update(
            f"[bold yellow]● BROWSING PUBLIC SDP[/bold yellow]  "
            f"{escape(device.name)}"
        )
        try:
            services = await self.app.bluetooth_manager.browse_classic_sdp(
                device.identifier,
            )
        except BluetoothScanError as exc:
            self.notify(
                str(exc),
                title="Classic SDP unavailable",
                severity="warning",
            )
        except Exception as exc:
            self.notify(str(exc), title="Classic SDP failed", severity="error")
        else:
            self._classic_sdp_services = {
                service.uuid: service.name
                for service in services
            }
            self._table_signature = None
            self.notify(
                f"Found {len(services)} public service classes",
                title="Classic SDP complete",
            )
        finally:
            self._classic_sdp_trace = (
                self.app.bluetooth_manager.classic_sdp_trace
            )
            self._classic_browsing = False
            self._table_signature = None
            self._refresh()

    @work(exclusive=True)
    async def disconnect_and_return(self) -> None:
        if self._inspection() is not None:
            await self.app.bluetooth_manager.disconnect()
            self.app.stop_bluetooth_target_capture()
            try:
                await self.app.bluetooth_manager.resume_scan()
            except Exception as exc:
                self.notify(str(exc), title="Bluetooth scan failed", severity="error")
        self.app.pop_screen()

