"""HackRF swept-spectrum view for Wi-Fi, Bluetooth, and BLE bands."""
from __future__ import annotations

import math
import statistics
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult, RenderResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label, Select, Static

from wifit3.sdr.sweep import (
    HACKRF_LNA_GAINS,
    HACKRF_VGA_GAINS,
    HackRfSweep,
    HackRfSweepError,
    SpectrumPoint,
)
from wifit3.ui.notification_center import WifiteHeader
from wifit3.ui.signal_bar import dbm_style
from wifit3.wlan.channels import CHANNELS_2G, CHANNELS_5G

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


@dataclass(frozen=True, slots=True)
class SpectrumSpan:
    label: str
    start_mhz: int
    stop_mhz: int


@dataclass(frozen=True, slots=True)
class RfChannel:
    key: str
    technology: str
    label: str
    center_mhz: float
    width_mhz: float


SPANS = {
    "all": SpectrumSpan("Wi-Fi + BT/BLE · 2.4–6.0 GHz", 2400, 6000),
    "2g": SpectrumSpan("2.4 GHz Wi-Fi + BT/BLE", 2400, 2500),
    "5g": SpectrumSpan("5 GHz Wi-Fi", 5150, 5925),
    "6g": SpectrumSpan("Low 6 GHz Wi-Fi · HackRF limit", 5925, 6000),
    "bt": SpectrumSpan("Bluetooth + BLE", 2400, 2485),
}


def wifi_channel_frequency_mhz(band: str, channel: int) -> float:
    if band == "2g":
        return 2484.0 if channel == 14 else 2407.0 + 5 * channel
    if band == "5g":
        return 5000.0 + 5 * channel
    if band == "6g":
        return 5950.0 + 5 * channel
    raise ValueError(f"unknown Wi-Fi band: {band}")


def bluetooth_channel_frequency_mhz(channel: int) -> float:
    if not 0 <= channel <= 78:
        raise ValueError(f"invalid Bluetooth Classic channel: {channel}")
    return 2402.0 + channel


def ble_channel_frequency_mhz(channel: int) -> float:
    if not 0 <= channel <= 39:
        raise ValueError(f"invalid BLE channel: {channel}")
    if channel == 37:
        return 2402.0
    if channel == 38:
        return 2426.0
    if channel == 39:
        return 2480.0
    if channel <= 10:
        return 2404.0 + 2 * channel
    return 2406.0 + 2 * channel


def rf_channels() -> tuple[RfChannel, ...]:
    channels = [
        RfChannel(
            f"2g:{channel}", "Wi-Fi 2.4", str(channel),
            wifi_channel_frequency_mhz("2g", channel), 20,
        )
        for channel in CHANNELS_2G
    ]
    channels.extend(
        RfChannel(
            f"5g:{channel}", "Wi-Fi 5", str(channel),
            wifi_channel_frequency_mhz("5g", channel), 20,
        )
        for channel in sorted(set(CHANNELS_5G) | {169, 173, 177})
    )
    channels.extend(
        RfChannel(
            f"6g:{channel}", "Wi-Fi 6", str(channel),
            wifi_channel_frequency_mhz("6g", channel), 20,
        )
        for channel in (1, 5, 9)
    )
    channels.extend(
        RfChannel(
            f"bt:{channel}",
            "BT Classic",
            str(channel),
            bluetooth_channel_frequency_mhz(channel),
            1,
        )
        for channel in range(79)
    )
    channels.extend(
        RfChannel(
            f"ble:{channel}",
            "BLE ADV" if channel >= 37 else "BLE DATA",
            str(channel),
            ble_channel_frequency_mhz(channel),
            2,
        )
        for channel in range(40)
    )
    return tuple(channels)


RF_CHANNELS = rf_channels()


def channels_in_span(span: SpectrumSpan) -> list[RfChannel]:
    return [
        channel for channel in RF_CHANNELS
        if channel.center_mhz + channel.width_mhz / 2 >= span.start_mhz
        and channel.center_mhz - channel.width_mhz / 2 <= span.stop_mhz
    ]


def selected_span(scope: str, channel_key: str) -> SpectrumSpan:
    scope_span = SPANS[scope]
    if channel_key == "__all__":
        return scope_span
    channel = next(channel for channel in RF_CHANNELS if channel.key == channel_key)
    start = max(scope_span.start_mhz, math.floor(channel.center_mhz - channel.width_mhz / 2))
    stop = min(scope_span.stop_mhz, math.ceil(channel.center_mhz + channel.width_mhz / 2))
    return SpectrumSpan(
        f"{channel.technology} channel {channel.label}",
        start,
        stop,
    )


def spectrum_bin_width_hz(span: SpectrumSpan) -> int:
    width_mhz = span.stop_mhz - span.start_mhz
    if width_mhz <= 40:
        return 100_000
    if width_mhz <= 120:
        return 250_000
    if width_mhz <= 1_000:
        return 500_000
    return 1_000_000


class SpectrumPlot(Static):
    DEFAULT_CSS = """
    SpectrumPlot {
        height: 15;
        border: round $primary;
        border-title-color: $accent;
        border-title-style: bold;
        padding: 0 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.start_mhz = 2400
        self.stop_mhz = 2500
        self.points: dict[int, float] = {}
        self.markers: list[RfChannel] = []
        self.highlight: RfChannel | None = None
        self.history: deque[dict[int, float]] = deque(maxlen=120)
        self._revision = 0
        self._snapshotted_revision = -1
        self.border_title = "LIVE RF POWER · dBFS"

    def reset(
        self,
        span: SpectrumSpan,
        channels: list[RfChannel],
        highlight: RfChannel | None = None,
    ) -> None:
        self.start_mhz = span.start_mhz
        self.stop_mhz = span.stop_mhz
        self.highlight = highlight
        self.points.clear()
        self.history.clear()
        self.markers = [
            channel for channel in channels
            if channel.technology.startswith("Wi-Fi")
        ]
        self._revision += 1
        self.refresh()

    def add_points(self, points: list[SpectrumPoint]) -> None:
        for point in points:
            frequency_mhz = point.frequency_hz / 1_000_000
            if self.start_mhz <= frequency_mhz <= self.stop_mhz:
                self.points[round(frequency_mhz * 10)] = point.power_dbfs
        self._revision += 1

    def snapshot(self) -> None:
        if self.points and self._snapshotted_revision != self._revision:
            self.history.append(dict(self.points))
            self._snapshotted_revision = self._revision

    def _column_powers(self, values: dict[int, float], width: int) -> list[float | None]:
        samples = sorted((frequency / 10, power) for frequency, power in values.items())
        if not samples:
            return [None] * width
        frequency_range = max(1, self.stop_mhz - self.start_mhz)
        columns = []
        sample_index = 0
        for index in range(width):
            frequency = self.start_mhz + (index + 0.5) / width * frequency_range
            while (
                sample_index + 1 < len(samples)
                and samples[sample_index + 1][0] <= frequency
            ):
                sample_index += 1
            candidates = samples[sample_index:sample_index + 2]
            nearest_frequency, nearest_power = min(
                candidates,
                key=lambda sample: abs(sample[0] - frequency),
            )
            max_gap = max(1.5, frequency_range / width * 2)
            columns.append(
                nearest_power if abs(nearest_frequency - frequency) <= max_gap else None
            )
        return columns

    @staticmethod
    def _heat_color(power: float | None) -> str:
        if power is None:
            return "#202630"
        if power >= -40:
            return "#d94b29"
        if power >= -55:
            return "#ffb000"
        if power >= -70:
            return "#26d9d9"
        if power >= -85:
            return "#3c78d8"
        return "#28344d"

    def _frequency_axis(self, width: int) -> str:
        axis = ["─"] * width
        for index in range(5):
            frequency = self.start_mhz + index / 4 * (self.stop_mhz - self.start_mhz)
            label = f"{frequency / 1000:.3f}"
            position = round(index / 4 * (width - 1))
            start = max(0, min(width - len(label), position - len(label) // 2))
            axis[start:start + len(label)] = label
        return "".join(axis)

    def _channel_axes(self, width: int) -> tuple[str, str]:
        rows = [[" "] * width, [" "] * width]
        occupied = [set(), set()]
        frequency_range = max(1, self.stop_mhz - self.start_mhz)
        for marker in sorted(self.markers, key=lambda channel: channel.center_mhz):
            label = f"│{marker.label}"
            position = round(
                (marker.center_mhz - self.start_mhz) / frequency_range * (width - 1)
            )
            start = max(0, min(width - len(label), position))
            slots = set(range(max(0, start - 1), min(width, start + len(label) + 1)))
            for row_index in range(2):
                if slots & occupied[row_index]:
                    continue
                rows[row_index][start:start + len(label)] = label
                occupied[row_index].update(slots)
                break
        return "".join(rows[0]), "".join(rows[1])

    def _band_axis(self, width: int) -> str:
        cells = [" "] * width
        frequency_range = max(1, self.stop_mhz - self.start_mhz)
        groups = (
            ("2.4 GHz", [marker for marker in self.markers
                         if marker.technology == "Wi-Fi 2.4"]),
            ("5 GHz", [marker for marker in self.markers
                       if marker.technology == "Wi-Fi 5"]),
            ("6 GHz", [marker for marker in self.markers
                       if marker.technology == "Wi-Fi 6"]),
        )
        for label, markers in groups:
            if not markers:
                continue
            center = statistics.mean(marker.center_mhz for marker in markers)
            position = round((center - self.start_mhz) / frequency_range * (width - 1))
            start = max(0, min(width - len(label), position - len(label) // 2))
            cells[start:start + len(label)] = label
        return "".join(cells)

    def _overlay_columns(self, width: int) -> tuple[int, int, int] | None:
        if self.highlight is None:
            return None
        frequency_range = max(1, self.stop_mhz - self.start_mhz)

        def column(frequency_mhz: float) -> int:
            fraction = (frequency_mhz - self.start_mhz) / frequency_range
            return round(max(0.0, min(1.0, fraction)) * (width - 1))

        half_width = self.highlight.width_mhz / 2
        return (
            column(self.highlight.center_mhz - half_width),
            column(self.highlight.center_mhz),
            column(self.highlight.center_mhz + half_width),
        )

    def render(self) -> RenderResult:
        width = max(24, self.size.width - 7)
        height = 7
        if not self.points:
            return Text.from_markup(
                "\n\n\n\n[dim]Waiting for receive-only IQ samples…[/dim]",
                justify="center",
            )
        columns = self._column_powers(self.points, width)
        overlay = self._overlay_columns(width)
        plot = Text()
        ceiling, floor = -20.0, -100.0
        for row in range(height):
            threshold = ceiling - row * (ceiling - floor) / (height - 1)
            plot.append(f"{int(threshold):>4} ")
            for column_index, power in enumerate(columns):
                if overlay is not None and column_index == overlay[1]:
                    plot.append("│", style="bold #ffb000")
                elif overlay is not None and column_index in (overlay[0], overlay[2]):
                    plot.append("┆", style="#ffb000")
                elif power is not None and power >= threshold:
                    style = self._heat_color(power)
                    if overlay is not None and overlay[0] < column_index < overlay[2]:
                        style += " on #18283d"
                    plot.append("█", style=style)
                else:
                    style = "dim #303844"
                    if overlay is not None and overlay[0] < column_index < overlay[2]:
                        style += " on #18283d"
                    plot.append("·", style=style)
            plot.append("\n")
        plot.append(" GHz " + self._frequency_axis(width) + "\n", style="dim")
        channel_row_1, channel_row_2 = self._channel_axes(width)
        if self.highlight is None:
            band_axis = self._band_axis(width)
        else:
            selected = (
                f"SELECTED · {self.highlight.technology} CH {self.highlight.label} "
                f"· {self.highlight.width_mhz:.0f} MHz"
            )
            band_axis = selected.center(width)[:width]
        plot.append("BAND " + band_axis + "\n", style="bold cyan")
        plot.append("  CH " + channel_row_1 + "\n", style="bold cyan")
        plot.append("     " + channel_row_2 + "\n", style="bold cyan")
        plot.append(" AGE " + "newest".ljust(width - 6) + "oldest\n", style="dim")
        visible_rows = max(1, self.size.height - height - 8)
        history = list(reversed(self.history))[:visible_rows * 2]
        for index in range(0, len(history), 2):
            upper = self._column_powers(history[index], width)
            lower = (
                self._column_powers(history[index + 1], width)
                if index + 1 < len(history) else [None] * width
            )
            for column_index, (upper_power, lower_power) in enumerate(
                zip(upper, lower),
            ):
                if overlay is not None and column_index == overlay[1]:
                    plot.append("│", style="bold #ffb000")
                elif overlay is not None and column_index in (overlay[0], overlay[2]):
                    plot.append("┆", style="#ffb000")
                else:
                    plot.append(
                        "▀",
                        style=f"{self._heat_color(upper_power)} "
                              f"on {self._heat_color(lower_power)}",
                    )
            plot.append("\n")
        return plot


class RfSpectrumView(Screen):
    app: "WifiteApp"
    _TABLE_COLUMNS = (
        ("radio", "RADIO"),
        ("channel", "CHANNEL"),
        ("frequency", "FREQUENCY"),
        ("power", "POWER"),
        ("busy", "BUSY"),
        ("state", "STATE"),
    )

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("r", "restart", "Restart"),
    ]

    CSS = """
    RfSpectrumView #spectrum-body { height: 1fr; padding: 0 1; }
    RfSpectrumView #spectrum-title {
        width: 14; height: 3; content-align: left middle;
        text-style: bold; color: $accent;
    }
    RfSpectrumView #spectrum-controls { height: 3; }
    RfSpectrumView #spectrum-controls Select { margin-right: 1; }
    RfSpectrumView #spectrum-scope { width: 1.4fr; }
    RfSpectrumView #spectrum-channel { width: 1.4fr; }
    RfSpectrumView #spectrum-lna, RfSpectrumView #spectrum-vga { width: 0.7fr; }
    RfSpectrumView #spectrum-status {
        width: 1.5fr; height: 3; content-align: left middle; color: $text-muted;
    }
    RfSpectrumView #spectrum-stats { height: 4; margin-bottom: 1; }
    RfSpectrumView .spectrum-stat {
        width: 1fr; height: 4; margin-right: 1; padding: 0 1;
        border: round $primary; content-align: center middle;
    }
    RfSpectrumView #spectrum-analysis { height: 1fr; min-height: 8; }
    RfSpectrumView #spectrum-table {
        width: 2fr; height: 1fr; border: round $primary;
        border-title-color: $accent; border-title-style: bold;
    }
    RfSpectrumView #spectrum-insights {
        width: 1fr; height: 1fr; margin-left: 1; padding: 1;
        border: round $primary; border-title-color: $accent;
        border-title-style: bold;
    }
    RfSpectrumView #spectrum-note {
        height: 2; color: $text-muted; content-align: center middle;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._sweep = HackRfSweep(self._accept_points, self._sweep_error)
        self._span = SPANS["2g"]
        self._bin_width_hz = spectrum_bin_width_hz(self._span)
        self._occupation: dict[str, deque[bool]] = {}
        self._channel_power: dict[str, deque[float]] = {}
        self._noise_samples: deque[float] = deque(maxlen=512)
        self._updating_controls = False
        self._table_sort_key = "frequency"
        self._table_sort_reverse = False

    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Vertical(id="spectrum-body"):
            with Horizontal(id="spectrum-controls"):
                yield Label("RF SPECTRUM", id="spectrum-title")
                yield Select(
                    [(span.label, key) for key, span in SPANS.items()],
                    value="2g",
                    allow_blank=False,
                    compact=True,
                    id="spectrum-scope",
                )
                yield Select(
                    self._channel_options("2g"),
                    value="__all__",
                    allow_blank=False,
                    compact=True,
                    id="spectrum-channel",
                )
                yield Select(
                    [(f"LNA {gain} dB", gain) for gain in HACKRF_LNA_GAINS],
                    value=16,
                    allow_blank=False,
                    compact=True,
                    id="spectrum-lna",
                )
                yield Select(
                    [(f"VGA {gain} dB", gain) for gain in HACKRF_VGA_GAINS],
                    value=20,
                    allow_blank=False,
                    compact=True,
                    id="spectrum-vga",
                )
                yield Static("Ready", id="spectrum-status")
            with Horizontal(id="spectrum-stats"):
                yield Static("PEAK SIGNAL\n[dim]waiting · Strongest bin now[/dim]",
                             classes="spectrum-stat", id="stat-peak")
                yield Static("NOISE FLOOR\n[dim]calibrating · Background RF level[/dim]",
                             classes="spectrum-stat", id="stat-noise")
                yield Static("BUSIEST CHANNEL\n[dim]waiting · Highest activity[/dim]",
                             classes="spectrum-stat", id="stat-busiest")
                yield Static("SCAN COVERAGE\n[dim]0% · Selected range sampled[/dim]",
                             classes="spectrum-stat", id="stat-coverage")
            yield SpectrumPlot(id="spectrum-plot")
            with Horizontal(id="spectrum-analysis"):
                table = DataTable(cursor_type="row", id="spectrum-table")
                for key, label in self._TABLE_COLUMNS:
                    table.add_column(label, key=key)
                table.border_title = "CHANNELS + CENTER FREQUENCIES"
                yield table
                insights = Static("", id="spectrum-insights")
                insights.border_title = "ANALYST VIEW"
                yield insights
            yield Static(
                "Receive-only · relative dBFS (not calibrated dBm) · activity is an adaptive "
                "energy estimate · table lists Wi-Fi, BT 0–78, and BLE 0–39 centers",
                id="spectrum-note",
            )
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.25, self._refresh_visuals)
        self._update_table_headers()

    def activate(self) -> None:
        self.action_restart()

    def _channel_options(self, scope: str) -> list[tuple[str, str]]:
        options = [("Whole selected range", "__all__")]
        options.extend(
            (
                f"{channel.technology} · {channel.label} · {channel.center_mhz:.0f} MHz",
                channel.key,
            )
            for channel in channels_in_span(SPANS[scope])
        )
        return options

    @on(Select.Changed)
    def _selection_changed(self, event: Select.Changed) -> None:
        if self._updating_controls:
            return
        if event.select.id in {"spectrum-lna", "spectrum-vga"}:
            lna_gain = int(self.query_one("#spectrum-lna", Select).value)
            vga_gain = int(self.query_one("#spectrum-vga", Select).value)
            self._sweep.set_gains(lna_gain, vga_gain)
            self.query_one("#spectrum-status", Static).update(
                f"[cyan]GAIN[/cyan] · LNA {lna_gain} · VGA {vga_gain}"
            )
            return
        if event.select.id == "spectrum-scope":
            scope = str(event.value)
            channel_select = self.query_one("#spectrum-channel", Select)
            self._updating_controls = True
            channel_select.set_options(self._channel_options(scope))
            channel_select.value = "__all__"
            self._updating_controls = False
        self.action_restart()

    @work(exclusive=True, group="rf-spectrum-restart")
    async def action_restart(self) -> None:
        scope = str(self.query_one("#spectrum-scope", Select).value)
        channel_key = str(self.query_one("#spectrum-channel", Select).value)
        self._span = selected_span(scope, channel_key)
        self._occupation.clear()
        self._channel_power.clear()
        self._noise_samples.clear()
        self._bin_width_hz = spectrum_bin_width_hz(self._span)
        channels = channels_in_span(self._span)
        highlight = (
            next(channel for channel in RF_CHANNELS if channel.key == channel_key)
            if channel_key != "__all__" else None
        )
        self.query_one("#spectrum-plot", SpectrumPlot).reset(
            self._span,
            channels,
            highlight,
        )
        self.query_one("#spectrum-status", Static).update(
            f"[cyan]Starting[/cyan] · {self._span.label}"
        )
        try:
            await self._sweep.start(
                self._span.start_mhz,
                self._span.stop_mhz,
                bin_width_hz=self._bin_width_hz,
                lna_gain=int(self.query_one("#spectrum-lna", Select).value),
                vga_gain=int(self.query_one("#spectrum-vga", Select).value),
            )
        except (HackRfSweepError, OSError) as exc:
            self._sweep_error(str(exc))
            return
        self.query_one("#spectrum-status", Static).update(
            f"[bold green]RECEIVING[/bold green] · {self._span.label}"
        )

    def _accept_points(self, points: list[SpectrumPoint]) -> None:
        if not points:
            return
        plot = self.query_one("#spectrum-plot", SpectrumPlot)
        plot.add_points(points)
        self._noise_samples.extend(point.power_dbfs for point in points)
        noise_floor = statistics.median(self._noise_samples)
        active_threshold = noise_floor + 8
        low = min(point.frequency_hz for point in points) / 1_000_000
        high = max(point.frequency_hz for point in points) / 1_000_000
        for channel in channels_in_span(self._span):
            channel_low = channel.center_mhz - channel.width_mhz / 2
            channel_high = channel.center_mhz + channel.width_mhz / 2
            if channel_high < low or channel_low > high:
                continue
            powers = [
                point.power_dbfs for point in points
                if channel_low <= point.frequency_hz / 1_000_000 <= channel_high
            ]
            if not powers:
                continue
            peak = max(powers)
            self._channel_power.setdefault(channel.key, deque(maxlen=120)).append(peak)
            self._occupation.setdefault(channel.key, deque(maxlen=120)).append(
                peak >= active_threshold,
            )

    def _refresh_visuals(self) -> None:
        if self.app.screen is not self:
            return
        plot = self.query_one("#spectrum-plot", SpectrumPlot)
        plot.snapshot()
        plot.refresh()
        channels = channels_in_span(self._span)
        noise_floor = (
            statistics.median(self._noise_samples)
            if self._noise_samples else None
        )
        rows = []
        for channel in channels:
            powers = self._channel_power.get(channel.key, ())
            samples = self._occupation.get(channel.key, ())
            recent_power = max(powers) if powers else None
            occupation = round(sum(samples) / len(samples) * 100) if samples else None
            rows.append((channel, recent_power, occupation, len(samples)))
        self._refresh_stats(plot, rows, noise_floor)
        self._refresh_insights(rows, noise_floor)
        rows = self._sort_channel_rows(rows)
        table = self.query_one("#spectrum-table", DataTable)
        table.border_title = (
            f"CHANNELS + CENTER FREQUENCIES · {len(channels)} ROWS · SCROLL"
        )
        table.clear(columns=False)
        for channel, peak, occupation, _sample_count in rows:
            power_text = Text("waiting", style="dim")
            if peak is not None:
                power_text = Text(f"{peak:.1f} dBFS", style=dbm_style(round(peak)))
            busy_text = Text("waiting", style="dim")
            state = Text("WAIT", style="dim")
            if occupation is not None:
                filled = round(occupation / 100 * 8)
                busy_text = Text("█" * filled, style=self._busy_style(occupation))
                busy_text.append("░" * (8 - filled), style="dim")
                busy_text.append(f" {occupation:>3}%")
                if occupation >= 70:
                    state = Text("CONGESTED", style="bold red")
                elif occupation >= 35:
                    state = Text("ACTIVE", style="yellow")
                else:
                    state = Text("CLEAR", style="bold green")
            table.add_row(
                channel.technology,
                channel.label,
                f"{channel.center_mhz:.0f} MHz",
                power_text,
                busy_text,
                state,
                key=channel.key,
            )

    @on(DataTable.HeaderSelected, "#spectrum-table")
    def sort_from_header(self, event: DataTable.HeaderSelected) -> None:
        key = str(event.column_key.value)
        if key not in {column_key for column_key, _label in self._TABLE_COLUMNS}:
            return
        if key == self._table_sort_key:
            self._table_sort_reverse = not self._table_sort_reverse
        else:
            self._table_sort_key = key
            self._table_sort_reverse = False
        self._update_table_headers()
        direction = "descending" if self._table_sort_reverse else "ascending"
        label = dict(self._TABLE_COLUMNS)[key]
        self.notify(f"Sorted by {label} {direction}", title="Sort changed")
        self._refresh_visuals()

    def _update_table_headers(self) -> None:
        table = self.query_one("#spectrum-table", DataTable)
        arrow = "▼" if self._table_sort_reverse else "▲"
        for key, label in self._TABLE_COLUMNS:
            table.columns[key].label = Text(
                f"{label} {arrow}" if key == self._table_sort_key else f"{label}  ",
            )
        table.refresh()

    def _sort_channel_rows(
        self,
        rows: list[tuple[RfChannel, float | None, int | None, int]],
    ) -> list[tuple[RfChannel, float | None, int | None, int]]:
        key = self._table_sort_key

        def value(row: tuple[RfChannel, float | None, int | None, int]):
            channel, power, occupation, _sample_count = row
            return {
                "radio": channel.technology.casefold(),
                "channel": int(channel.label),
                "frequency": channel.center_mhz,
                "power": power,
                "busy": occupation,
                "state": occupation,
            }[key]

        present = [row for row in rows if value(row) is not None]
        missing = [row for row in rows if value(row) is None]
        present.sort(
            key=lambda row: (value(row), row[0].center_mhz),
            reverse=self._table_sort_reverse,
        )
        return present + missing

    @staticmethod
    def _busy_style(occupation: int) -> str:
        if occupation >= 70:
            return "bold red"
        if occupation >= 35:
            return "yellow"
        return "cyan"

    def _refresh_stats(
        self,
        plot: SpectrumPlot,
        rows: list[tuple[RfChannel, float | None, int | None, int]],
        noise_floor: float | None,
    ) -> None:
        peak = max(plot.points.values()) if plot.points else None
        measured = len(plot.points)
        expected = max(
            1,
            math.ceil(
                (self._span.stop_mhz - self._span.start_mhz)
                * 1_000_000 / self._bin_width_hz
            ),
        )
        coverage = min(100, round(measured / expected * 100))
        ranked = [row for row in rows if row[2] is not None]
        busiest = max(ranked, key=lambda row: row[2]) if ranked else None
        if self._sweep.clip_ratio >= 0.005:
            peak_card = (
                "PEAK SIGNAL\n[bold red]OVERLOAD · "
                f"{self._sweep.clip_ratio:.1%} clipped · reduce gain[/]"
            )
        else:
            peak_card = (
                "PEAK SIGNAL\n[bold white]"
                + (f"{peak:.1f} dBFS" if peak is not None else "waiting")
                + "[/] [dim]· Strongest bin now[/dim]"
            )
        self.query_one("#stat-peak", Static).update(peak_card)
        self.query_one("#stat-noise", Static).update(
            "NOISE FLOOR\n[cyan]"
            + (f"{noise_floor:.1f} dBFS" if noise_floor is not None else "calibrating")
            + "[/] [dim]· Background RF level[/dim]"
        )
        self.query_one("#stat-busiest", Static).update(
            "BUSIEST CHANNEL\n[yellow]"
            + (
                f"{busiest[0].technology} {busiest[0].label} · {busiest[2]}%"
                if busiest is not None else "waiting"
            )
            + "[/] [dim]· Highest activity[/dim]"
        )
        self.query_one("#stat-coverage", Static).update(
            f"SCAN COVERAGE\n[bold green]{coverage}%[/] "
            "[dim]· Selected range sampled[/dim]"
        )

    def _refresh_insights(
        self,
        rows: list[tuple[RfChannel, float | None, int | None, int]],
        noise_floor: float | None,
    ) -> None:
        ranked = sorted(
            (row for row in rows if row[2] is not None),
            key=lambda row: (row[2], row[1] or -200),
            reverse=True,
        )[:6]
        text = Text()
        text.append("BUSIEST CHANNELS\n", style="bold cyan")
        if not ranked:
            text.append("Collecting enough sweep history…\n", style="dim")
        for channel, _power, occupation, _samples in ranked:
            assert occupation is not None
            label = f"{channel.technology} {channel.label}"
            filled = round(occupation / 100 * 10)
            text.append(f"{label:<17.17} ")
            text.append("█" * filled, style=self._busy_style(occupation))
            text.append("░" * (10 - filled), style="dim")
            text.append(f" {occupation:>3}%\n")
        text.append("\nADAPTIVE DETECTOR\n", style="bold cyan")
        if noise_floor is None:
            text.append("Calibrating noise floor…\n", style="dim")
        else:
            text.append(f"Noise floor   {noise_floor:>6.1f} dBFS\n")
            text.append(f"Busy above    {noise_floor + 8:>6.1f} dBFS\n")
        text.append_text(
            Text.from_markup("\n[green]CLEAR[/]  [yellow]ACTIVE[/]  [red]CONGESTED[/]"),
        )
        self.query_one("#spectrum-insights", Static).update(text)

    def _sweep_error(self, message: str) -> None:
        self.query_one("#spectrum-status", Static).update(
            f"[bold red]UNAVAILABLE[/bold red] · {message}"
        )

    @work(exclusive=True, group="rf-spectrum-navigation")
    async def action_back(self) -> None:
        await self._sweep.stop()
        self.app.switch_screen("splash")

    async def stop(self) -> None:
        await self._sweep.stop()
