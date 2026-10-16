"""AntennaTune: full-screen live signal and traffic monitor."""
from __future__ import annotations

import math
import time
from collections import deque

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, RadioButton, RadioSet, Select, Static

from wifit3.ui.antenna_tune import AntennaTuneSample, SampleProvider, frames_per_second
from wifit3.ui.screens.focus_v2.art import display_name
from wifit3.ui.antenna_tune_graph import (
    render_strength_wave,
    render_tx_ack_wave,
    window,
)
from wifit3.ui.antenna_tune_probe import AntennaTuneSession
from wifit3.ui.signal_bar import FULL_SCALE_RATE, dbm_style, render_signal_bar

_BLOCKS = " ▁▂▃▄▅▆▇█"
_HISTORY = 512
_LABEL_W = 6
_NUM_W = 6
_GUTTER = _LABEL_W + 1 + 1 + _NUM_W
_SAMPLE_S = 0.12
_BEACON_PEAK = FULL_SCALE_RATE
_WAVE_ROWS = 7
_ACK_ROWS = 5


def _dbm_tone(dbm: int) -> float:
    """Map RSSI onto the red→green rainbow (same −95…−30 window as Focus)."""
    if dbm <= -99:
        return 0.0
    return max(0.0, min(1.0, (max(-95, min(-30, dbm)) + 95) / 65))


class AntennaTuneModal(ModalScreen[None]):
    """Live traffic sparklines and reception meter."""

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
        Binding("t", "close", "Close", show=False),
    ]

    DEFAULT_CSS = """
    AntennaTuneModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.86);
    }
    AntennaTuneModal #shell {
        width: 118;
        max-width: 98%;
        height: auto;
        max-height: 96%;
        border: thick $accent;
        background: $surface;
        padding: 1 2 1 2;
    }
    AntennaTuneModal #title {
        width: 100%;
        content-align: center middle;
        text-style: bold;
        color: $accent;
        height: 1;
    }
    AntennaTuneModal #subtitle {
        width: 100%;
        content-align: center middle;
        color: $text-muted;
        height: 1;
        margin-bottom: 0;
    }
    AntennaTuneModal #card-row {
        width: 100%;
        height: 3;
        align: center middle;
        margin: 0 0 1 0;
    }
    AntennaTuneModal #card-row-label {
        width: auto;
        height: 3;
        content-align: left middle;
        color: $text-muted;
        padding: 0 1 0 0;
    }
    AntennaTuneModal #tune-card {
        width: 1fr;
        max-width: 48;
    }
    AntennaTuneModal #mode-row-label {
        width: 100%;
        height: 1;
        content-align: center middle;
        color: $text-muted;
        padding: 0;
    }
    AntennaTuneModal #mode-row {
        width: 100%;
        height: 3;
        align: center middle;
        margin: 0 0 1 0;
    }
    AntennaTuneModal #tune-mode {
        layout: horizontal;
        height: 3;
        width: auto;
        border: none;
        background: transparent;
        padding: 0;
    }
    AntennaTuneModal #tune-mode > RadioButton {
        width: auto;
        height: 3;
        background: transparent;
        padding: 0 2 0 0;
    }
    AntennaTuneModal #tune-mode > RadioButton.-on {
        text-style: bold;
        color: $accent;
    }
    AntennaTuneModal .section-title {
        width: 100%;
        height: 1;
        color: $text-muted;
        text-style: bold;
        padding: 0 1;
    }
    AntennaTuneModal #reception-bar {
        width: 100%;
        height: 1;
        background: $panel;
        padding: 0 1;
    }
    AntennaTuneModal #beacon-spark {
        width: 100%;
        height: 8;
        border: round $primary-darken-1;
        background: #0b0d12;
        padding: 0 1;
        margin-bottom: 1;
    }
    AntennaTuneModal #hero-stats {
        width: 100%;
        height: 1;
        content-align: center middle;
        margin: 0 0 1 0;
    }
    AntennaTuneModal #ack-spark {
        width: 100%;
        height: 7;
        border: round $warning-darken-1;
        background: #100e0a;
        padding: 0 1;
    }
    AntennaTuneModal #link-stats {
        width: 100%;
        height: 1;
        content-align: center middle;
        margin: 0 0 0 0;
    }
    AntennaTuneModal #tx-panel {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
        color: $text-muted;
    }
    AntennaTuneModal #metrics {
        width: 100%;
        height: auto;
        margin-bottom: 1;
    }
    AntennaTuneModal #close-row {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    AntennaTuneModal #close-row Button {
        min-width: 16;
        background: $primary-darken-1;
    }
    """

    def __init__(
        self,
        provider: SampleProvider,
        session: AntennaTuneSession | None = None,
    ) -> None:
        super().__init__()
        self._provider = provider
        self._session = session
        self._hist: dict[str, deque[float]] = {}
        self._reception_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._tone_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._tx_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._ack_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._prev_probe_sent = 0
        self._prev_probe_acked = 0
        self._packet_hist: deque[tuple[float, dict[str, int]]] = deque()
        self._probe_hist: deque[tuple[float, dict[str, int]]] = deque()
        self._rates: dict[str, float] = {}
        self._probe_1s = (0, 0)
        self._prev_time: float | None = None
        self._rows: list = []
        self._card_ready = False
        self._mode_ready = False

    def compose(self) -> ComposeResult:
        with Vertical(id="shell"):
            yield Label("AntennaTune", id="title")
            yield Label("", id="subtitle")
            with Horizontal(id="card-row"):
                yield Label("Card", id="card-row-label")
                yield Select(
                    [("No card", "")],
                    value="",
                    allow_blank=False,
                    id="tune-card",
                    disabled=True,
                )
            yield Label("Stream", id="mode-row-label")
            with Horizontal(id="mode-row"):
                yield RadioSet(
                    RadioButton("Passive", value=True, id="tune-passive"),
                    RadioButton("Active", id="tune-active"),
                    id="tune-mode",
                )
            yield Label("RECEPTION", classes="section-title")
            yield Static("", id="reception-bar")
            yield Static("", id="beacon-spark")
            yield Static("", id="hero-stats")
            yield Label("LINK  LISTEN", id="link-title", classes="section-title")
            yield Static("", id="ack-spark")
            yield Static("", id="link-stats")
            yield Static("", id="tx-panel")
            yield Label("TRAFFIC", classes="section-title")
            yield Static("", id="metrics")
            with Horizontal(id="close-row"):
                yield Button("Close", id="close", variant="primary")

    def on_mount(self) -> None:
        self._fill_card_select()
        self._card_ready = True
        self._mode_ready = True
        self.set_interval(_SAMPLE_S, self._tick)
        self._tick()

    def _tune_channel(self) -> int | None:
        ap = getattr(self.app, "target_ap", None)
        if ap is not None:
            return ap.channel
        client = getattr(self.app, "target_client", None)
        array = getattr(self.app, "array", None)
        if client is None or array is None or not client.bssid:
            return None
        linked = array.access_points.get(client.bssid.lower())
        return getattr(linked, "channel", None)

    def _fill_card_select(self) -> None:
        picker = self.query_one("#tune-card", Select)
        array = getattr(self.app, "array", None)
        members = list(getattr(array, "members", None) or [])
        channel = self._tune_channel()
        options: list[tuple[str, str]] = []
        for iface in members:
            supported = getattr(iface, "supported_channels", None) or []
            name = getattr(iface, "name", "") or display_name(iface)
            label = display_name(iface)
            if channel is not None and supported and channel not in supported:
                label = f"{label}  ·  off-channel"
            options.append((label, name))
        if not options:
            picker.set_options([("No card", "")])
            picker.value = ""
            picker.disabled = True
            return
        picker.set_options(options)
        picker.disabled = len(options) < 2
        current = getattr(self._session, "iface", None) if self._session else None
        current_name = getattr(current, "name", None)
        names = {name for _label, name in options}
        if current_name in names:
            picker.value = current_name
        else:
            picker.value = options[0][1]
            if self._session is not None:
                self._session.iface = next(
                    (m for m in members if getattr(m, "name", "") == options[0][1]),
                    None,
                )

    def _iface_by_name(self, name: str):
        array = getattr(self.app, "array", None)
        for iface in list(getattr(array, "members", None) or []):
            if getattr(iface, "name", "") == name:
                return iface
        return None

    def on_select_changed(self, event: Select.Changed) -> None:
        if not self._card_ready or event.select.id != "tune-card":
            return
        if event.value == Select.BLANK:
            return
        iface = self._iface_by_name(str(event.value))
        if iface is None or self._session is None:
            return
        channel = self._tune_channel()
        supported = getattr(iface, "supported_channels", None) or []
        if channel is not None and supported and channel not in supported:
            self.notify(
                f"{display_name(iface)} cannot tune to channel {channel}",
                severity="warning",
                title="AntennaTune",
            )
            return
        if iface is self._session.iface:
            return
        self._session.iface = iface
        self._packet_hist.clear()
        self._reset_ack_history()
        if self._session.probe is not None and self._transmitting():
            self.run_worker(self._session.probe.restart(), exclusive=True, group="tune-probe")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if not self._mode_ready or event.radio_set.id != "tune-mode":
            return
        pressed = event.pressed
        self._apply_transmit(pressed is not None and pressed.id == "tune-active")

    def _transmitting(self) -> bool:
        pressed = self.query_one("#tune-mode", RadioSet).pressed_button
        return pressed is not None and pressed.id == "tune-active"

    def _apply_transmit(self, active: bool) -> None:
        if self._session is None or self._session.probe is None:
            return
        self._reset_ack_history()
        self.run_worker(
            self._set_transmit(active),
            exclusive=True,
            group="tune-probe",
        )

    async def _set_transmit(self, active: bool) -> None:
        probe = None if self._session is None else self._session.probe
        if probe is None:
            return
        if active:
            probe.start()
            return
        await probe.stop()

    def _reset_ack_history(self) -> None:
        self._tx_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._ack_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._probe_hist.clear()
        self._probe_1s = (0, 0)
        self._prev_probe_sent = 0
        self._prev_probe_acked = 0

    async def on_unmount(self) -> None:
        if self._session is not None and self._session.probe is not None:
            await self._session.probe.stop()

    def action_close(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            event.stop()
            self.action_close()

    def _tick(self) -> None:
        sample = self._provider()
        if sample is None:
            return
        now = sample.sample_time
        self._rows = [r for r in sample.rows if r.key != "beacon"]
        if not self._hist:
            self._hist = {r.key: deque([0.0] * _HISTORY, maxlen=_HISTORY) for r in self._rows}

        self._rates = frames_per_second(self._packet_hist, now, sample.packet_totals)
        probe_rates = frames_per_second(
            self._probe_hist,
            now,
            {"sent": sample.probe_sent, "acked": sample.probe_acked},
        )
        sent_1s = int(round(probe_rates.get("sent", 0.0)))
        ack_1s = int(round(min(probe_rates.get("acked", 0.0), probe_rates.get("sent", 0.0))))
        self._probe_1s = (sent_1s, ack_1s)

        if "beacon" in sample.packet_totals:
            reception = self._rates.get("beacon", 0.0)
        elif sample.beacon_rate is not None:
            reception = sample.beacon_rate
        else:
            reception = self._meter_from_dbm(sample.dbm) or 0.0
        self._reception_hist.append(float(reception))
        self._tone_hist.append(_dbm_tone(sample.dbm))

        sent_delta = max(0, sample.probe_sent - self._prev_probe_sent)
        acked_delta = max(0, sample.probe_acked - self._prev_probe_acked)
        if self._prev_time is not None:
            self._tx_hist.append(float(sent_delta))
            self._ack_hist.append(float(min(acked_delta, sent_delta)))
        self._prev_probe_sent = sample.probe_sent
        self._prev_probe_acked = sample.probe_acked

        deltas = {key: value for key, value in self._rates.items() if key != "beacon"}
        for row in self._rows:
            self._hist.setdefault(row.key, deque([0.0] * _HISTORY, maxlen=_HISTORY))
            self._hist[row.key].append(deltas.get(row.key, 0.0))
        self._prev_time = now

        self.query_one("#subtitle", Label).update(sample.subheading)
        self._paint_reception(sample)
        self._paint_ack(sample)
        self.query_one("#hero-stats", Static).update(
            Text.from_markup(
                self._hero_stats_markup(sample, deltas),
                emoji=False,
            ),
        )
        self.query_one("#metrics", Static).update(self._metrics_block(deltas))
        self.query_one("#tx-panel", Static).update(
            Text.from_markup(self._tx_panel_markup(sample), emoji=False),
        )

    def _hero_stats_markup(self, sample: AntennaTuneSample, deltas: dict[str, float]) -> str:
        parts = [f"[{dbm_style(sample.dbm)}]{sample.dbm} dBm[/]"]
        if "beacon" in sample.packet_totals:
            beacon_r = self._rates.get("beacon", 0.0)
            parts.append(f"[cyan]{beacon_r:.1f}[/] beacons/s")
        elif sample.beacon_rate is not None:
            parts.append(f"[cyan]{sample.beacon_rate:.1f}[/] beacons/s")
        data_r = self._rates.get("data", deltas.get("data", 0.0))
        parts.append(f"[blue]{data_r:.1f}[/] data/s")
        return "  [dim]│[/dim]  ".join(parts)

    def _spark_width(self) -> int:
        shell_w = self.query_one("#shell").size.width or self.size.width or 100
        return max(56, min(108, shell_w - 6))

    def _paint_reception(self, sample: AntennaTuneSample) -> None:
        width = self._spark_width()
        pulse = 0.5 + 0.5 * math.sin(time.time() * math.tau)
        if "beacon" in sample.packet_totals:
            live_rate: float | None = self._rates.get("beacon", 0.0)
        else:
            live_rate = sample.beacon_rate
        bar = render_signal_bar(live_rate, width=width, pulse=pulse)
        self.query_one("#reception-bar", Static).update(bar)

        values = window(self._reception_hist, width)
        tones = window(self._tone_hist, width)
        wave = render_strength_wave(values, rows=_WAVE_ROWS, peak=_BEACON_PEAK, colors=tones)
        if "beacon" in sample.packet_totals:
            beacon_r = self._rates.get("beacon", 0.0)
        else:
            beacon_r = sample.beacon_rate or 0.0
        caption = Text()
        caption.append("beacon  ", style="bold cyan")
        caption.append(f"{beacon_r:.1f}/s", style="bold cyan")
        caption.append("   last 1s   ·   color = RSSI", style="dim")
        self.query_one("#beacon-spark", Static).update(Text("\n").join([wave, caption]))

    def _paint_ack(self, sample: AntennaTuneSample) -> None:
        width = self._spark_width()
        pair_w = max(20, width // 2)
        sent = window(self._tx_hist, pair_w)
        acked = window(self._ack_hist, pair_w)
        sent_n, ack_n = self._probe_1s
        pct = None
        if sent_n >= 1:
            pct = max(0, min(100, int(round(100 * ack_n / sent_n))))
        wave = render_tx_ack_wave(sent, acked, rows=_ACK_ROWS, peak=1.0)
        legend = Text()
        if not self._transmitting():
            title = "LINK  LISTEN"
            legend.append("sent  ", style="bold rgb(80,170,255)")
            legend.append("acked  ", style="bold rgb(40,210,90)")
            legend.append("passive · not transmitting", style="dim")
        elif pct is not None:
            title = f"LINK  TX / ACK  {pct}%"
            legend.append("sent  ", style="bold rgb(80,170,255)")
            legend.append(f"{sent_n}  ", style="bold rgb(80,170,255)")
            legend.append("acked  ", style="bold rgb(40,210,90)")
            legend.append(f"{ack_n}  ", style="bold rgb(40,210,90)")
            legend.append(f"{pct}%", style="bold")
            legend.append("  1s", style="dim")
            if sample.probe_sent:
                session = max(0, min(100, int(round(100 * sample.probe_acked / sample.probe_sent))))
                legend.append(
                    f"    session {sample.probe_acked}/{sample.probe_sent}  {session}%",
                    style="dim",
                )
        elif sample.probe_sent:
            legend.append("sent  ", style="bold rgb(80,170,255)")
            legend.append("acked  ", style="bold rgb(40,210,90)")
            session = max(0, min(100, int(round(100 * sample.probe_acked / sample.probe_sent))))
            title = f"LINK  TX / ACK  {session}%"
            legend.append(
                f"{sample.probe_acked}/{sample.probe_sent}  {session}%",
                style="bold",
            )
        else:
            title = "LINK  TX / ACK"
            legend.append("sent  ", style="bold rgb(80,170,255)")
            legend.append("acked  ", style="bold rgb(40,210,90)")
            legend.append("waiting for first probe…", style="dim")
        self.query_one("#link-title", Label).update(title)
        self.query_one("#ack-spark", Static).update(wave)
        self.query_one("#link-stats", Static).update(legend)

    def _tx_panel_markup(self, sample: AntennaTuneSample) -> str:
        if not self._transmitting():
            return f"[cyan]{sample.card_label}[/cyan]  ·  Passive · listening only"
        if sample.probe_mode in ("ap", "client"):
            kind = "Probe Req → AP" if sample.probe_mode == "ap" else "Null AP → client"
            return (
                f"[cyan]{sample.card_label}[/cyan]  ·  {kind}  ·  "
                f"as [dim]{sample.probe_mac}[/dim]  ·  {sample.probe_status}"
            )
        return f"[cyan]{sample.card_label}[/cyan]  ·  {sample.probe_status or 'link probe idle'}"

    @staticmethod
    def _meter_from_dbm(dbm: int) -> float | None:
        if dbm <= -99:
            return None
        clamped = max(-95, min(-30, dbm))
        return FULL_SCALE_RATE * (clamped + 95) / 65

    def _metrics_block(self, deltas: dict[str, float]) -> Text:
        width = max(44, self._spark_width() - _GUTTER)
        lines: list[Text] = []
        for row in self._rows:
            hist = list(self._hist.get(row.key, []))
            series = window(hist, width)
            peak = max(max(series, default=0), row.peak / 8, 1.0)
            upper = "".join(
                _BLOCKS[max(0, self._col(v, peak, 16) - 8)] for v in series
            )
            lower = "".join(
                _BLOCKS[max(1, min(8, self._col(v, peak, 16)))] for v in series
            )
            rate = self._rates.get(row.key, deltas.get(row.key, 0.0))
            num = f"{rate:.1f}/s" if row.as_rate else f"{rate:.0f}"
            color = row.color if any(series) else f"dim {row.color}"
            head = Text()
            head.append(f"{row.label:>{_LABEL_W}} ", style=f"bold {color}")
            head.append(upper.rjust(width), style=color)
            line = Text()
            line.append(" " * (_LABEL_W + 1))
            line.append(lower.rjust(width), style=color)
            line.append(f"  {num:>{_NUM_W}}", style=f"bold {color}")
            lines.append(head)
            lines.append(line)
        return Text("\n").join(lines)

    @staticmethod
    def _col(v: float, peak: float, levels: int) -> int:
        if v <= 0:
            return 0
        return max(1, min(levels, round(v / peak * levels)))
