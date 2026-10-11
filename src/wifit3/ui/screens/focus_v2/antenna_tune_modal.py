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
from textual.widgets import Button, Label, Select, Static

from wifit3.ui.antenna_tune import AntennaTuneSample, SampleProvider
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
        height: 6;
        border: round $warning-darken-1;
        background: #100e0a;
        padding: 0 1;
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
        self._prev_packets: dict[str, int] | None = None
        self._prev_probe_sent = 0
        self._prev_probe_acked = 0
        self._prev_time: float | None = None
        self._rows: list = []
        self._card_ready = False

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
            yield Label("RECEPTION", classes="section-title")
            yield Static("", id="reception-bar")
            yield Static("", id="beacon-spark")
            yield Static("", id="hero-stats")
            yield Label("LINK  TX / ACK", classes="section-title")
            yield Static("", id="ack-spark")
            yield Static("", id="tx-panel")
            yield Label("TRAFFIC", classes="section-title")
            yield Static("", id="metrics")
            with Horizontal(id="close-row"):
                yield Button("Close", id="close", variant="primary")

    def on_mount(self) -> None:
        self._fill_card_select()
        self._card_ready = True
        if self._session is not None and self._session.probe is not None:
            self._session.probe.start()
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
        self._reset_ack_history()
        if self._session.probe is not None:
            self.run_worker(self._session.probe.restart(), exclusive=True, group="tune-card")

    def _reset_ack_history(self) -> None:
        self._tx_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._ack_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
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
        dt = (now - self._prev_time) if self._prev_time is not None else _SAMPLE_S
        dt = max(dt, 1e-3)
        self._rows = [r for r in sample.rows if r.key != "beacon"]
        if not self._hist:
            self._hist = {r.key: deque([0.0] * _HISTORY, maxlen=_HISTORY) for r in self._rows}

        reception = sample.beacon_rate
        if reception is None:
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

        deltas: dict[str, float] = {}
        if self._prev_packets is not None:
            for r in sample.rows:
                cur = sample.packet_totals.get(r.key, 0)
                prev = self._prev_packets.get(r.key, 0)
                rate = max(0, cur - prev) / dt
                deltas[r.key] = rate
                if r.key == "beacon":
                    continue
                self._hist.setdefault(r.key, deque([0.0] * _HISTORY, maxlen=_HISTORY))
                self._hist[r.key].append(rate)
        self._prev_packets = dict(sample.packet_totals)
        self._prev_time = now

        self.query_one("#subtitle", Label).update(sample.subheading)
        self._paint_reception(sample, deltas)
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
        beacon_r = deltas.get("beacon", sample.beacon_rate or 0.0)
        parts.append(f"[cyan]{beacon_r:.1f}[/] beacons/s")
        data_r = deltas.get("data", 0.0)
        parts.append(f"[blue]{data_r:.0f}[/] data/s")
        return "  [dim]│[/dim]  ".join(parts)

    def _spark_width(self) -> int:
        shell_w = self.query_one("#shell").size.width or self.size.width or 100
        return max(56, min(108, shell_w - 6))

    def _paint_reception(self, sample: AntennaTuneSample, deltas: dict[str, float]) -> None:
        width = self._spark_width()
        pulse = 0.5 + 0.5 * math.sin(time.time() * math.tau)
        live_rate = sample.beacon_rate if sample.beacon_rate is not None else self._meter_from_dbm(sample.dbm)
        bar = render_signal_bar(live_rate, width=width, pulse=pulse)
        self.query_one("#reception-bar", Static).update(bar)

        values = window(self._reception_hist, width)
        tones = window(self._tone_hist, width)
        wave = render_strength_wave(values, rows=_WAVE_ROWS, peak=_BEACON_PEAK, colors=tones)
        beacon_r = deltas.get("beacon", 0.0) if deltas else (sample.beacon_rate or 0.0)
        caption = Text()
        caption.append("beacon  ", style="bold cyan")
        caption.append(f"{beacon_r:.1f}/s", style="bold cyan")
        caption.append("   height = rate   ·   color = RSSI", style="dim")
        self.query_one("#beacon-spark", Static).update(Text("\n").join([wave, caption]))

    def _paint_ack(self, sample: AntennaTuneSample) -> None:
        width = self._spark_width()
        pair_w = max(20, width // 2)
        sent = window(self._tx_hist, pair_w)
        acked = window(self._ack_hist, pair_w)
        wave = render_tx_ack_wave(sent, acked, rows=_ACK_ROWS, peak=1.0)
        legend = Text()
        legend.append("sent  ", style="bold rgb(80,170,255)")
        legend.append("acked  ", style="bold rgb(40,210,90)")
        if sample.probe_sent:
            pct = int(100 * sample.probe_acked / sample.probe_sent)
            legend.append(f"{sample.probe_acked}/{sample.probe_sent}  {pct}%", style="bold")
        else:
            legend.append("waiting for first probe…", style="dim")
        self.query_one("#ack-spark", Static).update(Text("\n").join([wave, legend]))

    def _tx_panel_markup(self, sample: AntennaTuneSample) -> str:
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
            rate = deltas.get(row.key, 0.0)
            num = f"{rate:.0f}/s" if row.as_rate else f"{sum(hist[-6:]):.0f}"
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
