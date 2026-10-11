"""Tall multi-color column graphs for AntennaTune."""
from __future__ import annotations

from typing import Iterable, Sequence

from rich.text import Text

from wifit3.ui.signal_bar import _dim, _hue

_BLOCKS = " ▁▂▃▄▅▆▇█"


def strength_style(t: float, *, dim: bool = False) -> str:
    """Red → yellow → green, same scale as the Focus rainbow meter."""
    return _dim(_hue(t), 0.45 if dim else 1.0)


def _levels(value: float, peak: float, total: int) -> int:
    if value <= 0 or peak <= 0:
        return 0
    return max(1, min(total, round(value / peak * total)))


def render_strength_wave(
    values: Sequence[float],
    *,
    rows: int = 6,
    peak: float | None = None,
    colors: Sequence[float] | None = None,
) -> Text:
    """Column wave: height from ``values``, hue from ``colors`` (or value/peak)."""
    if not values:
        return Text("")
    peak = max(peak or 0.0, max(values), 0.5)
    total = max(1, rows) * 8
    heights = [_levels(v, peak, total) for v in values]
    tones = list(colors) if colors is not None else [min(1.0, v / peak) for v in values]
    lines: list[Text] = []
    for row in range(rows - 1, -1, -1):
        line = Text(no_wrap=True)
        base = row * 8
        for height, tone in zip(heights, tones):
            frag = height - base
            if frag <= 0:
                line.append(" ", style=strength_style(tone, dim=True))
                continue
            glyph = "█" if frag >= 8 else _BLOCKS[frag]
            line.append(glyph, style=strength_style(min(1.0, max(0.0, tone))))
        lines.append(line)
    return Text("\n").join(lines)


_SENT_STYLE = "bold rgb(80,170,255)"
_ACK_STYLE = "bold rgb(40,210,90)"
_IDLE_STYLE = "rgb(40,40,48)"


def _column_glyph(height: int, base: int) -> str:
    frag = height - base
    if frag <= 0:
        return ""
    return "█" if frag >= 8 else _BLOCKS[min(8, frag)]


def render_tx_ack_wave(
    sent: Sequence[float],
    acked: Sequence[float],
    *,
    rows: int = 5,
    peak: float | None = None,
) -> Text:
    """Each probe is a pair of columns: sent (blue) then acked (green)."""
    n = min(len(sent), len(acked))
    if n == 0:
        return Text("")
    sent = list(sent[-n:])
    acked = [min(a, s) for a, s in zip(acked[-n:], sent)]
    peak = max(peak or 0.0, max(sent, default=0.0), max(acked, default=0.0), 1.0)
    total = max(1, rows) * 8
    sent_h = [_levels(v, peak, total) if v > 0 else 0 for v in sent]
    ack_h = [_levels(v, peak, total) if v > 0 else 0 for v in acked]
    lines: list[Text] = []
    for row in range(rows - 1, -1, -1):
        line = Text(no_wrap=True)
        base = row * 8
        for tx, ack in zip(sent_h, ack_h):
            sent_glyph = _column_glyph(tx, base)
            ack_glyph = _column_glyph(ack, base)
            line.append(sent_glyph or "·", style=_SENT_STYLE if sent_glyph else _IDLE_STYLE)
            line.append(ack_glyph or "·", style=_ACK_STYLE if ack_glyph else _IDLE_STYLE)
        lines.append(line)
    return Text("\n").join(lines)


def window(values: Iterable[float], width: int) -> list[float]:
    """Right-aligned slice, padded on the left so newest sits at the right edge."""
    data = list(values)
    if width <= 0:
        return []
    if len(data) >= width:
        return data[-width:]
    return [0.0] * (width - len(data)) + data
