"""Splash panel for a connected NMEA GPS/GNSS receiver."""
from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from wifit3.gps import GpsStatus
from wifit3.models.location import LocationFix
from wifit3.ui.screens.device_picker import (
    _PICKER_MAX,
    _PICKER_MIN,
    _ROW_CHROME,
    detach_rows_now,
)


def gps_fix_label(fix: LocationFix | None) -> str:
    if fix is None:
        return "NMEA · NO FIX"
    parts = ["NMEA"]
    if fix.satellites is not None:
        parts.append(f"{fix.satellites} SAT")
    parts.append(f"±{fix.accuracy_m:.0f} m")
    return " · ".join(parts)


class GpsPicker(Vertical):
    DEFAULT_CSS = """
    GpsPicker {
        display: none;
        width: auto;
        max-width: 80;
        height: auto;
        border: round $primary;
        background: $panel;
        padding: 0 1;
    }
    GpsPicker .gps-row {
        width: 100%;
        height: 1;
        min-height: 1;
        align: left middle;
    }
    GpsPicker .gps-name {
        width: 1fr;
        height: 1;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    GpsPicker .gps-mode {
        width: auto;
        height: 1;
        margin-left: 1;
        padding: 0 1;
        color: $text-muted;
        text-style: bold;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._status: GpsStatus | None = None
        self._preferred_width = _PICKER_MIN

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def set_status(
        self,
        status: GpsStatus | None,
        fix: LocationFix | None = None,
    ) -> None:
        signature = status.instance_key if status is not None else None
        current = self._status.instance_key if self._status is not None else None
        mode = gps_fix_label(fix)
        if signature == current and status is not None:
            name = f"{status.label} · {status.port} · {status.baudrate:,} baud"
            full_text = f"{name} · {mode}"
            matches = list(self.query(".gps-mode"))
            if matches:
                matches[0].update(mode)
                matches[0].tooltip = full_text
            names = list(self.query(".gps-name"))
            if names:
                names[0].tooltip = full_text
            rows = list(self.query(".gps-row"))
            if rows:
                rows[0].tooltip = full_text
            return
        self._status = status
        detach_rows_now(self, ".gps-row")
        if status is None:
            self.display = False
            self.border_title = ""
            return
        self.display = True
        self.border_title = "GPS / GNSS receivers"
        name = f"{status.label} · {status.port} · {status.baudrate:,} baud"
        self._preferred_width = max(
            _PICKER_MIN,
            min(_PICKER_MAX, len(name) + len(mode) + _ROW_CHROME),
        )
        self.styles.width = self._preferred_width
        row = Horizontal(classes="gps-row", id="gps-row-0")
        self.mount(row)
        full_text = f"{name} · {mode}"
        row.tooltip = full_text
        name_widget = Static(name, classes="gps-name")
        name_widget.tooltip = full_text
        row.mount(name_widget)
        mode_widget = Static(mode, classes="gps-mode")
        mode_widget.tooltip = full_text
        row.mount(mode_widget)
