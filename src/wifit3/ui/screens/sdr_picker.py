"""Splash panel for detected software-defined radios."""
from __future__ import annotations

from typing import Sequence

from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from wifit3.sdr import HackRfDevice
from wifit3.ui.screens.device_picker import (
    _PICKER_MAX,
    _PICKER_MIN,
    _ROW_CHROME,
    detach_rows_now,
)


def _fit_width(devices: Sequence[HackRfDevice]) -> int:
    longest = max((len(device.label) for device in devices), default=0)
    return max(_PICKER_MIN, min(_PICKER_MAX, longest + len("SDR") + _ROW_CHROME))


class SdrPicker(Vertical):
    """Display-only list of SDR hardware available for future analysis."""

    DEFAULT_CSS = """
    SdrPicker {
        display: none;
        width: auto;
        max-width: 80;
        height: auto;
        border: round $primary;
        background: $panel;
        padding: 0 1;
    }
    SdrPicker .sdr-row {
        width: 100%;
        height: 1;
        min-height: 1;
        align: left middle;
    }
    SdrPicker .sdr-name {
        width: 1fr;
        height: 1;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    SdrPicker .sdr-mode {
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
        self._devices: list[HackRfDevice] = []
        self._preferred_width = _PICKER_MIN

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def set_devices(self, devices: Sequence[HackRfDevice]) -> None:
        devices = list(devices)
        if [device.instance_key for device in devices] == [
            device.instance_key for device in self._devices
        ]:
            return
        self._devices = devices
        detach_rows_now(self, ".sdr-row")
        if not devices:
            self.display = False
            self.border_title = ""
            return
        self.display = True
        self.border_title = "Software-defined radios"
        self._preferred_width = _fit_width(devices)
        self.styles.width = self._preferred_width
        for index, device in enumerate(devices):
            row = Horizontal(classes="sdr-row", id=f"sdr-row-{index}")
            self.mount(row)
            row.mount(Static(device.label, classes="sdr-name"))
            row.mount(Static("SDR", classes="sdr-mode"))
