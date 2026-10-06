"""Splash panel for detected software-defined radios."""
from __future__ import annotations

from typing import Sequence

from textual.containers import Horizontal, Vertical
from textual.widgets import Checkbox, Static

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


def _row_id(index: int) -> str:
    return f"sdr-row-{index}"


def _checkbox_id(index: int) -> str:
    return f"sdr-chk-{index}"


class SdrPicker(Vertical):
    """List of detected SDR hardware; each device can be checked on/off."""

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
    SdrPicker .sdr-row Checkbox {
        width: auto;
        height: 1;
        margin: 0 1 0 0;
        padding: 0;
        border: none;
        background: transparent;
    }
    SdrPicker .sdr-row Checkbox:focus {
        border: none;
        background: transparent;
    }
    SdrPicker .sdr-name {
        width: 1fr;
        height: 1;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    SdrPicker .sdr-name.-muted {
        color: $text-muted;
    }
    SdrPicker .sdr-mode {
        width: auto;
        height: 1;
        margin-left: 1;
        padding: 0 1;
        background: $success;
        color: $background;
        text-style: bold;
        content-align: center middle;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._devices: list[HackRfDevice] = []
        self._checked_by_key: dict[tuple, bool] = {}
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
            key = device.instance_key
            if key not in self._checked_by_key:
                self._checked_by_key[key] = True
            row = Horizontal(classes="sdr-row", id=_row_id(index))
            self.mount(row)
            row.mount(
                Checkbox(
                    "",
                    value=self._checked_by_key[key],
                    id=_checkbox_id(index),
                    compact=True,
                )
            )
            name = Static(device.label, classes="sdr-name")
            name.set_class(not self._checked_by_key[key], "-muted")
            row.mount(name)
            row.mount(Static("SDR", classes="sdr-mode"))

    def on_checkbox_changed(self, _event: Checkbox.Changed) -> None:
        self._sync_row_styles()

    def _sync_row_styles(self) -> None:
        for index, device in enumerate(self._devices):
            try:
                row = self.query_one(f"#{_row_id(index)}", Horizontal)
                name = row.query_one(".sdr-name", Static)
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                continue
            self._checked_by_key[device.instance_key] = checked
            name.set_class(not checked, "-muted")

    def selected_devices(self) -> list[HackRfDevice]:
        out: list[HackRfDevice] = []
        for index, device in enumerate(self._devices):
            try:
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                checked = self._checked_by_key.get(device.instance_key, True)
            self._checked_by_key[device.instance_key] = checked
            if checked:
                out.append(device)
        return out
