"""Startup panel for the operating system's Bleak BLE source."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Checkbox, Static

from wifit3.bluetooth.manager import OsBleSourceStatus
from wifit3.ui.screens.device_picker import (
    _PICKER_MAX,
    _PICKER_MIN,
    _ROW_CHROME,
)


def _status_style(status: OsBleSourceStatus) -> str:
    if status.state in {"OS-READY", "OS-ACTIVE"}:
        return "bold green"
    if status.state == "OS-DISABLED":
        return "bold red"
    return "yellow"


class OsBlePicker(Vertical):
    DEFAULT_CSS = """
    OsBlePicker {
        width: auto;
        max-width: 80;
        height: auto;
        border: round $primary;
        background: $panel;
        padding: 0 1;
    }
    OsBlePicker .os-ble-row {
        width: 100%;
        height: 1;
        min-height: 1;
        align: left middle;
    }
    OsBlePicker Checkbox {
        width: auto;
        height: 1;
        margin: 0 1 0 0;
        padding: 0;
        border: none;
        background: transparent;
    }
    OsBlePicker Checkbox:focus {
        border: none;
        background: transparent;
    }
    OsBlePicker .os-ble-name {
        width: 1fr;
        height: 1;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    OsBlePicker .os-ble-state {
        width: auto;
        height: 1;
        margin-left: 1;
        padding: 0 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._status: OsBleSourceStatus | None = None
        self._preferred_width = _PICKER_MIN

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def compose(self) -> ComposeResult:
        with Horizontal(classes="os-ble-row", id="os-ble-row"):
            yield Checkbox("", value=True, id="os-ble-enabled", compact=True)
            yield Static("Bleak · checking", classes="os-ble-name")
            yield Static(Text("CHECKING", style="yellow"), classes="os-ble-state")

    def set_status(self, status: OsBleSourceStatus) -> None:
        if self._status is not None and status.instance_key == self._status.instance_key:
            return
        self._status = status
        self.border_title = "Operating-system BLE"
        vendor = f"{status.manufacturer} " if status.manufacturer else ""
        name = f"{vendor}{status.backend} · {status.operating_system} · {status.adapter}"
        chipset = f"Chipset unavailable through {status.backend}"
        full_text = f"{name} · {status.state} · {status.detail} · {chipset}"
        self._preferred_width = max(
            _PICKER_MIN,
            min(_PICKER_MAX, len(name) + len(status.state) + _ROW_CHROME),
        )
        self.styles.width = self._preferred_width
        row = self.query_one("#os-ble-row", Horizontal)
        row.tooltip = full_text
        checkbox = self.query_one("#os-ble-enabled", Checkbox)
        checkbox.value = status.enabled
        checkbox.tooltip = (
            "Enable or disable use of the OS BLE source inside wifit3; "
            "this does not change the operating system's Bluetooth setting"
        )
        name_widget = self.query_one(".os-ble-name", Static)
        name_widget.update(name)
        name_widget.tooltip = full_text
        state_widget = self.query_one(".os-ble-state", Static)
        state_widget.update(Text(status.state, style=_status_style(status)))
        state_widget.tooltip = full_text
