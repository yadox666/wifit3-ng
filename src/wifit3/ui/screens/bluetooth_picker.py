"""Splash list of USB Bluetooth adapters: one checkbox row per dongle."""
from __future__ import annotations

from typing import Sequence

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Checkbox, Static

from wifit3.bluetooth.usb_hci import UsbBluetoothController
from wifit3.ui.screens.device_picker import (
    _PICKER_MAX,
    _PICKER_MIN,
    _ROW_CHROME,
    detach_rows_now,
)


def bluetooth_mode_label(controller: UsbBluetoothController) -> str:
    if controller.supports_classic and controller.supports_le:
        return "BT+BLE"
    if controller.supports_classic:
        return "BT"
    return "BLE"


def _fit_width(controllers: Sequence[UsbBluetoothController]) -> int:
    """Hug the longest name plus its mode tag, matching the Wi-Fi box chrome."""
    longest = 0
    mode = 0
    for controller in controllers:
        longest = max(longest, len(controller.label))
        mode = max(mode, len(bluetooth_mode_label(controller)) + 3)
    return max(_PICKER_MIN, min(_PICKER_MAX, longest + mode + _ROW_CHROME))


def _row_id(index: int) -> str:
    return f"bt-row-{index}"


def _checkbox_id(index: int) -> str:
    return f"bt-chk-{index}"


class BluetoothPicker(Vertical):
    """Checkbox + adapter name for each detected USB Bluetooth radio."""

    DEFAULT_CSS = """
    BluetoothPicker {
        display: none;
        width: auto;
        max-width: 80;
        height: auto;
        border: round $primary;
        background: $panel;
        padding: 0 1;
    }
    BluetoothPicker .bt-row {
        width: 100%;
        height: 1;
        min-height: 1;
        align: left middle;
        padding: 0;
        margin: 0;
        border-left: tall transparent;
        background: transparent;
    }
    BluetoothPicker .bt-row.-focus {
        border-left: tall $accent;
        background: $boost;
    }
    BluetoothPicker .bt-row Checkbox {
        width: auto;
        height: 1;
        margin: 0 1 0 0;
        padding: 0;
        border: none;
        background: transparent;
        content-align: left middle;
    }
    BluetoothPicker .bt-row Checkbox:focus {
        border: none;
        background: transparent;
    }
    BluetoothPicker .bt-name {
        width: 1fr;
        height: 1;
        min-width: 12;
        padding: 0 1;
        content-align: left middle;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    BluetoothPicker .bt-name.-muted {
        color: $text-muted;
    }
    BluetoothPicker .bt-mode {
        width: auto;
        height: 1;
        margin-left: 1;
        padding: 0 1;
        color: $text-muted;
        text-style: bold;
        content-align: center middle;
    }
    """

    highlighted: reactive[int] = reactive(0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._controllers: list[UsbBluetoothController] = []
        self._checked_by_key: dict[tuple, bool] = {}
        self._preferred_width = _PICKER_MIN

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def compose(self) -> ComposeResult:
        yield from ()

    def set_controllers(self, controllers: Sequence[UsbBluetoothController]) -> None:
        controllers = list(controllers)
        if [c.instance_key for c in controllers] == [c.instance_key for c in self._controllers]:
            return
        self._controllers = controllers
        detach_rows_now(self, ".bt-row")
        if not controllers:
            self.display = False
            self.border_title = ""
            self.highlighted = 0
            return
        self.display = True
        self.border_title = "Bluetooth adapters"
        self._preferred_width = _fit_width(controllers)
        self.styles.width = self._preferred_width
        for index, controller in enumerate(controllers):
            key = controller.instance_key
            if key not in self._checked_by_key:
                self._checked_by_key[key] = True
            row = Horizontal(classes="bt-row", id=_row_id(index))
            self.mount(row)
            row.mount(
                Checkbox(
                    "",
                    value=self._checked_by_key[key],
                    id=_checkbox_id(index),
                    compact=True,
                )
            )
            row.mount(Static(controller.label, classes="bt-name"))
            row.mount(Static(bluetooth_mode_label(controller), classes="bt-mode"))
        if self.highlighted >= len(controllers):
            self.highlighted = max(0, len(controllers) - 1)
        self._sync_row_styles()

    def watch_highlighted(self, _old: int, index: int) -> None:
        self._sync_row_styles()

    def _sync_row_styles(self) -> None:
        for index in range(len(self._controllers)):
            try:
                row = self.query_one(f"#{_row_id(index)}", Horizontal)
                name = row.query_one(".bt-name", Static)
            except Exception:
                continue
            row.set_class(index == self.highlighted, "-focus")
            try:
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                checked = True
            name.set_class(not checked, "-muted")

    def on_checkbox_changed(self, _event: Checkbox.Changed) -> None:
        self._sync_row_styles()

    def selected_controllers(self) -> list[UsbBluetoothController]:
        out: list[UsbBluetoothController] = []
        for index, controller in enumerate(self._controllers):
            try:
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                checked = self._checked_by_key.get(controller.instance_key, True)
            self._checked_by_key[controller.instance_key] = checked
            if checked:
                out.append(controller)
        return out

    def selected_controller(self) -> UsbBluetoothController | None:
        """The radio the USB scan will claim. One dongle can be on the bus at a time."""
        selected = self.selected_controllers()
        if not selected:
            return None
        highlighted = self.highlighted_controller()
        if highlighted is not None and highlighted in selected:
            return highlighted
        return selected[0]

    def highlighted_controller(self) -> UsbBluetoothController | None:
        if not self._controllers:
            return None
        index = min(max(0, self.highlighted), len(self._controllers) - 1)
        return self._controllers[index]

    def focus_list(self) -> None:
        if not self._controllers:
            return
        try:
            self.query_one(f"#{_checkbox_id(self.highlighted)}", Checkbox).focus()
        except Exception:
            self.focus()

    def row_index_at(self, widget) -> int | None:
        row = widget
        while row is not None:
            if isinstance(row, Horizontal) and row.id and row.id.startswith("bt-row-"):
                try:
                    return int(row.id.split("-")[-1])
                except ValueError:
                    return None
            row = row.parent
        return None

    def on_click(self, event) -> None:
        index = self.row_index_at(event.widget)
        if index is not None:
            self.highlighted = index
