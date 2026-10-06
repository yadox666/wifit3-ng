"""Splash list of USB Bluetooth adapters: one checkbox row per dongle."""
from __future__ import annotations

from typing import AbstractSet, Sequence

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Click
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Static

from wifit3.bluetooth import scan_modes
from wifit3.bluetooth.usb_hci import UsbBluetoothController
from wifit3.ui.screens.device_picker import (
    _PICKER_MAX,
    _PICKER_MIN,
    _ROW_CHROME,
    detach_rows_now,
)


_RECLAIM_ICON = "↻"
_RECLAIM_CHROME = 5

# Segmented scan-mode control, mirroring the Wi-Fi band bar (All | 2.4 | 5G).
_MODE_SEGMENTS_DUAL: tuple[tuple[str, str], ...] = (
    ("ALL", "all"),
    ("BT", "bt"),
    ("BLE", "ble"),
)
_MODE_KEY_TO_SCAN = {
    "all": scan_modes.BT_BLE,
    "bt": scan_modes.BT,
    "ble": scan_modes.BLE,
}
_MODE_TOOLTIP = {
    "all": "Scan Classic + BLE on this adapter",
    "bt": "Classic (BR/EDR) only",
    "ble": "BLE only",
}


def mode_choices(
    controller: UsbBluetoothController,
) -> tuple[tuple[str, str], ...]:
    """Segments to draw. ``ALL`` exists only when the dongle has both radios."""
    le = controller.supports_le
    classic = controller.supports_classic
    if le and classic:
        return _MODE_SEGMENTS_DUAL
    if classic:
        return (("BT", "bt"),)
    if le:
        return (("BLE", "ble"),)
    return (("BT", "bt"),)


def default_mode_key(controller: UsbBluetoothController, os_ble_active: bool) -> str:
    """Most-effective default: a dual dongle runs Classic when the OS covers BLE."""
    le = controller.supports_le
    classic = controller.supports_classic
    if le and classic:
        return "bt" if os_ble_active else "all"
    if classic:
        return "bt"
    if le:
        return "ble"
    return "bt"


def _mode_cells(controller: UsbBluetoothController) -> int:
    choices = mode_choices(controller)
    return sum(len(label) + 2 for label, _key in choices) + max(0, len(choices) - 1)


def _fit_width(
    controllers: Sequence[UsbBluetoothController],
    not_claimed: AbstractSet[tuple],
) -> int:
    """Hug the longest name plus its scan-mode bar, matching the Wi-Fi box chrome."""
    longest = 0
    mode = 0
    reclaim = 0
    for controller in controllers:
        longest = max(longest, len(controller.label))
        mode = max(mode, _mode_cells(controller))
        if controller.instance_key in not_claimed:
            reclaim = max(reclaim, _RECLAIM_CHROME)
    return max(
        _PICKER_MIN,
        min(_PICKER_MAX, longest + mode + reclaim + _ROW_CHROME + 2),
    )


def _row_id(index: int) -> str:
    return f"bt-row-{index}"


def _checkbox_id(index: int) -> str:
    return f"bt-chk-{index}"


def _reclaim_id(index: int) -> str:
    return f"bt-reclaim-{index}"


def _bar_id(index: int) -> str:
    return f"bt-mode-bar-{index}"


class _BtModeOpt(Static):
    """One segment of the scan-mode control. Clicking it selects that mode."""

    def __init__(self, label: str, key: str) -> None:
        super().__init__(label, classes=f"bt-mode-opt bt-mode-{key}")
        self.mode_key = key

    def on_click(self, event: Click) -> None:
        event.stop()
        bar = self.parent
        if not isinstance(bar, BluetoothModeBar):
            return
        if len(bar.choices) > 1 and bar.value != self.mode_key:
            bar.value = self.mode_key
        node = bar.parent
        while node is not None and not isinstance(node, BluetoothPicker):
            node = node.parent
        if isinstance(node, BluetoothPicker):
            node._on_mode_segment_changed(bar)


class BluetoothModeBar(Horizontal):
    """One-line segmented scan-mode picker. The selected segment stays filled."""

    DEFAULT_CSS = """
    BluetoothModeBar {
        width: auto;
        height: 1;
        align: right middle;
        background: $primary 14%;
        margin-left: 1;
    }
    BluetoothModeBar > .bt-mode-sep {
        width: 1;
        height: 1;
        color: $primary 55%;
        content-align: center middle;
    }
    BluetoothModeBar > .bt-mode-opt {
        width: auto;
        height: 1;
        padding: 0 1;
        color: $text-muted;
        background: transparent;
        content-align: center middle;
        text-wrap: nowrap;
    }
    BluetoothModeBar > .bt-mode-opt:hover {
        background: $boost;
        color: $foreground;
    }
    BluetoothModeBar > .bt-mode-opt.-chosen {
        background: $success;
        color: $background;
        text-style: bold;
    }
    BluetoothModeBar > .bt-mode-opt.-chosen:hover {
        background: $success;
        color: $background;
    }
    BluetoothModeBar.-fixed {
        background: transparent;
    }
    """

    value: reactive[str] = reactive("all")

    def __init__(
        self,
        controller: UsbBluetoothController,
        value: str = "all",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.controller = controller
        self.choices: tuple[tuple[str, str], ...] = tuple(mode_choices(controller))
        keys = {key for _label, key in self.choices}
        self.value = value if value in keys else self.choices[0][1]
        if len(self.choices) == 1:
            self.tooltip = _MODE_TOOLTIP.get(self.choices[0][1], "")
        else:
            self.tooltip = "Pick which radios this adapter scans"

    def compose(self) -> ComposeResult:
        for index, (label, key) in enumerate(self.choices):
            if index:
                yield Static("│", classes="bt-mode-sep")
            yield _BtModeOpt(label, key)

    def on_mount(self) -> None:
        self._sync_chosen()

    def watch_value(self, _old: str, _new: str) -> None:
        self._sync_chosen()

    def _sync_chosen(self) -> None:
        # A single-radio dongle has one fixed segment; it's the active mode, so
        # it stays filled green like a chosen segment (and like the OS BLE tag).
        fixed = len(self.choices) == 1
        self.set_class(fixed, "-fixed")
        for _label, key in self.choices:
            chosen = fixed or self.value == key
            for opt in self.query(f".bt-mode-{key}"):
                opt.set_class(chosen, "-chosen")

    def scan_mode(self) -> str:
        return _MODE_KEY_TO_SCAN.get(self.value, scan_modes.BT_BLE)


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
    BluetoothPicker .bt-reclaim {
        width: 3;
        min-width: 3;
        height: 1;
        min-height: 1;
        margin: 0 0 0 1;
        padding: 0;
        border: none;
        background: transparent;
        color: $error;
        text-style: bold;
        content-align: center middle;
    }
    BluetoothPicker .bt-reclaim:focus {
        border: none;
        background: $boost;
    }
    """

    class ReclaimRequested(Message):
        """Release a USB Bluetooth adapter from the OS (splash handles the work)."""

        def __init__(self, controller: UsbBluetoothController) -> None:
            self.controller = controller
            super().__init__()

    class ScanModeChanged(Message):
        """User changed a dongle's scan mode (ALL / BT / BLE)."""

        def __init__(self, controller: UsbBluetoothController, mode: str) -> None:
            self.controller = controller
            self.mode = mode
            super().__init__()

    highlighted: reactive[int] = reactive(0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._controllers: list[UsbBluetoothController] = []
        self._not_claimed: frozenset[tuple] = frozenset()
        self._checked_by_key: dict[tuple, bool] = {}
        # Selected segment per dongle ("all"/"bt"/"ble") and which the user set.
        self._mode_by_key: dict[tuple, str] = {}
        self._mode_manual: set[tuple] = set()
        self._preferred_width = _PICKER_MIN
        self._os_ble_active = True

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def compose(self) -> ComposeResult:
        yield from ()

    def set_controllers(
        self,
        controllers: Sequence[UsbBluetoothController],
        *,
        not_claimed: AbstractSet[tuple] | None = None,
    ) -> None:
        controllers = list(controllers)
        claimed = frozenset(not_claimed or ())
        same_list = [c.instance_key for c in controllers] == [
            c.instance_key for c in self._controllers
        ]
        if same_list and claimed == self._not_claimed:
            return
        self._not_claimed = claimed
        if same_list:
            self._preferred_width = _fit_width(controllers, claimed)
            self.styles.width = self._preferred_width
            self._sync_reclaim_buttons()
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
        self._preferred_width = _fit_width(controllers, claimed)
        self.styles.width = self._preferred_width
        for index, controller in enumerate(controllers):
            key = controller.instance_key
            if key not in self._checked_by_key:
                self._checked_by_key[key] = True
            if key in self._mode_manual and key in self._mode_by_key:
                mode_key = self._mode_by_key[key]
            else:
                mode_key = default_mode_key(controller, self._os_ble_active)
            allowed = {band_key for _label, band_key in mode_choices(controller)}
            if mode_key not in allowed:
                mode_key = default_mode_key(controller, self._os_ble_active)
            self._mode_by_key[key] = mode_key
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
            row.mount(BluetoothModeBar(controller, value=mode_key, id=_bar_id(index)))
            reclaim = Button(
                _RECLAIM_ICON,
                id=_reclaim_id(index),
                classes="bt-reclaim",
                variant="default",
            )
            reclaim.display = key in claimed
            if key in claimed:
                reclaim.tooltip = (
                    "The OS still owns this USB adapter. Click ↻ to release it for "
                    "wifit3 (on macOS Bluetooth may turn off briefly), or unplug and "
                    "re-plug once."
                )
            row.mount(reclaim)
        if self.highlighted >= len(controllers):
            self.highlighted = max(0, len(controllers) - 1)
        self._sync_row_styles()

    def set_os_ble_active(self, active: bool) -> None:
        if active == self._os_ble_active:
            return
        self._os_ble_active = active
        # Re-pin dongles the user hasn't touched to the most-effective default.
        for index, controller in enumerate(self._controllers):
            key = controller.instance_key
            if key in self._mode_manual:
                continue
            new_key = default_mode_key(controller, active)
            self._mode_by_key[key] = new_key
            try:
                bar = self.query_one(f"#{_bar_id(index)}", BluetoothModeBar)
            except Exception:
                continue
            bar.value = new_key

    def scan_mode_for(self, controller: UsbBluetoothController) -> str:
        """The scan mode the manager should apply for a controller."""
        key = self._mode_by_key.get(controller.instance_key)
        if key is None:
            key = default_mode_key(controller, self._os_ble_active)
        return _MODE_KEY_TO_SCAN.get(key, scan_modes.BT_BLE)

    def _on_mode_segment_changed(self, bar: "BluetoothModeBar") -> None:
        """A segment was clicked: record the choice and notify the splash."""
        index = self.row_index_at(bar)
        if index is None or not (0 <= index < len(self._controllers)):
            return
        controller = self._controllers[index]
        self.highlighted = index
        if len(bar.choices) <= 1:
            return
        self._mode_by_key[controller.instance_key] = bar.value
        self._mode_manual.add(controller.instance_key)
        self.post_message(self.ScanModeChanged(controller, bar.scan_mode()))

    def _sync_reclaim_buttons(self) -> None:
        for index, controller in enumerate(self._controllers):
            try:
                reclaim = self.query_one(f"#{_reclaim_id(index)}", Button)
            except Exception:
                continue
            not_claimed = controller.instance_key in self._not_claimed
            reclaim.display = not_claimed
            if not_claimed:
                reclaim.tooltip = (
                    "The OS still owns this USB adapter. Click ↻ to release it for "
                    "wifit3 (on macOS Bluetooth may turn off briefly), or unplug and "
                    "re-plug once."
                )
            else:
                reclaim.tooltip = ""

    def watch_highlighted(self, _old: int, index: int) -> None:
        self._sync_row_styles()

    def _sync_row_styles(self) -> None:
        for index in range(len(self._controllers)):
            try:
                row = self.query_one(f"#{_row_id(index)}", Horizontal)
                name = row.query_one(".bt-name", Static)
            except Exception:
                continue
            # Only show the highlight cursor when there's an actual choice to
            # navigate; a lone row shouldn't carry a selection marker.
            focused = index == self.highlighted and len(self._controllers) > 1
            row.set_class(focused, "-focus")
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if not button_id.startswith("bt-reclaim-"):
            return
        try:
            index = int(button_id.removeprefix("bt-reclaim-"))
        except ValueError:
            return
        if 0 <= index < len(self._controllers):
            self.post_message(self.ReclaimRequested(self._controllers[index]))
