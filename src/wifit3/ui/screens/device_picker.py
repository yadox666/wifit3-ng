"""Unified splash device list: one row per card (checkbox, name, scan band)."""
from __future__ import annotations

import functools
from typing import Sequence

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Checkbox, Static

from wifit3.models.device_id import DeviceID

# Short labels: the control is one line, so the words have to stay obvious at a glance.
_BANDS: tuple[tuple[str, str], ...] = (
    ("All", "all"),
    ("2.4", "2g"),
    ("5G", "5g"),
)
_BAND_ONLY = {"2g": "2.4", "5g": "5G"}
_ONLY_TOOLTIP = {"2g": "2.4 GHz", "5g": "5 GHz"}
# Checkbox glyph, its gap, name padding, row accent, panel padding, and the frame.
_ROW_CHROME = 4 + 2 + 2 + 2 + 2
_PICKER_MIN = 46
_PICKER_MAX = 80


def detach_rows_now(parent: Vertical, selector: str) -> None:
    """Drop rows and free their IDs before this call returns.

    ``Widget.remove`` only leaves the node list after the message loop exits, so
    remounting ``device-row-0`` in the same turn raises ``DuplicateIds``.
    """
    for child in list(parent.query(selector)):
        child.remove()
        parent._nodes._remove(child)


def _choice_cells(choices: Sequence[tuple[str, str]]) -> int:
    if not choices:
        return 0
    return sum(len(label) + 2 for label, _key in choices) + max(0, len(choices) - 1)


def _fit_width(devices: Sequence[DeviceID]) -> int:
    """Hug the longest adapter name plus the bands that card can actually tune."""
    longest = 0
    for dev in devices:
        longest = max(longest, len(device_name_plain(dev)) + _choice_cells(band_choices(dev)))
    return max(_PICKER_MIN, min(_PICKER_MAX, longest + _ROW_CHROME))


@functools.cache
def hardware_scan_bands(vid: int, pid: int) -> frozenset[str]:
    """Bands the driver for this VID:PID can tune. Unknown cards keep both."""
    try:
        from wifit3.device.manager import driver_for
        found = driver_for(vid, pid)
    except Exception:
        return frozenset({"2g", "5g"})
    if found is None:
        return frozenset({"2g", "5g"})
    channels = list(getattr(found[0], "SUPPORTED_CHANNELS", ()) or ())
    if not channels:
        return frozenset({"2g", "5g"})
    bands: set[str] = set()
    if any(channel <= 14 for channel in channels):
        bands.add("2g")
    if any(channel > 14 for channel in channels):
        bands.add("5g")
    return frozenset(bands) or frozenset({"2g", "5g"})


def band_choices(dev: DeviceID) -> tuple[tuple[str, str], ...]:
    """Segments to draw. ``All`` exists only when the radio has both bands."""
    bands = hardware_scan_bands(dev.vid, dev.pid)
    if "2g" in bands and "5g" in bands:
        return _BANDS
    only = "5g" if "5g" in bands else "2g"
    return ((_BAND_ONLY[only], only),)


def default_scan_bands(devices: Sequence[DeviceID]) -> dict[tuple, str]:
    """Pin each dual-band card to the band no single-band card already covers.

    A 2.4 GHz-only adapter next to a dual-band adapter selects 5 GHz on the
    dual-band card. A 5 GHz-only adapter selects 2.4 GHz. When both bands
    already have a dedicated card, or every card is dual-band, the dual-band
    cards stay on all channels.
    """
    if len(devices) < 2:
        return {}
    classified = [(dev, hardware_scan_bands(dev.vid, dev.pid)) for dev in devices]
    covered: set[str] = set()
    for _dev, bands in classified:
        if bands == frozenset({"2g"}):
            covered.add("2g")
        elif bands == frozenset({"5g"}):
            covered.add("5g")
    missing = frozenset({"2g", "5g"}) - covered
    if len(missing) != 1 or not covered:
        return {}
    target = next(iter(missing))
    return {
        dev.instance_key: target
        for dev, bands in classified
        if bands == frozenset({"2g", "5g"})
    }


def _row_id(index: int) -> str:
    return f"device-row-{index}"


def _checkbox_id(index: int) -> str:
    return f"device-chk-{index}"


def _band_bar_id(index: int) -> str:
    return f"device-band-{index}"


def device_name_plain(dev: DeviceID) -> str:
    brand = " ".join(part for part in (dev.vendor, dev.product_name) if part)
    chipset = dev.chipset or "Unknown chipset"
    return f"{chipset} · {brand}" if brand else chipset


class _BandOpt(Static):
    """One segment of the scan-band control. Clicking it selects that band."""

    def __init__(self, label: str, key: str) -> None:
        super().__init__(label, classes=f"band-opt band-{key}")
        self.band_key = key

    def on_click(self, event: Click) -> None:
        event.stop()
        bar = self.parent
        if not isinstance(bar, ScanBandBar):
            return
        if len(bar.choices) > 1:
            bar.value = self.band_key
        picker = bar.parent
        while picker is not None and not isinstance(picker, DevicePicker):
            picker = picker.parent
        if isinstance(picker, DevicePicker):
            index = picker.row_index_at(bar)
            if index is not None:
                picker.highlighted = index
                if len(bar.choices) > 1:
                    picker.note_manual_band(index)


class ScanBandBar(Horizontal):
    """One-line segmented band picker. The selected segment stays filled."""

    DEFAULT_CSS = """
    ScanBandBar {
        width: auto;
        height: 1;
        align: right middle;
        background: $primary 14%;
        margin-left: 1;
    }
    ScanBandBar > .band-sep {
        width: 1;
        height: 1;
        color: $primary 55%;
        content-align: center middle;
    }
    ScanBandBar > .band-opt {
        width: auto;
        height: 1;
        padding: 0 1;
        color: $text-muted;
        background: transparent;
        content-align: center middle;
        text-wrap: nowrap;
    }
    ScanBandBar > .band-opt:hover {
        background: $boost;
        color: $foreground;
    }
    ScanBandBar > .band-opt.-chosen {
        background: $success;
        color: $background;
        text-style: bold;
    }
    ScanBandBar > .band-opt.-chosen:hover {
        background: $success;
        color: $background;
    }
    ScanBandBar.-fixed {
        background: transparent;
    }
    ScanBandBar.-fixed > .band-opt,
    ScanBandBar.-fixed > .band-opt:hover {
        background: transparent;
        color: $text-muted;
        text-style: bold;
    }
    """

    value: reactive[str] = reactive("all")

    def __init__(
        self,
        value: str = "all",
        choices: Sequence[tuple[str, str]] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.choices: tuple[tuple[str, str], ...] = tuple(choices or _BANDS)
        if value in ("all", "2g", "5g"):
            self.value = value
        if len(self.choices) == 1:
            band = self.choices[0][1]
            self.tooltip = f"This adapter only tunes {_ONLY_TOOLTIP.get(band, band)}"
        else:
            self.tooltip = "Only the AP / client scan uses this band"

    def compose(self) -> ComposeResult:
        for index, (label, key) in enumerate(self.choices):
            if index:
                yield Static("│", classes="band-sep")
            yield _BandOpt(label, key)

    def on_mount(self) -> None:
        self._sync_chosen()

    def watch_value(self, _old: str, new: str) -> None:
        if new not in ("all", "2g", "5g"):
            self.value = "all"
            return
        self._sync_chosen()

    def _sync_chosen(self) -> None:
        fixed = len(self.choices) == 1
        self.set_class(fixed, "-fixed")
        if fixed:
            return
        for _label, key in self.choices:
            for opt in self.query(f".band-{key}"):
                opt.set_class(self.value == key, "-chosen")


class DevicePicker(Vertical):
    """Checkbox + adapter label + scan-band toggles for each detected card."""

    DEFAULT_CSS = """
    DevicePicker {
        display: none;
        width: auto;
        max-width: 80;
        height: auto;
        border: round $primary;
        background: $panel;
        padding: 0 1;
    }
    DevicePicker .device-row {
        width: 100%;
        height: 1;
        min-height: 1;
        align: left middle;
        padding: 0;
        margin: 0;
        border-left: tall transparent;
        background: transparent;
    }
    DevicePicker .device-row.-focus {
        border-left: tall $accent;
        background: $boost;
    }
    DevicePicker .device-row Checkbox {
        width: auto;
        height: 1;
        margin: 0 1 0 0;
        padding: 0;
        border: none;
        background: transparent;
        content-align: left middle;
    }
    DevicePicker .device-row Checkbox:focus {
        border: none;
        background: transparent;
    }
    DevicePicker .device-name {
        width: 1fr;
        height: 1;
        min-width: 12;
        padding: 0 1;
        content-align: left middle;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }
    DevicePicker .device-name.-muted {
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("left", "band_prev", "Band", show=False),
        Binding("right", "band_next", "Band", show=False),
    ]

    highlighted: reactive[int] = reactive(0)

    class HighlightChanged(Message):
        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._devices: list[DeviceID] = []
        self._checked_by_key: dict[tuple, bool] = {}
        self._band_by_key: dict[tuple, str] = {}
        self._band_manual: set[tuple] = set()
        self._preferred_width = _PICKER_MIN

    @property
    def preferred_width(self) -> int:
        return self._preferred_width

    def compose(self) -> ComposeResult:
        yield from ()

    def clear_devices(self) -> None:
        self._devices = []
        detach_rows_now(self, ".device-row")
        self.highlighted = 0
        self.display = False
        self.border_title = ""
        self.border_subtitle = ""

    def set_devices(self, devices: Sequence[DeviceID]) -> None:
        self._devices = list(devices)
        detach_rows_now(self, ".device-row")
        if not devices:
            self.display = False
            self.border_title = ""
            self.border_subtitle = ""
            return
        self.display = True
        self.border_title = "Wi‑Fi adapters"
        self._preferred_width = _fit_width(devices)
        self.styles.width = self._preferred_width
        defaults = default_scan_bands(devices)
        for index, dev in enumerate(devices):
            key = dev.instance_key
            if key not in self._checked_by_key:
                self._checked_by_key[key] = True
            choices = band_choices(dev)
            allowed = {band_key for _label, band_key in choices}
            if key in self._band_manual:
                band = self._band_by_key.get(key, "all")
            else:
                band = defaults.get(key, "all")
            if band not in allowed:
                band = "all"
            row = Horizontal(classes="device-row", id=_row_id(index))
            self.mount(row)
            row.mount(
                Checkbox(
                    "",
                    value=self._checked_by_key[key],
                    id=_checkbox_id(index),
                    compact=True,
                )
            )
            row.mount(Static(device_name_plain(dev), classes="device-name"))
            bar = ScanBandBar(value=band, choices=choices, id=_band_bar_id(index))
            row.mount(bar)
        if self.highlighted >= len(devices):
            self.highlighted = max(0, len(devices) - 1)
        self._sync_row_styles()

    def watch_highlighted(self, _old: int, index: int) -> None:
        self._sync_row_styles()
        self.post_message(self.HighlightChanged(index))

    def _sync_row_styles(self) -> None:
        for index in range(len(self._devices)):
            try:
                row = self.query_one(f"#{_row_id(index)}", Horizontal)
                name = row.query_one(".device-name", Static)
            except Exception:
                continue
            # Only show the highlight cursor when there's an actual choice to
            # navigate; a lone row shouldn't carry a selection marker.
            focused = index == self.highlighted and len(self._devices) > 1
            row.set_class(focused, "-focus")
            try:
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                checked = True
            name.set_class(not checked, "-muted")

    def on_checkbox_changed(self, _event: Checkbox.Changed) -> None:
        self._sync_row_styles()

    def selected_devices(self) -> list[DeviceID]:
        out: list[DeviceID] = []
        for index, dev in enumerate(self._devices):
            try:
                checked = self.query_one(f"#{_checkbox_id(index)}", Checkbox).value
            except Exception:
                checked = self._checked_by_key.get(dev.instance_key, True)
            self._checked_by_key[dev.instance_key] = checked
            if checked:
                out.append(dev)
        return out

    def highlighted_device(self) -> DeviceID | None:
        if not self._devices:
            return None
        index = min(max(0, self.highlighted), len(self._devices) - 1)
        return self._devices[index]

    def collect_band_plan(self) -> dict[tuple, str]:
        plan: dict[tuple, str] = {}
        for index, dev in enumerate(self._devices):
            key = dev.instance_key
            try:
                bar = self.query_one(f"#{_band_bar_id(index)}", ScanBandBar)
                band = bar.value
                allowed = {band_key for _label, band_key in bar.choices}
            except Exception:
                band = self._band_by_key.get(key, "all")
                allowed = {band_key for _label, band_key in band_choices(dev)}
            if len(allowed) == 1 or band not in allowed:
                band = "all"
            plan[key] = band
            self._band_by_key[key] = band
        return plan

    def action_band_prev(self) -> None:
        self._step_band(-1)

    def action_band_next(self) -> None:
        self._step_band(1)

    def _step_band(self, delta: int) -> None:
        if not self._devices:
            return
        index = min(max(0, self.highlighted), len(self._devices) - 1)
        try:
            bar = self.query_one(f"#{_band_bar_id(index)}", ScanBandBar)
        except Exception:
            return
        keys = [key for _label, key in bar.choices]
        if len(keys) < 2 or bar.value not in keys:
            return
        current = keys.index(bar.value)
        bar.value = keys[(current + delta) % len(keys)]
        self.note_manual_band(index)

    def note_manual_band(self, index: int) -> None:
        """Remember a band the operator picked, so a later refresh does not overwrite it."""
        if not self._devices:
            return
        index = min(max(0, index), len(self._devices) - 1)
        try:
            bar = self.query_one(f"#{_band_bar_id(index)}", ScanBandBar)
            band = bar.value
        except Exception:
            return
        key = self._devices[index].instance_key
        self._band_by_key[key] = band
        self._band_manual.add(key)

    def focus_list(self) -> None:
        if not self._devices:
            return
        try:
            self.query_one(f"#{_checkbox_id(self.highlighted)}", Checkbox).focus()
        except Exception:
            self.focus()

    def row_index_at(self, widget) -> int | None:
        row = widget
        while row is not None:
            if isinstance(row, Horizontal) and row.id and row.id.startswith("device-row-"):
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
