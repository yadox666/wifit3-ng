import asyncio
import logging
import sys
from pathlib import Path
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Static, Label, Footer, Button, Checkbox
from textual.containers import Vertical, Center, Horizontal
from textual import events, work
from rich.style import Style
from rich.text import Text

from typing import TYPE_CHECKING

from wifit3.ui.ansi_art import make_black_transparent, recolor_logo
from wifit3.ui.screens.setup_error import SetupErrorDialog
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.bluetooth import BluetoothScanError
from wifit3.device.manager import Status
from wifit3.id import oui_db
from wifit3.ui.notification_center import WifiteHeader
from wifit3.ui.screens.bluetooth_picker import BluetoothPicker
from wifit3.ui.screens.device_picker import DevicePicker
from wifit3.ui.screens.gps_picker import GpsPicker
from wifit3.ui.screens.os_ble_picker import OsBlePicker
from wifit3.persist.config import Config

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

logger = logging.getLogger(__name__)

_NG_BADGE_COLUMN = 48

# Suffix appended to a chipset name when 2+ of the same chip are present, so a multi-card
# list doesn't read as a wall of identical names. Flip the glyph here (e.g. "_{n}", "·{n}").
_DUP_SUFFIX = " #{n}"
# A left buffer so chipset names don't butt against the list edge. Widen here for more indent.
_LEFT_MARGIN = " "


def _bluetooth_usb_claim_alert(controller, error: Exception) -> str | None:
    if "could not detach" not in str(error).casefold():
        return None
    device_name = (
        "Sena UD100 adapter"
        if (controller.vid, controller.pid) == (0x0A12, 0x0001)
        else "Bluetooth USB device"
    )
    return (
        f"Please unplug and re-plug your {device_name} "
        "to claim it from the OS!"
    )


def _alpha_head(chipset: str) -> str:
    """The leading non-digit run of a chipset name (``"RTL"`` of ``"RTL8812AU"``)."""
    i = 0
    while i < len(chipset) and not chipset[i].isdigit():
        i += 1
    return chipset[:i]


def device_list_labels(devices) -> list:
    """One Splash interface-list label per device: ``chipset[ #n] · vendor product``. Two-axis
    alignment keeps a multi-card list scannable: the alpha prefix (RTL/MT/RT/AR) is left-padded so
    the model digits line up, and the chipset column is right-padded so the ``·`` separators line
    up. ``#n`` shows only when 2+ cards share a chipset; the ``·`` tail only when a brand is known.
    Alignment is relative to the cards present now, so it re-flows on plug/unplug."""
    if not devices:
        return []
    chip_counts: dict = {}
    for d in devices:
        chip_counts[d.chipset] = chip_counts.get(d.chipset, 0) + 1

    prefix_w = max(len(_alpha_head(d.chipset)) for d in devices)
    seen: dict = {}
    heads = []
    for dev in devices:
        seen[dev.chipset] = seen.get(dev.chipset, 0) + 1
        head = " " * (prefix_w - len(_alpha_head(dev.chipset))) + dev.chipset
        if chip_counts[dev.chipset] > 1:
            head += _DUP_SUFFIX.format(n=seen[dev.chipset])
        heads.append(head)
    head_w = max(len(h) for h in heads)

    labels = []
    for dev, head in zip(devices, heads):
        brand = " ".join(x for x in (dev.vendor, dev.product_name) if x)
        body = f"{head.ljust(head_w)} · {brand}" if brand else head
        labels.append(_LEFT_MARGIN + body)
    return labels


def load_logo() -> Text:
    """Load the ANSI logo from assets."""
    logo_path = Path(__file__).parent.parent / "assets" / "logo_sm.ans"
    try:
        if logo_path.exists():
            logo = Text.from_ansi(logo_path.read_text(encoding="utf-8"))
            return make_black_transparent(_add_ng_badge(logo))
    except Exception:
        pass

    # Fallback
    return Text.from_markup(
        "[bold green]Wifit3[/bold green][bold bright_green]-NG[/bold bright_green]"
        "\n[dim green]// Wireless Auditor[/dim green]"
    )


def _add_ng_badge(logo: Text) -> Text:
    lines = logo.split("\n")
    if len(lines) < 3:
        return logo

    green = Style(color="#00ff00")
    white = Style(color="#ffffff")
    badge = [
        Text("┌────┐", style=green),
        Text("│ ", style=green)
        + Text("N", style=white)
        + Text("G │", style=green),
        Text("└────┘", style=green),
    ]
    for index, badge_line in enumerate(badge):
        line = lines[index]
        if len(line) < _NG_BADGE_COLUMN + len(badge_line):
            line.pad_right(_NG_BADGE_COLUMN + len(badge_line))
        lines[index] = (
            line[:_NG_BADGE_COLUMN]
            + badge_line
            + line[_NG_BADGE_COLUMN + len(badge_line):]
        )
    return Text("\n").join(lines)

LOGO = load_logo()

class SplashView(Screen):
    """Splash + device picker: the logo, the list of live cards, Start and Uninstall buttons. START
    and Uninstall delegate the whole bring-up / setup flow to ``app.device_manager``; the splash only
    picks the cards and reports the terminal result."""

    app: "WifiteApp"

    DEFAULT_CSS = """
    SplashView #bt-picker-slot,
    SplashView #gps-picker-slot {
        display: none;
    }
    """

    BINDINGS = [
        Binding("w", "start", "Wi-Fi"),
        Binding("b", "start_bluetooth", "BLE"),
        Binding("d", "start_usb_bluetooth", "BT + BLE"),
        Binding("o", "offline", "Offline DB"),
        Binding("u", "update_oui", "Update OUI DB"),
    ]

    def __init__(self):
        super().__init__()
        self._is_initializing = False
        # DeviceIDs from the last render (the app's DeviceWatch feeds them), indexed to the rows.
        self._devices = []
        self._usb_bluetooth_controllers = []
        self._gps_status = None
        self._last_optional_hardware_signature: tuple[tuple, tuple] | None = None
    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Vertical(id="splash-container"):
            with Center():
                yield Static(self._logo(), id="ascii-art")
            with Center():
                yield Label("Scanning for compatible hardware…", id="status-label")
            with Center():
                # Persistent failure line. render_devices only touches #status-label, so an error
                # parked here survives the next device refresh (the status line gets overwritten).
                yield Label("", id="error-label")
            with Center():
                yield DevicePicker(id="device-picker")
            with Center():
                yield OsBlePicker(id="os-ble-picker")
            with Center(id="bt-picker-slot"):
                yield BluetoothPicker(id="bluetooth-picker")
            with Center(id="gps-picker-slot"):
                yield GpsPicker(id="gps-picker")
            with Center():
                with Horizontal(id="primary-actions"):
                    yield Button(
                        Text.from_markup("START [bold bright_yellow]W[/]I-FI"),
                        id="start-btn",
                        variant="success",
                    )
                    yield Button(
                        Text.from_markup("SCAN [bold bright_yellow]B[/]LE"),
                        id="bluetooth-btn",
                        variant="primary",
                    )
                    yield Button(
                        Text("BT/BLE Scan"),
                        id="bluetooth-usb-btn",
                        variant="primary",
                    )
                    yield Button(
                        Text.from_markup("[bold bright_yellow]O[/]FFLINE DB"),
                        id="offline-btn",
                        variant="default",
                    )
            with Center():
                # Reverses driver/access changes for the highlighted card.
                yield Button("Uninstall", id="uninstall-btn", variant="error")
        yield GlobalJobTracker()
        yield Footer()

    def _picker(self) -> DevicePicker:
        return self.query_one("#device-picker", DevicePicker)

    def _bt_picker(self) -> BluetoothPicker:
        return self.query_one("#bluetooth-picker", BluetoothPicker)

    def _os_ble_picker(self) -> OsBlePicker:
        return self.query_one("#os-ble-picker", OsBlePicker)

    def _gps_picker(self) -> GpsPicker:
        return self.query_one("#gps-picker", GpsPicker)

    def _sync_adapter_widths(self) -> None:
        """Keep all detected-hardware boxes the same width."""
        shown = [
            picker for picker in (
                self._picker(), self._os_ble_picker(), self._bt_picker(),
                self._gps_picker(),
            )
            if picker.display
        ]
        if not shown:
            return
        width = max(picker.preferred_width for picker in shown)
        for picker in shown:
            picker.styles.width = width

    def _optional_action_button(self, button_id: str) -> Button | None:
        matches = list(self.query(f"#{button_id}"))
        return matches[0] if matches else None

    def _ensure_primary_action_button(
        self,
        button_id: str,
        *,
        visible: bool,
        factory: Button,
    ) -> Button | None:
        """Mount or remove a startup action button before Offline DB."""
        button = self._optional_action_button(button_id)
        if not visible:
            if button is not None:
                button.remove()
            return None
        if button is None:
            bar = self.query_one("#primary-actions", Horizontal)
            offline = self.query_one("#offline-btn", Button)
            bar.mount(factory, before=offline)
            button = self._optional_action_button(button_id)
        return button

    def _optional_hardware_signature(self) -> tuple[tuple, tuple]:
        return (
            tuple(c.instance_key for c in self._usb_bluetooth_controllers),
            self._gps_status.instance_key if self._gps_status is not None else (),
        )

    def _sync_optional_hardware_ui(self) -> None:
        """Panels, buttons, and footer keys for plug-in USB BT hardware."""
        signature = self._optional_hardware_signature()
        layout_changed = signature != self._last_optional_hardware_signature
        controllers = self._usb_bluetooth_controllers
        gps_status = self._gps_status

        if layout_changed:
            self._last_optional_hardware_signature = signature
            self.query_one("#bt-picker-slot", Center).display = bool(controllers)
            self.query_one("#gps-picker-slot", Center).display = gps_status is not None
            self.refresh_bindings()

        usb_button = self.query_one("#bluetooth-usb-btn", Button)
        usb_button.display = bool(controllers)
        if usb_button is not None:
            selected = self._bt_picker().selected_controller()
            usb_button.disabled = selected is None
            if selected is not None:
                usb_button.tooltip = (
                    f"Use {selected.label} for Bluetooth Classic + BLE"
                )
            else:
                usb_button.tooltip = "Select a Bluetooth adapter"

        os_ble_status = self.app.bluetooth_manager.os_ble_status
        ble_button = self.query_one("#bluetooth-btn", Button)
        ble_button.disabled = not (
            os_ble_status.enabled and os_ble_status.available is True
        )
        ble_button.tooltip = (
            "Start discovery through the operating-system BLE layer"
            if not ble_button.disabled else os_ble_status.detail
        )

    def _logo(self) -> Text:
        theme = self.app.current_theme
        return recolor_logo(LOGO, theme.variables, dark=theme.dark)

    def refresh_theme_art(self) -> None:
        logo = self.query_one("#ascii-art", Static)
        logo.update(self._logo())

    @work(exclusive=True, group="oui-db")
    async def action_update_oui(self) -> None:
        try:
            status = await asyncio.to_thread(oui_db.ensure, force=True)
        except Exception:
            self.notify(
                "Could not download oui.txt",
                title="OUI database",
                severity="error",
            )
            return
        self.notify(
            status.message,
            title="OUI database",
            severity="information" if status.ok else "warning",
        )

    def _enter_scanning_mode(self) -> None:
        """The 'pick a card' resting state."""
        self._is_initializing = False
        self._devices = []
        self._last_optional_hardware_signature = None
        self.query_one("#error-label").display = False
        picker = self._picker()
        picker.clear_devices()
        picker.disabled = False
        self._bt_picker().disabled = False
        self._os_ble_picker().disabled = False
        self._os_ble_picker().set_status(self.app.bluetooth_manager.os_ble_status)
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#bluetooth-btn", Button).disabled = False
        self.query_one("#offline-btn", Button).disabled = False
        self._sync_optional_hardware_ui()
        self._sync_adapter_widths()
        self.query_one("#uninstall-btn", Button).disabled = True
        self.query_one("#status-label", Label).update("Scanning for compatible hardware…")

    def _collect_scan_band_plan(self) -> dict[tuple, str]:
        return self._picker().collect_band_plan()

    async def on_mount(self) -> None:
        uninstall = self.query_one("#uninstall-btn", Button)
        if sys.platform == "darwin":
            # macOS has no install step, so there's nothing to uninstall.
            uninstall.display = False
        else:
            hint = "the WinUSB driver" if sys.platform == "win32" else "the udev/modprobe rules"
            uninstall.tooltip = f"Uninstall {hint} for the highlighted card"
        self.app.theme_changed_signal.subscribe(self, lambda _theme: self.refresh_theme_art())
        self._enter_scanning_mode()
        self.set_interval(1.0, self.refresh_usb_bluetooth_controllers)
        await self.refresh_usb_bluetooth_controllers()
        self.probe_os_ble()

    @work(exclusive=True, group="os-ble-probe")
    async def probe_os_ble(self) -> None:
        status = await self.app.bluetooth_manager.probe_os_ble()
        if self.app.screen is self:
            self._os_ble_picker().set_status(status)
            self._sync_optional_hardware_ui()
            self._sync_adapter_widths()

    async def refresh_usb_bluetooth_controllers(self) -> None:
        if self._is_initializing:
            return
        controllers = await asyncio.to_thread(
            self.app.bluetooth_manager.available_usb_controllers,
        )
        bluetooth_changed = [c.instance_key for c in controllers] != [
            c.instance_key for c in self._usb_bluetooth_controllers
        ]
        gps_status = self.app.gps_manager.status
        gps_changed = (
            gps_status.instance_key if gps_status is not None else None
        ) != (
            self._gps_status.instance_key if self._gps_status is not None else None
        )
        self._usb_bluetooth_controllers = controllers
        self._gps_status = gps_status
        if bluetooth_changed:
            self._bt_picker().set_controllers(controllers)
        self._gps_picker().set_status(gps_status, self.app.gps_manager.latest_fix)
        self._os_ble_picker().set_status(self.app.bluetooth_manager.os_ble_status)
        self._sync_optional_hardware_ui()
        if bluetooth_changed or gps_changed:
            self._sync_adapter_widths()

    def reset_for_reentry(self) -> None:
        """Returning to splash (adapter lost): the installed screen only resumes (on_mount doesn't
        re-run) so restore the scanning state, resume the device watch perform_start paused, and
        render the currently-present cards right away (not on the next 0.5s tick)."""
        self._enter_scanning_mode()
        self.app.device_watch.resume()
        self.render_devices(self.app.device_watch.present())
        array = getattr(self.app, "array", None)
        if array is not None and array.members:
            self._picker().refresh_regulatory_from_array(array.members)

    def refresh_regulatory_subtitle(self) -> None:
        """Re-read ``wifi_regulatory_country`` for the adapter panel (e.g. after Preferences)."""
        picker = self._picker()
        if picker._devices:
            picker._refresh_regulatory_subtitle()

    def render_devices(self, devices) -> None:
        """Render the current device list. Called by the app's DeviceWatch on plug/unplug."""
        if self._is_initializing:
            return
        self._devices = devices
        picker = self._picker()
        picker.set_devices(devices)
        array = getattr(self.app, "array", None)
        if array is not None and array.members:
            picker.refresh_regulatory_from_array(array.members)
        self._sync_adapter_widths()

        status = self.query_one("#status-label", Label)
        start_btn = self.query_one("#start-btn", Button)
        uninstall_btn = self.query_one("#uninstall-btn", Button)
        if devices:
            status.update(self._ready_prompt())
            start_btn.disabled = False
            uninstall_btn.disabled = False
            picker.focus_list()
        else:
            status.update("Scanning for compatible hardware…")
            start_btn.disabled = True
            uninstall_btn.disabled = True

    def _show_error(self, message: str, *, title: str = "Card bring-up failed") -> None:
        """Surface a recoverable bring-up failure: a persistent red label (which poll_usb leaves
        alone, unlike the status line) plus a toast."""
        label = self.query_one("#error-label", Label)
        label.update(f"[bold red]{message}[/bold red]")
        label.display = True
        self.notify(message, title=title, severity="error")

    def _clear_error(self) -> None:
        label = self.query_one("#error-label", Label)
        label.update("")
        label.display = False

    def _ready_prompt(self) -> str:
        if len(self._devices) > 1:
            return "[bold $text-success]Check the card(s) to use, then press START[/]"
        return "[bold $text-success]Press START to begin scanning[/]"

    def _start_targets(self) -> list:
        return self._picker().selected_devices()

    def _highlighted_device(self):
        return self._picker().highlighted_device()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        # Textual hides a footer key only when check_action returns False; None keeps
        # it visible but disabled. So return False to drop optional-hardware keys entirely.
        if action == "start_usb_bluetooth" and not self._usb_bluetooth_controllers:
            return False
        return True

    def action_start(self) -> None:
        """START: bring up the checked cards. Clicking a row only toggles it (no auto-start)."""
        if self._is_initializing:
            return
        targets = self._start_targets()
        if not targets:
            if self._devices:                 # 2+ cards present but none checked
                self.notify("Select at least one card.", severity="warning")
            return
        self.perform_start(targets)

    def on_click(self, event: events.Click) -> None:
        """Double-click a row to start (single-card shortcut). One click only highlights."""
        if event.chain < 2 or self._is_initializing:
            return
        if len(self._devices) == 1 and self._picker().row_index_at(event.widget) is not None:
            self.action_start()
            return
        if (
            len(self._usb_bluetooth_controllers) == 1
            and self._bt_picker().row_index_at(event.widget) is not None
        ):
            self.action_start_usb_bluetooth()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox = event.checkbox
        if checkbox.id == "os-ble-enabled":
            Config.os_ble_enabled = checkbox.value
            self.app.bluetooth_manager.set_os_ble_enabled(checkbox.value)
            self.app.persist_config()
            self._os_ble_picker().set_status(self.app.bluetooth_manager.os_ble_status)
            self._sync_optional_hardware_ui()
            if checkbox.value:
                self.probe_os_ble()
            return
        if checkbox.id and checkbox.id.startswith("bt-chk-"):
            self._sync_optional_hardware_ui()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._is_initializing:
            return
        if event.button.id == "start-btn":
            self.action_start()
        elif event.button.id == "bluetooth-btn":
            self.action_start_bluetooth()
        elif event.button.id == "bluetooth-usb-btn":
            self.action_start_usb_bluetooth()
        elif event.button.id == "offline-btn":
            self.action_offline()
        elif event.button.id == "uninstall-btn":
            dev = self._highlighted_device()
            if dev is not None:
                self.perform_uninstall(dev)

    def _enter_busy(self) -> None:
        self._is_initializing = True
        self.app.device_watch.pause()     # freeze the device watch so the list can't churn mid-bring-up
        self._picker().disabled = True
        self._bt_picker().disabled = True
        self._os_ble_picker().disabled = True
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#bluetooth-btn", Button).disabled = True
        for button_id in ("bluetooth-usb-btn",):
            button = self._optional_action_button(button_id)
            if button is not None:
                button.disabled = True
        self.query_one("#offline-btn", Button).disabled = True
        self.query_one("#uninstall-btn", Button).disabled = True

    def _exit_busy(self) -> None:
        self._is_initializing = False
        self.app.device_watch.resume()
        picker = self._picker()
        picker.disabled = False
        self._bt_picker().disabled = False
        self._os_ble_picker().disabled = False
        self.query_one("#start-btn", Button).disabled = not self._devices
        self.query_one("#bluetooth-btn", Button).disabled = False
        self._sync_optional_hardware_ui()
        self.query_one("#offline-btn", Button).disabled = False
        self.query_one("#uninstall-btn", Button).disabled = not self._devices
        if self._devices:
            picker.focus_list()
        else:
            self.query_one("#bluetooth-btn", Button).focus()

    @work(exclusive=True)
    async def perform_start(self, devices) -> None:
        """Bring up each checked card in turn through the engine; enter the scanner if any came up. The
        engine owns the per-card progress modal, the install/replug dialogs, and the platform branching.
        A per-card failure is a toast; a card whose install the user declines (CANCELLED) is skipped."""
        self._clear_error()
        self._enter_busy()
        pooled = 0
        failures = []
        try:
            for dev in devices:
                res = await self.app.device_manager.bringup(dev)
                if res.status is Status.READY:
                    pooled += 1
                elif res.status is Status.FAILED:
                    failures.append(res.message)
        finally:
            self._exit_busy()

        if pooled > 0:
            if failures:
                self.notify(f"{len(failures)} card(s) failed to start.", severity="warning")
            self.app.scan_band_by_instance = self._collect_scan_band_plan()
            self.app.locked_target_id = None
            self.app.auto_lock_armed = True
            self.app.switch_screen("scanner")
        elif failures:
            self._show_error(failures[-1])
        else:  # all declined / nothing checked
            self.query_one("#status-label", Label).update(self._ready_prompt())

    def action_start_bluetooth(self) -> None:
        status = self.app.bluetooth_manager.os_ble_status
        if not status.enabled:
            self.notify("Enable the OS BLE source first.", severity="warning")
            return
        if status.available is not True:
            self.notify(status.detail, title="OS BLE unavailable", severity="warning")
            return
        if not self._is_initializing:
            self.perform_bluetooth_start()

    def action_offline(self) -> None:
        if not self._is_initializing:
            self.app.switch_screen("offline")

    def action_start_usb_bluetooth(self) -> None:
        if self._is_initializing:
            return
        controller = self._bt_picker().selected_controller()
        if controller is None:
            if self._usb_bluetooth_controllers:
                self.notify("Select a Bluetooth adapter.", severity="warning")
            return
        self.perform_usb_bluetooth_start(controller)

    @work(exclusive=True)
    async def perform_bluetooth_start(self) -> None:
        self._clear_error()
        self._enter_busy()
        try:
            await self.app.bluetooth_manager.start()
        except BluetoothScanError as exc:
            self._exit_busy()
            self._show_error(f"Bluetooth scan failed: {exc}", title="Bluetooth unavailable")
            return
        self._exit_busy()
        self.app.locked_target_id = None
        self.app.auto_lock_armed = True
        self.app.switch_screen("bluetooth")

    @work(exclusive=True)
    async def perform_usb_bluetooth_start(self, controller) -> None:
        self._clear_error()
        self._enter_busy()
        try:
            await self.app.bluetooth_manager.start_usb(controller)
        except BluetoothScanError as exc:
            self._exit_busy()
            claim_alert = _bluetooth_usb_claim_alert(controller, exc)
            if claim_alert is not None:
                self._show_error(claim_alert, title="Bluetooth USB device busy")
            else:
                self._show_error(
                    f"Bluetooth USB scan failed: {exc}",
                    title="Bluetooth USB unavailable",
                )
            return
        self._exit_busy()
        self.app.locked_target_id = None
        self.app.auto_lock_armed = True
        self.app.switch_screen("bluetooth")

    @work(exclusive=True)
    async def perform_uninstall(self, device_id) -> None:
        """Reverse wifit3's driver/access for the selected card via the engine."""
        self._clear_error()
        self._enter_busy()
        try:
            res = await self.app.device_manager.uninstall(device_id)
        finally:
            self._exit_busy()

        status = self.query_one("#status-label", Label)
        if res.ok:
            status.update(f"[bold green]{res.message}[/bold green]")
            self.notify(f"[green]✓[/green] {res.message}", title="Uninstalled",
                        severity="information")
        elif res.cancelled:
            status.update(self._ready_prompt())
        else:
            status.update("[bold red]Uninstall failed.[/bold red]")
            self.app.push_screen(SetupErrorDialog("Uninstall failed", res.message, res.detail))
