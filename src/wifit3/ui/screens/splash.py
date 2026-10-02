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
from wifit3.ui.screens.sdr_picker import SdrPicker
from wifit3.persist.config import Config
from wifit3.wlan.scan_plan import member_channels_for_scan

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
    lowered = str(error).casefold()
    if "could not detach" not in lowered and "could not claim" not in lowered:
        return None
    device_name = (
        "Sena UD100 adapter"
        if (controller.vid, controller.pid) == (0x0A12, 0x0001)
        else "Bluetooth USB device"
    )
    return (
        f"Your {device_name} is still owned by the OS. "
        "Click ⎋ on that adapter in the Bluetooth adapters list to release it "
        "(on macOS this briefly turns Bluetooth off), or unplug and re-plug once."
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
            logo = _add_ng_badge(logo)
            logo = _add_private_edition_badge(logo)
            return make_black_transparent(logo)
    except Exception:
        pass

    # Fallback
    return Text.from_markup(
        "[bold green]Wifit3[/bold green][bold bright_green]-NG[/bold bright_green]"
        "\n[dim green]// Wireless Auditor[/dim green]"
    )


def _overlay_badge(lines: list[Text], start_row: int, column: int, badge: list[Text]) -> None:
    for offset, badge_line in enumerate(badge):
        row = start_row + offset
        if row < 0 or row >= len(lines):
            continue
        line = lines[row]
        end = column + len(badge_line)
        if len(line) < end:
            line.pad_right(end)
        lines[row] = line[:column] + badge_line + line[end:]


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
    _overlay_badge(lines, 0, _NG_BADGE_COLUMN, badge)
    return Text("\n").join(lines)


def _add_private_edition_badge(logo: Text) -> Text:
    """Bottom-right lab marker (two lines inside a small frame)."""
    lines = logo.split("\n")
    accent = Style(color="#ff00aa")
    white = Style(bold=True, color="#ffffff")
    badge = [
        Text("┌─────────┐", style=accent),
        Text("│ ", style=accent) + Text("PRIVATE", style=white) + Text(" │", style=accent),
        Text("│ ", style=accent) + Text("EDITION", style=white) + Text(" │", style=accent),
        Text("└─────────┘", style=accent),
    ]
    if len(lines) < len(badge):
        return logo
    column = max(len(line) for line in lines) - len(badge[0])
    if column < 0:
        column = 0
    _overlay_badge(lines, len(lines) - len(badge), column, badge)
    return Text("\n").join(lines)

LOGO = load_logo()

class SplashView(Screen):
    """Splash + device picker: the logo, the list of live cards, Start and Uninstall buttons. START
    and Uninstall delegate the whole bring-up / setup flow to ``app.device_manager``; the splash only
    picks the cards and reports the terminal result."""

    app: "WifiteApp"

    DEFAULT_CSS = """
    SplashView #bt-picker-slot,
    SplashView #sdr-picker-slot,
    SplashView #gps-picker-slot {
        display: none;
    }
    """

    BINDINGS = [
        Binding("w", "start", "Wi-Fi"),
        Binding("b", "start_bluetooth", "BLE"),
        Binding("g", "start_background", "Background"),
        Binding("d", "start_usb_bluetooth", "BT + BLE"),
        Binding("r", "start_spectrum", "RF Spectrum"),
        Binding("o", "offline", "Offline DB"),
        Binding("u", "update_oui", "Update OUI DB"),
    ]

    def __init__(self):
        super().__init__()
        self._is_initializing = False
        # DeviceIDs from the last render (the app's DeviceWatch feeds them), indexed to the rows.
        self._devices = []
        self._usb_bluetooth_controllers = []
        self._bt_not_claimed_snapshot: frozenset[tuple] = frozenset()
        self._hackrf_devices = []
        self._gps_status = None
        self._last_optional_hardware_signature: tuple[tuple, tuple, tuple] | None = None
        self._background_active = False
        self._background_stop_event: asyncio.Event | None = None
        self._background_timer = None
        self._bt_autoreclaim_done = False

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
            with Center(id="sdr-picker-slot"):
                yield SdrPicker(id="sdr-picker")
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
                        Text.from_markup("BACK[bold bright_yellow]G[/]ROUND"),
                        id="background-btn",
                        variant="warning",
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

    def _sdr_picker(self) -> SdrPicker:
        return self.query_one("#sdr-picker", SdrPicker)

    def _gps_picker(self) -> GpsPicker:
        return self.query_one("#gps-picker", GpsPicker)

    def _sync_adapter_widths(self) -> None:
        """Keep all detected-hardware boxes the same width."""
        shown = [
            picker for picker in (
                self._picker(), self._os_ble_picker(), self._bt_picker(),
                self._sdr_picker(), self._gps_picker(),
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
        """Mount or remove a startup action button before Background / Offline DB."""
        button = self._optional_action_button(button_id)
        if not visible:
            if button is not None:
                button.remove()
            return None
        if button is None:
            bar = self.query_one("#primary-actions", Horizontal)
            anchor = self.query_one("#background-btn", Button)
            bar.mount(factory, before=anchor)
            button = self._optional_action_button(button_id)
        return button

    def _optional_hardware_signature(self) -> tuple[tuple, tuple, tuple]:
        return (
            tuple(c.instance_key for c in self._usb_bluetooth_controllers),
            tuple(d.instance_key for d in self._hackrf_devices),
            self._gps_status.instance_key if self._gps_status is not None else (),
        )

    def _sync_optional_hardware_ui(self) -> None:
        """Panels, buttons, and footer keys for plug-in USB BT and SDR hardware."""
        signature = self._optional_hardware_signature()
        layout_changed = signature != self._last_optional_hardware_signature
        controllers = self._usb_bluetooth_controllers
        hackrf = self._hackrf_devices
        gps_status = self._gps_status

        if layout_changed:
            self._last_optional_hardware_signature = signature
            self.query_one("#bt-picker-slot", Center).display = bool(controllers)
            self._ensure_primary_action_button(
                "bluetooth-usb-btn",
                visible=bool(controllers),
                factory=Button(
                    Text("BT/BLE Scan"),
                    id="bluetooth-usb-btn",
                    variant="primary",
                ),
            )
            self.query_one("#sdr-picker-slot", Center).display = bool(hackrf)
            self._ensure_primary_action_button(
                "spectrum-btn",
                visible=bool(hackrf),
                factory=Button(
                    Text.from_markup("[bold bright_yellow]R[/]F-SPECTRUM"),
                    id="spectrum-btn",
                    variant="primary",
                ),
            )
            self.query_one("#gps-picker-slot", Center).display = gps_status is not None
            self.refresh_bindings()

        usb_button = self._optional_action_button("bluetooth-usb-btn")
        if usb_button is not None:
            selected = self._bt_picker().selected_controller()
            usb_button.disabled = selected is None
            if selected is not None:
                usb_button.tooltip = (
                    f"Use {selected.label} for Bluetooth Classic + BLE"
                )
            else:
                usb_button.tooltip = "Select a Bluetooth adapter"

        spectrum_button = self._optional_action_button("spectrum-btn")
        if spectrum_button is not None:
            spectrum_button.disabled = False
            spectrum_button.tooltip = "Open the receive-only RF spectrum analyzer"
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
        self._set_background_button(running=False)
        self.set_interval(1.0, self.refresh_usb_bluetooth_controllers)
        await self.refresh_usb_bluetooth_controllers()
        self.autoreclaim_usb_bluetooth_once()
        self.probe_os_ble()
        if self.app.background_autostart:
            self.autostart_background()

    @work(exclusive=True, group="os-ble-probe")
    async def probe_os_ble(self) -> None:
        status = await self.app.bluetooth_manager.probe_os_ble()
        if self.app.screen is self:
            self._os_ble_picker().set_status(status)
            self._sync_optional_hardware_ui()
            self._sync_adapter_widths()

    async def refresh_usb_bluetooth_controllers(self) -> None:
        if self._is_initializing:
            if self._background_active:
                await self._attach_reserved_usb()
            return
        from wifit3.sdr import find_hackrf_devices

        controllers, hackrf_devices = await asyncio.gather(
            asyncio.to_thread(self.app.bluetooth_manager.available_usb_controllers),
            asyncio.to_thread(find_hackrf_devices),
        )
        bluetooth_changed = [c.instance_key for c in controllers] != [
            c.instance_key for c in self._usb_bluetooth_controllers
        ]
        hackrf_changed = [d.instance_key for d in hackrf_devices] != [
            d.instance_key for d in self._hackrf_devices
        ]
        gps_status = self.app.gps_manager.status
        gps_changed = (
            gps_status.instance_key if gps_status is not None else None
        ) != (
            self._gps_status.instance_key if self._gps_status is not None else None
        )
        not_claimed = self.app.bluetooth_manager.usb_not_claimed_keys()
        claim_changed = not_claimed != self._bt_not_claimed_snapshot
        self._usb_bluetooth_controllers = controllers
        self._hackrf_devices = hackrf_devices
        self._gps_status = gps_status
        self._bt_not_claimed_snapshot = not_claimed
        if bluetooth_changed or claim_changed:
            self._bt_picker().set_controllers(controllers, not_claimed=not_claimed)
        if hackrf_changed:
            self._sdr_picker().set_devices(hackrf_devices)
        self._gps_picker().set_status(gps_status, self.app.gps_manager.latest_fix)
        self._os_ble_picker().set_status(self.app.bluetooth_manager.os_ble_status)
        self._sync_optional_hardware_ui()
        if bluetooth_changed or claim_changed or hackrf_changed or gps_changed:
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
        if action == "start_spectrum" and not self._hackrf_devices:
            return False
            return False
        if self._background_active and action in {
            "start",
            "start_bluetooth",
            "start_usb_bluetooth",
            "start_spectrum",
            "offline",
        }:
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
        if event.button.id == "background-btn":
            self.action_start_background()
            return
        if self._is_initializing:
            return
        if event.button.id == "start-btn":
            self.action_start()
        elif event.button.id == "bluetooth-btn":
            self.action_start_bluetooth()
        elif event.button.id == "bluetooth-usb-btn":
            self.action_start_usb_bluetooth()
        elif event.button.id == "spectrum-btn":
            self.action_start_spectrum()
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
        for button_id in ("bluetooth-usb-btn", "spectrum-btn", "background-btn"):
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
        self._set_background_button(running=False)
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

    def _set_background_button(self, *, running: bool) -> None:
        button = self.query_one("#background-btn", Button)
        if running:
            button.label = "Stop monitor"
            button.tooltip = "Stop background monitor"
            button.disabled = False
            button.variant = "error"
            return
        button.label = Text.from_markup("BACK[bold bright_yellow]G[/]ROUND")
        button.tooltip = (
            "Record Wi-Fi, BLE, and Bluetooth on this screen until you stop"
        )
        button.disabled = False
        button.variant = "warning"

    def action_start_background(self) -> None:
        """Stay on this screen and record every enabled radio until stop or quit."""
        if self._background_active:
            self._request_background_stop()
            return
        if self._is_initializing:
            return
        self.perform_background_start(force_all=False)

    def _request_background_stop(self) -> None:
        if self._background_stop_event is not None:
            self._background_stop_event.set()
        button = self.query_one("#background-btn", Button)
        button.disabled = True
        self.query_one("#status-label", Label).update("Stopping background monitor…")

    def _background_selection(self, force_all: bool):
        """Checked Wi-Fi cards, OS BLE, and the selected USB controller.

        ``--all`` turns OS BLE on for this launch and uses every present Wi-Fi
        card plus a USB controller when one is plugged in.
        """
        if force_all:
            self.app.bluetooth_manager.set_os_ble_enabled(True)
            try:
                checkbox = self.query_one("#os-ble-enabled", Checkbox)
                if not checkbox.value:
                    checkbox.value = True
            except Exception:
                pass
            wifi = list(self._devices)
            controller = self._bt_picker().selected_controller()
            if controller is None and self._usb_bluetooth_controllers:
                controller = self._usb_bluetooth_controllers[0]
        else:
            wifi = self._start_targets()
            controller = (
                self._bt_picker().selected_controller()
                if self._usb_bluetooth_controllers else None
            )
        status = self.app.bluetooth_manager.os_ble_status
        use_ble = bool(status.enabled and status.available is not False)
        return wifi, use_ble, controller

    def _background_is_live(self) -> bool:
        array = self.app.array
        wifi = array is not None and bool(array.members)
        return wifi or self.app.bluetooth_manager.is_scanning

    def _refresh_background_status(self) -> None:
        parts = ["Background monitor"]
        array = self.app.array
        if array is not None and array.members:
            parts.append(f"Wi-Fi {len(array.access_points)} AP")
        manager = self.app.bluetooth_manager
        if manager.is_scanning:
            radios = []
            if manager.os_ble_status.state == "OS-ACTIVE":
                radios.append("BLE")
            if manager.is_usb_scanning:
                radios.append("BT")
            parts.append(f"{'+'.join(radios) or 'Bluetooth'} {len(manager.devices())}")
        if self.app.gps_manager.latest_fix is not None:
            parts.append("GPS")
        elif self._gps_status is not None:
            parts.append("GPS wait")
        parts.append("recording")
        self.query_one("#status-label", Label).update(
            "[bold]" + " · ".join(parts) + "[/]"
        )

    async def _background_wifi(self, devices) -> tuple[int, list[str]]:
        pooled = 0
        failures: list[str] = []
        for dev in devices:
            if self._background_stop_event is not None and self._background_stop_event.is_set():
                break
            res = await self.app.device_manager.bringup(dev)
            if res.status is Status.READY:
                pooled += 1
            elif res.status is Status.FAILED:
                failures.append(res.message)
        if (
            pooled
            and self._background_stop_event is not None
            and not self._background_stop_event.is_set()
        ):
            array = self.app.array
            if array is not None and array.members:
                self.app.scan_band_by_instance = self._collect_scan_band_plan()
                member_channels = member_channels_for_scan(
                    array.members, None, self.app.scan_band_by_instance,
                )
                await array.start_hopping(
                    interval=0.25,
                    member_channels=member_channels,
                )
        return pooled, failures

    async def _background_radios(self, use_ble: bool, controller) -> list[str]:
        if self._background_stop_event is not None and self._background_stop_event.is_set():
            return []
        if not use_ble and controller is None:
            return []
        try:
            failures = await self.app.bluetooth_manager.start_parallel(
                os_ble=use_ble,
                controller=controller,
            )
        except Exception as exc:
            logger.debug("background radio start failed", exc_info=True)
            failures = [str(exc) or type(exc).__name__]
        if controller is None:
            return failures
        return [
            _bluetooth_usb_claim_alert(controller, RuntimeError(message)) or message
            for message in failures
        ]

    async def _attach_reserved_usb(self) -> None:
        """After a replug, macOS reservation holds the dongle. Start it without a second claim."""
        manager = self.app.bluetooth_manager
        if manager.is_usb_scanning:
            return
        try:
            controllers = await asyncio.to_thread(manager.available_usb_controllers)
        except Exception:
            logger.debug("background USB refresh failed", exc_info=True)
            return
        held = [controller for controller in controllers if manager.usb_reservation_held(controller)]
        if not held:
            return
        failures = await self._background_radios(False, held[0])
        if failures:
            return
        if manager.is_usb_scanning:
            self._clear_error()
            self._refresh_background_status()

    async def _stop_background_engines(self) -> None:
        array = self.app.array
        if array is not None:
            await array.stop_hopping()
            await array.close()
            if self.app.array is array:
                self.app.array = None
        await self.app.bluetooth_manager.stop()

    def _restore_idle_status(self) -> None:
        label = self.query_one("#status-label", Label)
        if self._devices:
            label.update(self._ready_prompt())
        else:
            label.update("Scanning for compatible hardware…")

    @work(exclusive=True, group="background-autostart")
    async def autostart_background(self) -> None:
        """``--background``: wait for the first hardware pass, then start the monitor."""
        await self.app.device_watch.poll()
        await self.refresh_usb_bluetooth_controllers()
        if self.app.background_all:
            self.app.bluetooth_manager.set_os_ble_enabled(True)
        status = await self.app.bluetooth_manager.probe_os_ble()
        if self.app.screen is self:
            self._os_ble_picker().set_status(status)
            self._sync_optional_hardware_ui()
            self._sync_adapter_widths()
        if self._background_active or self._is_initializing:
            return
        self.perform_background_start(force_all=bool(self.app.background_all))

    @work(exclusive=True, group="background-monitor")
    async def perform_background_start(self, force_all: bool = False) -> None:
        """Bring up the enabled radios and keep hopping on this screen."""
        self._background_stop_event = asyncio.Event()
        self._background_active = True
        self._clear_error()
        self._enter_busy()
        self._set_background_button(running=True)
        self.query_one("#status-label", Label).update("Starting background monitor…")
        timer = None
        try:
            wifi, use_ble, controller = self._background_selection(force_all)
            _wifi_result, radio_failures = await asyncio.gather(
                self._background_wifi(wifi),
                self._background_radios(use_ble, controller),
            )
            _pooled, wifi_failures = _wifi_result
            if self._background_stop_event.is_set():
                return
            for message in (*wifi_failures, *radio_failures):
                if message.startswith("Please unplug"):
                    self._show_error(message, title="Bluetooth USB device busy")
                else:
                    self.notify(message, title="Background monitor", severity="warning")
            if not self._background_is_live():
                self.notify(
                    "Nothing is available to monitor. Enable a Wi-Fi card, BLE, or a Bluetooth adapter.",
                    title="Background monitor",
                    severity="warning",
                )
                return
            self._refresh_background_status()
            timer = self.set_interval(1.0, self._refresh_background_status)
            self._background_timer = timer
            await self._background_stop_event.wait()
        finally:
            if timer is not None:
                timer.stop()
            self._background_timer = None
            try:
                await self._stop_background_engines()
            except Exception:
                logger.debug("background monitor stop failed", exc_info=True)
            self._background_active = False
            try:
                self._exit_busy()
                self._restore_idle_status()
            except Exception:
                logger.debug("background monitor ui restore failed", exc_info=True)

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

    def action_start_spectrum(self) -> None:
        if self._is_initializing or not self._hackrf_devices:
            return
        self.app.switch_screen("spectrum")
        spectrum = self.app.get_screen("spectrum")
        self.app.call_after_refresh(spectrum.activate)


    def on_bluetooth_picker_reclaim_requested(
        self, event: BluetoothPicker.ReclaimRequested,
    ) -> None:
        if self._is_initializing or self._background_active:
            return
        self.perform_reclaim_bluetooth_usb(event.controller)

    @work(exclusive=True, group="bt-usb-reclaim")
    async def perform_reclaim_bluetooth_usb(self, controller) -> None:
        self.query_one("#status-label", Label).update(
            "Releasing USB Bluetooth adapter from the OS…"
        )
        ok, message = await asyncio.to_thread(
            self.app.bluetooth_manager.reclaim_usb_controller, controller,
        )
        await self.refresh_usb_bluetooth_controllers()
        self.query_one("#status-label", Label).update(self._ready_prompt())
        if ok:
            self.notify(message, title="Bluetooth USB", severity="information")
        else:
            self.notify(message, title="Bluetooth USB", severity="warning")

    @work(exclusive=True, group="bt-usb-reclaim")
    async def autoreclaim_usb_bluetooth_once(self) -> None:
        """One soft reclaim pass when the splash opens (avoids replug when the OS still holds the dongle)."""
        if self._bt_autoreclaim_done:
            return
        self._bt_autoreclaim_done = True
        await asyncio.sleep(0.25)
        for controller in list(self._usb_bluetooth_controllers):
            if controller.instance_key not in self.app.bluetooth_manager.usb_not_claimed_keys():
                continue
            await asyncio.to_thread(
                self.app.bluetooth_manager.reclaim_usb_controller, controller,
            )
        await self.refresh_usb_bluetooth_controllers()

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
        if controller.instance_key in self.app.bluetooth_manager.usb_not_claimed_keys():
            await asyncio.to_thread(
                self.app.bluetooth_manager.reclaim_usb_controller, controller,
            )
            await self.refresh_usb_bluetooth_controllers()
        manager = self.app.bluetooth_manager
        use_os_ble = (
            Config.os_ble_enabled
            and manager.os_ble_enabled
            and manager.os_ble_status.available is not False
        )
        try:
            failures = await manager.start_parallel(
                os_ble=use_os_ble,
                controller=controller,
            )
        except BluetoothScanError as exc:
            self._exit_busy()
            claim_alert = _bluetooth_usb_claim_alert(controller, exc)
            if claim_alert is not None:
                self._show_error(claim_alert, title="Bluetooth USB device busy")
            else:
                self._show_error(
                    f"Bluetooth scan failed: {exc}",
                    title="Bluetooth unavailable",
                )
            return
        if not manager.is_scanning:
            self._exit_busy()
            detail = "; ".join(failures) if failures else "No scanner started"
            self._show_error(
                f"Bluetooth scan failed: {detail}",
                title="Bluetooth unavailable",
            )
            return
        for message in failures:
            claim_alert = _bluetooth_usb_claim_alert(controller, RuntimeError(message))
            self.notify(
                claim_alert or message,
                title="Bluetooth scan",
                severity="warning",
            )
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
