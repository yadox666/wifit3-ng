"""Splash START drives the engine end-to-end for the happy path: a connectable card is pooled into
the array and the scanner is requested. The real WifiteApp / DeviceManager / BringupPrompter (the
progress modal really opens and closes) run; only wlan_iface is stubbed."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual import events
from textual.widgets import Checkbox

from wifit3.chips.driver import DeviceID
from wifit3.device.manager import BringupResult
from wifit3.gps import GpsStatus
from wifit3.persist.config import Config
from wifit3.sdr import HackRfDevice
from wifit3.setup.base import SetupResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.splash import SplashView, _bluetooth_usb_claim_alert
from wifit3.ui.screens.spectrum import RfSpectrumView


def _fake_iface():
    return SimpleNamespace(
        name="wlan0", description="RT5372 (test)", vid=0x148F, pid=0x5372,
        bus=1, address=1, instance_key=(0x148F, 0x5372, 1, 1),
        supported_channels=[1, 6, 11], on_tx=None,
        register_rx_callback=lambda cb: None, register_disconnect_callback=lambda cb: None,
        connect=AsyncMock(return_value=True), close=AsyncMock())


def test_bluetooth_claim_alert_names_sena_ud100():
    controller = SimpleNamespace(vid=0x0A12, pid=0x0001)

    message = _bluetooth_usb_claim_alert(
        controller,
        RuntimeError("Could not detach BlueCore4-ROM from the OS Bluetooth driver"),
    )

    assert message is not None
    assert "Sena UD100" in message
    assert "↻" in message


def test_bluetooth_claim_alert_uses_generic_usb_name():
    controller = SimpleNamespace(vid=0x1234, pid=0x5678)

    message = _bluetooth_usb_claim_alert(
        controller,
        RuntimeError("Could not detach OtherChip from the OS Bluetooth driver"),
    )

    assert message is not None
    assert "Bluetooth USB device" in message
    assert "↻" in message


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_spectrum_button_is_disabled_without_an_sdr():
    """Hardware-gated buttons are never removed, only disabled (and the footer
    key stays visible-but-disabled too, consistent with every other action)."""
    app = WifiteApp()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        splash = app.screen

        assert splash.query_one("#spectrum-btn").disabled is True
        assert splash.query_one("#sdr-picker-slot").display is False
        assert splash.check_action("start_spectrum", ()) is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_update_oui_shows_a_download_progress_bar(monkeypatch):
    """Pressing 'u' reveals a small, centered progress bar below the buttons,
    fed live by the download, that hides again once it finishes."""
    from textual.widgets import ProgressBar
    from wifit3.id import oui_db

    def _fake_ensure(*, force, progress=None):
        # Drive the bar as the real download would, then report success.
        progress(0, 1000)
        progress(500, 1000)
        progress(1000, 1000)
        return oui_db.OuiStatus(True, True, 42, "downloaded 42 vendors")

    monkeypatch.setattr(oui_db, "ensure", _fake_ensure)

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        panel = splash.query_one("#oui-progress")
        assert panel.display is False       # hidden until invoked

        splash.action_update_oui()
        for _ in range(40):
            await pilot.pause()
            if "42 vendors" in str(splash.query_one("#oui-progress-status").render()):
                break

        bar = splash.query_one("#oui-progress-bar", ProgressBar)
        assert bar.total == 1000
        assert bar.progress == 1000
        assert "42 vendors" in str(splash.query_one("#oui-progress-status").render())


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_update_oui_hides_progress_on_download_error(monkeypatch):
    from wifit3.id import oui_db

    def _boom(*, force, progress=None):
        raise OSError("offline")

    monkeypatch.setattr(oui_db, "ensure", _boom)

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        notified = []
        monkeypatch.setattr(splash, "notify", lambda msg, **kw: notified.append(msg))
        splash.action_update_oui()
        for _ in range(40):
            await pilot.pause()
            if splash.query_one("#oui-progress").display is False:
                break
        # The progress panel must not be left stuck open after a failure.
        assert splash.query_one("#oui-progress").display is False
        assert any("Was not able to download" in m for m in notified)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_update_oui_times_out_if_download_never_starts(monkeypatch):
    """A connection that never streams bytes must fail fast, not spin forever."""
    import time as _time
    from wifit3.id import oui_db
    from wifit3.ui.screens import splash as splash_mod

    monkeypatch.setattr(splash_mod, "OUI_START_TIMEOUT_S", 0.2)

    def _never_starts(*, force, progress=None):
        _time.sleep(0.6)                      # "connecting" but never reports progress
        return oui_db.OuiStatus(False, False, 0, "nope")

    monkeypatch.setattr(oui_db, "ensure", _never_starts)

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        notified = []
        monkeypatch.setattr(splash, "notify", lambda msg, **kw: notified.append(msg))
        splash.action_update_oui()
        for _ in range(60):
            await pilot.pause()
            if notified:
                break
        assert any("Was not able to download" in m for m in notified)
        assert splash.query_one("#oui-progress").display is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_update_oui_hides_percentage_until_determinate(monkeypatch):
    """The '--%' readout stays hidden while connecting (indeterminate) and only
    appears once a real percentage is known."""
    import threading
    from wifit3.id import oui_db

    release = threading.Event()

    def _slow_start(*, force, progress=None):
        progress(0, None)                     # indeterminate: connecting, no total yet
        release.wait(2.0)
        progress(500, 1000)                   # now determinate
        progress(1000, 1000)
        return oui_db.OuiStatus(True, True, 42, "downloaded 42 vendors")

    monkeypatch.setattr(oui_db, "ensure", _slow_start)

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        splash.action_update_oui()
        for _ in range(40):
            await pilot.pause()
            if splash.query_one("#oui-progress").display:
                break

        pct = splash.query_one("#oui-progress-bar").query_one("#percentage")
        # Indeterminate phase: percentage hidden.
        assert pct.display is False

        release.set()
        for _ in range(40):
            await pilot.pause()
            if pct.display:
                break
        # Determinate phase: percentage shown.
        assert pct.display is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_multi_card_start_brings_up_only_checked(monkeypatch):
    # 2+ cards -> checkbox list, all checked by default. Unchecking one and pressing START must bring
    # up only the checked card, one run() per card (no silent auto-pool of the rest).
    devA = DeviceID(0x0E8D, 0x7961, "MT7921AU", bus=2, address=32)
    devB = DeviceID(0x0E8D, 0x7961, "MT7921AU", bus=2, address=35)

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)

        splash.render_devices([devA, devB])
        await pilot.pause(0)
        picker = splash.query_one("#device-picker")
        assert picker.display is True
        assert len(picker.selected_devices()) == 2

        splash.query_one("#device-chk-1", Checkbox).value = False
        await pilot.pause(0)
        assert len(picker.selected_devices()) == 1

        ran = []

        async def _fake_run(device_id, **kw):
            ran.append(device_id)
            return BringupResult.ready()

        monkeypatch.setattr(app.device_manager, "bringup", _fake_run)
        monkeypatch.setattr(app, "switch_screen", lambda name: None)

        splash.action_start()
        for _ in range(40):
            await pilot.pause(0)
            if ran:
                break

        assert ran == [devA]                 # only the checked card, devB skipped


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_enter_uninstalls_when_uninstall_button_focused(monkeypatch):
    # Enter activates the focused Uninstall button (same as clicking it).
    # Uninstall only exists on Linux/Windows (macOS has no install step and hides
    # the button), so pin a non-macOS platform to exercise the behavior anywhere.
    import sys
    monkeypatch.setattr(sys, "platform", "linux")
    dev = DeviceID(0x148F, 0x5372, "RT5372 (test)")
    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        splash.render_devices([dev])         # single card -> ListView, highlighted
        await pilot.pause(0)

        uninstalled, started = [], []

        async def _fake_uninstall(device_id):
            uninstalled.append(device_id)
            return SetupResult(ok=True, message="removed")

        async def _fake_run(device_id, **kw):
            started.append(device_id)
            return BringupResult.ready()

        monkeypatch.setattr(app.device_manager, "uninstall", _fake_uninstall)
        monkeypatch.setattr(app.device_manager, "bringup", _fake_run)

        splash.query_one("#uninstall-btn").focus()
        await pilot.pause(0)
        await pilot.press("enter")
        for _ in range(40):
            await pilot.pause(0)
            if uninstalled:
                break

        assert uninstalled == [dev] and started == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_single_click_highlights_double_click_starts(monkeypatch):
    # Single-card view: a single click only highlights (no start); a double click starts Wi-Fi.
    dev = DeviceID(0x148F, 0x5372, "RT5372 (test)")
    app = WifiteApp()
    started = []

    async def _fake_run(device_id, **kw):
        started.append(device_id)
        return BringupResult.ready()

    async with app.run_test(size=(120, 40)) as pilot:
        app.device_manager.bringup = _fake_run
        monkeypatch.setattr(app, "switch_screen", lambda name: started.append(("switch", name)))
        splash = app.screen
        splash.render_devices([dev])
        await pilot.pause(0)

        row = splash.query_one("#device-row-0")
        splash.on_click(events.Click(row, 0, 0, 0, 0, 1, False, False, False, chain=1))
        await pilot.pause(0)
        assert started == []                                  # highlight only, no start

        splash.on_click(events.Click(row, 0, 0, 0, 0, 1, False, False, False, chain=2))
        for _ in range(40):
            await pilot.pause(0)
            if started:
                break
        assert dev in started                                 # started, like Enter / START


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_hackrf_is_shown_in_its_own_splash_panel(monkeypatch):
    device = HackRfDevice(0x1D50, 0x6089, 2, 7)
    monkeypatch.setattr("wifit3.sdr.find_hackrf_devices", lambda: [device])

    app = WifiteApp()
    async with app.run_test(size=(120, 45)) as pilot:
        await pilot.pause(0)
        panel = app.screen.query_one("#sdr-picker")

        assert panel.display is True
        assert panel.border_title == "Software-defined radios"
        assert panel.query_one("#sdr-row-0 .sdr-name").render().plain == device.label
        assert app.screen.query_one("#spectrum-btn") is not None


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecking_sdr_device_disables_its_buttons(monkeypatch):
    device = HackRfDevice(0x1D50, 0x6089, 2, 7)
    monkeypatch.setattr("wifit3.sdr.find_hackrf_devices", lambda: [device])

    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        spectrum_btn = splash.query_one("#spectrum-btn")
        assert not spectrum_btn.disabled

        splash.query_one("#sdr-chk-0", Checkbox).value = False
        for _ in range(5):
            await pilot.pause(0)

        assert spectrum_btn.disabled
        # The footer/menu key bindings must track the buttons exactly - they
        # share the same _sync_primary_actions() -> refresh_bindings() path.
        assert splash.check_action("start_spectrum", ()) is None

        notified = []
        monkeypatch.setattr(
            splash, "notify", lambda msg, **kw: notified.append(msg),
        )
        splash.action_start_spectrum()
        assert notified                       # warned instead of switching screens
        assert app.screen is splash

        splash.query_one("#sdr-chk-0", Checkbox).value = True
        for _ in range(5):
            await pilot.pause(0)
        assert not spectrum_btn.disabled
        # Regression guard: menus must re-enable right alongside the buttons.
        assert splash.check_action("start_spectrum", ()) is True

        # The footer widget itself only updates its rendered FooterKeys when
        # Screen.refresh_bindings() fires screen.bindings_updated_signal - it
        # does NOT re-run check_action() on its own. Confirm the actual footer
        # key for "r" (RF Spectrum) is really re-enabled, not just that
        # check_action() would say so if asked directly.
        await pilot.pause()
        from textual.widgets import Footer
        from textual.widgets._footer import FooterKey
        footer = splash.query_one(Footer)
        spectrum_key = next(
            k for k in footer.query(FooterKey) if k.action == "start_spectrum"
        )
        assert not spectrum_key.has_class("-disabled")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecking_wifi_device_disables_wifi_and_background():
    """Wi-Fi must follow the same selection-aware disable rule as Bluetooth/SDR:
    unchecking the only Wi-Fi card disables WI-FI, and BACKGROUND once
    OS BLE is also off (nothing left to use) - buttons and footer menus alike."""
    dev = DeviceID(0x0BDA, 0x8812, "RTL8812AU", bus=1, address=3)

    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        splash = app.screen
        splash.render_devices([dev])
        await pilot.pause(0)
        splash.query_one("#os-ble-enabled", Checkbox).value = False
        for _ in range(5):
            await pilot.pause(0)

        start_btn = splash.query_one("#start-btn")
        bg_btn = splash.query_one("#background-btn")
        assert not start_btn.disabled
        assert not bg_btn.disabled
        assert start_btn.label.plain == "WI-FI"

        splash.query_one("#device-chk-0", Checkbox).value = False
        for _ in range(5):
            await pilot.pause(0)

        assert start_btn.disabled
        assert bg_btn.disabled
        assert start_btn.label.plain == "WI-FI"
        assert splash.check_action("start", ()) is None
        assert splash.check_action("start_background", ()) is None

        from textual.widgets import Footer
        from textual.widgets._footer import FooterKey
        await pilot.pause()
        footer = splash.query_one(Footer)
        wifi_key = next(k for k in footer.query(FooterKey) if k.action == "start")
        assert wifi_key.has_class("-disabled")

        splash.query_one("#device-chk-0", Checkbox).value = True
        for _ in range(5):
            await pilot.pause(0)

        assert not start_btn.disabled
        assert not bg_btn.disabled
        assert start_btn.label.plain == "WI-FI"
        assert splash.check_action("start", ()) is True
        assert splash.check_action("start_background", ()) is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_os_ble_box_width_stays_synced_after_disabling():
    """Disabling OS BLE must not shrink its box smaller than the other adapter boxes."""
    dev = DeviceID(0x0E8D, 0x7961, "MT7921AU Very Long Adapter Model Name", bus=2, address=32)

    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        splash.render_devices([dev])
        await pilot.pause(0)

        wifi_panel = splash.query_one("#device-picker")
        os_ble_panel = splash.query_one("#os-ble-picker")
        width_before = os_ble_panel.styles.width.value
        assert width_before == wifi_panel.styles.width.value

        splash.query_one("#os-ble-enabled", Checkbox).value = False
        await pilot.pause(0)

        assert os_ble_panel.styles.width.value == width_before
        assert os_ble_panel.styles.width.value == wifi_panel.styles.width.value

        splash.query_one("#os-ble-enabled", Checkbox).value = True
        await pilot.pause(0)

        assert os_ble_panel.styles.width.value == width_before
        assert os_ble_panel.styles.width.value == wifi_panel.styles.width.value


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_refresh_usb_resyncs_width_after_os_ble_status_update():
    """The 1s USB refresh calls set_status on OS BLE; widths must stay matched."""
    from wifit3.bluetooth.manager import OsBleSourceStatus

    dev = DeviceID(0x0E8D, 0x7961, "MT7921AU Very Long Adapter Model Name", bus=2, address=32)
    checking = OsBleSourceStatus(
        enabled=True,
        available=True,
        state="OS-CHECKING",
        backend="CoreBluetooth",
        operating_system="Darwin",
        manufacturer="Apple",
        adapter="Built-in",
        detail="probing",
    )
    ready = OsBleSourceStatus(
        enabled=True,
        available=True,
        state="OS-READY",
        backend="CoreBluetooth",
        operating_system="Darwin",
        manufacturer="Apple",
        adapter="Built-in",
        detail="ready",
    )

    app = WifiteApp()
    app.bluetooth_manager.os_ble_status = checking
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        splash.render_devices([dev])
        splash._os_ble_picker().set_status(checking)
        splash._sync_adapter_widths()
        await pilot.pause(0)

        wifi_panel = splash.query_one("#device-picker")
        os_ble_panel = splash.query_one("#os-ble-picker")
        width_before = wifi_panel.styles.width.value
        assert os_ble_panel.styles.width.value == width_before

        app.bluetooth_manager.os_ble_status = ready
        await splash.refresh_usb_bluetooth_controllers()
        await pilot.pause(0)

        assert os_ble_panel.styles.width.value == width_before
        assert os_ble_panel.styles.width.value == wifi_panel.styles.width.value


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecking_gps_disables_use_without_stopping_receiver():
    app = WifiteApp()
    app.gps_manager.status = GpsStatus(port="/dev/ttyUSB0", baudrate=9600)
    app.gps_manager.start = lambda: None

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        assert app.gps_manager.enabled is True

        splash = app.screen
        panel = splash.query_one("#gps-picker")
        splash.query_one("#gps-chk-0", Checkbox).value = False
        for _ in range(5):
            await pilot.pause(0)

        assert app.gps_manager.enabled is False
        assert Config.gps_enabled is False
        assert panel.query_one(".gps-name").has_class("-muted")
        # Disabling is a soft "don't use it" switch - the receiver keeps running.
        assert app.gps_manager.status is not None

        splash.query_one("#gps-chk-0", Checkbox).value = True
        for _ in range(5):
            await pilot.pause(0)
        assert app.gps_manager.enabled is True
        assert Config.gps_enabled is True
        assert not panel.query_one(".gps-name").has_class("-muted")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_connected_gps_is_shown_with_receiver_information():
    app = WifiteApp()
    app.gps_manager.status = GpsStatus(
        port="/dev/ttyUSB0",
        baudrate=9600,
        description="u-blox GNSS receiver",
        manufacturer="u-blox",
        product="NEO-M8U",
        vid=0x1546,
        pid=0x01A8,
    )
    app.gps_manager.start = lambda: None

    async with app.run_test(size=(120, 45)) as pilot:
        await pilot.pause(0)
        panel = app.screen.query_one("#gps-picker")

        assert panel.display is True
        assert panel.border_title == "GPS / GNSS receivers"
        assert "u-blox NEO-M8U" in panel.query_one(".gps-name").render().plain
        assert "/dev/ttyUSB0" in panel.query_one(".gps-name").render().plain
        assert "9,600 baud" in panel.query_one(".gps-name").render().plain
        assert panel.query_one(".gps-mode").render().plain == "NMEA · NO FIX"
        assert panel.query_one(".gps-name").tooltip == (
            "u-blox NEO-M8U · /dev/ttyUSB0 · 9,600 baud · NMEA · NO FIX"
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_spectrum_button_opens_receive_only_analyzer(monkeypatch):
    device = HackRfDevice(0x1D50, 0x6089, 2, 7)

    async def start_sweep(_self, _start_mhz, _stop_mhz, **_kwargs):
        return None

    monkeypatch.setattr("wifit3.sdr.find_hackrf_devices", lambda: [device])
    monkeypatch.setattr(
        "wifit3.ui.screens.spectrum.HackRfSweep.start",
        start_sweep,
    )

    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        splash.action_start_spectrum()
        for _ in range(20):
            await pilot.pause(0)
            if isinstance(app.screen, RfSpectrumView):
                break

        assert isinstance(app.screen, RfSpectrumView)
        assert "RECEIVING" in app.screen.query_one("#spectrum-status").render().plain
