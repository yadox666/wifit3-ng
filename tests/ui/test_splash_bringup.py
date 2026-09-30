"""Splash START drives the engine end-to-end for the happy path: a connectable card is pooled into
the array and the scanner is requested. The real WifiteApp / DeviceManager / BringupPrompter (the
progress modal really opens and closes) run; only wlan_iface is stubbed."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual import events
from textual.widgets import Button, Checkbox

from wifit3.chips.driver import DeviceID
from wifit3.device.manager import BringupResult
from wifit3.gps import GpsStatus
from wifit3.setup.base import SetupResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.splash import SplashView, _bluetooth_usb_claim_alert


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

    assert message == (
        "Please unplug and re-plug your Sena UD100 adapter "
        "to claim it from the OS!"
    )


def test_bluetooth_claim_alert_uses_generic_usb_name():
    controller = SimpleNamespace(vid=0x1234, pid=0x5678)

    message = _bluetooth_usb_claim_alert(
        controller,
        RuntimeError("Could not detach OtherChip from the OS Bluetooth driver"),
    )

    assert message == (
        "Please unplug and re-plug your Bluetooth USB device "
        "to claim it from the OS!"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_usb_button_hidden_without_dongle():
    app = WifiteApp()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        splash = app.screen
        assert splash.query_one("#bluetooth-usb-btn").display is False
        assert splash.check_action("start_usb_bluetooth", ()) is False


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
    dev = DeviceID(0x148F, 0x5372, "RT5372 (test)")
    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        splash.render_devices([dev])
        await pilot.pause(0)
        splash._picker().focus_list()

        uninstalled, started = [], []

        async def _fake_uninstall(device_id):
            uninstalled.append(device_id)
            return SetupResult(ok=True, message="removed")

        async def _fake_run(device_id, **kw):
            started.append(device_id)
            return BringupResult.ready()

        monkeypatch.setattr(app.device_manager, "uninstall", _fake_uninstall)
        monkeypatch.setattr(app.device_manager, "bringup", _fake_run)

        uninstall_btn = splash.query_one("#uninstall-btn", Button)
        uninstall_btn.display = True  # hidden on macOS; exercise the handler anyway
        uninstall_btn.focus()
        await pilot.pause(0)
        await pilot.press("enter")
        for _ in range(80):
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
