"""Background monitor stays on the startup screen and records without opening a scanner."""
import pytest

from wifit3.chips.driver import DeviceID
from wifit3.device.manager import BringupResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.background_monitor_modal import BackgroundMonitorModal
from wifit3.ui.screens.splash import SplashView
from textual.widgets import ProgressBar, Static
from wifit3.__main__ import build_parser, check_cli


def test_background_all_is_a_cli_flag():
    args = build_parser().parse_args(["--background", "--all"])
    assert args.background is True
    assert args.all is True


def test_case_prompt_is_a_cli_flag():
    assert build_parser().parse_args([]).case is False
    assert build_parser().parse_args(["--case"]).case is True


def test_all_requires_background():
    parser = build_parser()
    args = parser.parse_args(["--all"])
    with pytest.raises(SystemExit):
        check_cli(parser, args)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_background_monitor_stays_on_splash_and_locks_actions(monkeypatch):
    dev = DeviceID(0x0BDA, 0x8812, "RTL8812AU", bus=1, address=3)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)
        splash.render_devices([dev])
        await pilot.pause()

        hopped = {}

        class FakeArray:
            def __init__(self):
                self.members = [type("Member", (), {
                    "instance_key": dev.instance_key,
                    "supported_channels": [1, 6, 11, 36],
                    "name": "wlan0",
                })()]
                self.access_points = {"ap-1": object()}
                self.clients = {"sta-1": object(), "sta-2": object()}

            async def start_hopping(self, **_kwargs):
                hopped["started"] = True

            async def stop_hopping(self):
                hopped["stopped"] = True

            async def close(self):
                hopped["closed"] = True

        async def _fake_run(device_id, **_kw):
            assert device_id is dev
            app.array = FakeArray()
            return BringupResult.ready()

        async def _fake_parallel(**_kwargs):
            hopped["radios"] = True
            return []

        switched = []
        monkeypatch.setattr(app.device_manager, "bringup", _fake_run)
        monkeypatch.setattr(app.bluetooth_manager, "start_parallel", _fake_parallel)
        monkeypatch.setattr(app, "switch_screen", lambda name: switched.append(name))

        await pilot.click("#background-btn")
        stats = ""
        for _ in range(80):
            await pilot.pause()
            if not (hopped.get("started") and hopped.get("radios")):
                continue
            if isinstance(app.screen, BackgroundMonitorModal):
                stats = app.screen.query_one(
                    "#background-progress-stats", Static,
                ).render().plain
                if "WIFI-APS" in stats:
                    break

        assert hopped.get("started") is True
        assert hopped.get("radios") is True
        assert switched == []
        assert isinstance(app.get_screen("splash"), SplashView)
        assert isinstance(app.screen, BackgroundMonitorModal)
        assert splash.query_one("#start-btn").disabled is True
        assert splash.query_one("#bluetooth-btn").disabled is True
        assert splash.query_one("#offline-btn").disabled is True
        assert "Stop" in str(splash.query_one("#background-btn").label)
        assert splash.query_one("#background-btn").disabled is False
        modal = app.screen
        assert isinstance(modal, BackgroundMonitorModal)
        assert modal.query_one("#background-progress-bar", ProgressBar).total is None
        assert "WIFI-APS" in stats and "WIFI-STA" in stats
        assert "      1         2" in stats
        assert splash.check_action("update_oui", ()) is None
        assert app.check_action("preferences", ()) is None

        # Button has a ~0.2s "-active" press-effect debounce (see Textual's
        # Button._on_click): a second click landing inside that window is
        # silently ignored. Real users never click that fast; wait it out here.
        await pilot.pause(0.25)
        await pilot.click("#background-stop")
        for _ in range(40):
            await pilot.pause()
            if hopped.get("closed"):
                break

        assert hopped.get("stopped") is True
        assert hopped.get("closed") is True
        assert app.array is None
        assert switched == []
        assert isinstance(app.screen, SplashView)
        assert splash.query_one("#start-btn").disabled is False
        assert splash._background_active is False
        assert isinstance(app.screen, SplashView)
