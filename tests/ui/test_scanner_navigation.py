import pytest

from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.splash import SplashView


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_escape_returns_wifi_scanner_to_device_selection():
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.switch_screen("scanner")
        await pilot.pause(0)
        assert isinstance(app.screen, ScannerView)

        await pilot.press("escape")
        await pilot.pause(0)

        assert isinstance(app.screen, SplashView)
        assert app.array is None
