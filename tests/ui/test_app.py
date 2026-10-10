import pytest

from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.splash import SplashView
from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.offline import OfflineDatabaseView
from textual.widgets import Button, RichLog, DataTable



@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")  # ui/conftest.py
async def test_app_layout_and_boot():
    """Verify the app boots and registers the required screens."""
    app = WifiteApp()
    async with app.run_test() as pilot:
        # Check Title
        assert pilot.app.title.startswith("wifit3")
        
        # Verify we start on the Splash screen
        assert isinstance(pilot.app.screen, SplashView)
        
        # Check Splash Screen Components
        ascii_art = pilot.app.screen.query_one("#ascii-art")
        assert ascii_art is not None
        device_picker = pilot.app.screen.query_one("#device-picker")
        assert device_picker is not None
        offline_button = pilot.app.screen.query_one("#offline-btn", Button)
        assert not offline_button.disabled
        assert "offline" in pilot.app._installed_screens

        pilot.app.screen.action_offline()
        await pilot.pause(0)
        assert isinstance(pilot.app.screen, OfflineDatabaseView)
        assert pilot.app.array is None
        offline = pilot.app.screen
        offline._loading_kinds.discard("aps")
        offline._loaded_kinds.add("aps")
        offline._records["aps"] = [
            {
                "bssid": "00:11:22:33:44:55", "ssid": "First",
                "last_seen": 2, "clients": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
            },
            {
                "bssid": "00:11:22:33:44:66", "ssid": "Second",
                "last_seen": 1, "clients": [],
            },
        ]
        offline._detail_focus = ("aps", "00:11:22:33:44:55")
        offline._render_table("aps", selected_identity="00:11:22:33:44:55")
        table = offline.query_one("#offline-aps", DataTable)
        assert table.row_count >= 2
        assert offline._detail_focus == ("aps", "00:11:22:33:44:55")
        detail = offline.query_one("#offline-detail")
        assert detail is not None

        offline._detail_focus = ("aps", "00:11:22:33:44:66")
        offline._render_table("aps", selected_identity="00:11:22:33:44:66")
        assert offline._detail_focus == ("aps", "00:11:22:33:44:66")

        pilot.app.screen.action_back()
        await pilot.pause(0)
        
        # Manually transition to Scanner View
        pilot.app.push_screen("scanner")
        await pilot.pause(0)
        
        assert isinstance(pilot.app.screen, ScannerView)
        
        # Check Scanner Screen Components
        table = pilot.app.screen.query_one("#ap-table", DataTable)
        assert table is not None
        log = pilot.app.screen.query_one("#system-log", RichLog)
        assert log is not None
        
        # Check that FocusViewV2 is registered (but requires target_ap to mount properly without escaping immediately, so we won't push it here)
        assert "focus" in pilot.app._installed_screens

