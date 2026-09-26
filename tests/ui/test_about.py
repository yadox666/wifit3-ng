import pytest

from wifit3.ui.app import WifiteApp
from wifit3.ui.pref import PreferencesModal
from wifit3.ui.screens.about import AboutModal


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_about_modal_opens_from_preferences():
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.action_preferences()
        await pilot.pause(0)
        assert isinstance(app.screen, PreferencesModal)
        app.screen.action_about()
        await pilot.pause(0)
        assert isinstance(app.screen, AboutModal)
        assert "wifit3" in app.screen.query_one("#about-title").render().plain

    assert not any(binding.key == "ctrl+a" for binding in WifiteApp.BINDINGS)
