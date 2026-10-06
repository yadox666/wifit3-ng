import pytest

from textual.app import App
from textual.widgets import Button

from wifit3.updates import UpdateInfo
from wifit3.ui.app import WifiteApp
from wifit3.ui.pref import PreferencesModal
from wifit3.ui.screens import about
from wifit3.ui.screens.about import AboutModal, UpdateAvailableModal


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


class _UpdateHost(App):
    def on_mount(self) -> None:
        self.push_screen(UpdateAvailableModal(UpdateInfo(
            current_version="1.0.0",
            latest_version="2.0.0",
            release_url="https://github.com/yadox666/wifit3-ng/releases/tag/v2.0.0",
        )))


@pytest.mark.asyncio
async def test_update_modal_opens_the_validated_release(monkeypatch):
    opened = []
    monkeypatch.setattr(about.webbrowser, "open", opened.append)

    app = _UpdateHost()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        assert isinstance(app.screen, UpdateAvailableModal)
        assert "2.0.0" in app.screen.query_one("#update-details").render().plain
        app.screen.query_one("#update-open", Button).press()
        await pilot.pause(0)

    assert opened == [
        "https://github.com/yadox666/wifit3-ng/releases/tag/v2.0.0",
    ]


@pytest.mark.asyncio
async def test_update_modal_starts_verified_install(monkeypatch):
    installed = []
    monkeypatch.setattr(about, "can_install_update", lambda _update: True)

    class InstallHost(_UpdateHost):
        def install_update(self, update):
            installed.append(update)

    app = InstallHost()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        app.screen.query_one("#update-install", Button).press()
        await pilot.pause(0)

    assert [update.latest_version for update in installed] == ["2.0.0"]
