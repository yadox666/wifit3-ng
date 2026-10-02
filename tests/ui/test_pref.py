"""The Ctrl+P preferences modal (ui/pref.py): Save survives a failing Config.save(),
and Consolidate has moved out of Prefs into the Vault screen."""
import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, Input, Select

from wifit3.persist.config import Config, ConfigError
from wifit3.persist.vault import Vault
from wifit3.ui.pref import PreferencesModal
from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.scanner import ScannerView


class _Host(App):
    """A bare app to host the modal (no USB, no splash)."""
    def __init__(self):
        super().__init__()
        self.vault = Vault()


def _raise_config_error() -> None:
    raise ConfigError("disk full")


@pytest.mark.asyncio
async def test_save_notifies_instead_of_crashing_on_config_error(monkeypatch):
    monkeypatch.setattr(Config, "save", staticmethod(_raise_config_error))
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        modal = app.screen
        toasts = []
        monkeypatch.setattr(modal, "notify", lambda *a, **k: toasts.append((a, k)))

        app.screen.query_one("#save", Button).press()   # would propagate ConfigError if uncaught
        await pilot.pause(0)

        assert toasts, "a failed save should surface a toast"
        assert toasts[0][1].get("title") == "Config Error"
        assert not isinstance(app.screen, PreferencesModal)   # dismissed anyway


@pytest.mark.asyncio
async def test_prefs_no_longer_hosts_consolidate(tmp_path):
    """Consolidate moved to the Vault screen; Prefs must not show it, even with legacy files."""
    (tmp_path / "HomeNet_aa-bb-cc-dd-ee-ff_1700000001_handshake.hc22000").write_text("WPA*02*...\n")
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        assert len(app.screen.query("#consolidate")) == 0


@pytest.mark.asyncio
async def test_ap_expiry_setting_is_applied_and_cancelled():
    Config.scanner_ap_expiry = 30.0
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        expiry = app.screen.query_one("#ap_expiry", Select)
        assert expiry.value == 30.0

        expiry.value = 120.0
        await pilot.pause(0)
        assert Config.scanner_ap_expiry == 120.0

        app.screen.action_cancel()
        assert Config.scanner_ap_expiry == 30.0


@pytest.mark.asyncio
async def test_wps_pbc_preference_applies_to_current_session(monkeypatch):
    monkeypatch.setattr(Config, "auto_wps_pbc", False)
    monkeypatch.setattr(Config, "save", staticmethod(lambda: None))
    app = _Host()
    app.pbc_enabled = False
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        app.screen.query_one("#auto_wps_pbc", Checkbox).value = True
        app.screen.query_one("#save", Button).press()
        await pilot.pause(0)

        assert Config.auto_wps_pbc is True
        assert app.pbc_enabled is True


@pytest.mark.asyncio
async def test_unlimited_capture_parts_preference_can_be_saved(monkeypatch):
    monkeypatch.setattr(Config, "target_capture_max_parts", 10)
    monkeypatch.setattr(Config, "save", staticmethod(lambda: None))
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        parts = app.screen.query_one("#target_capture_max_parts", Select)
        parts.value = 0
        app.screen.query_one("#save", Button).press()
        await pilot.pause(0)

        assert Config.target_capture_max_parts == 0


@pytest.mark.asyncio
async def test_gps_accuracy_preference_can_be_saved(monkeypatch):
    monkeypatch.setattr(Config, "gps_max_accuracy_m", 20.0)
    monkeypatch.setattr(Config, "save", staticmethod(lambda: None))
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        app.screen.query_one("#gps_max_accuracy_m", Input).value = "12"
        app.screen.query_one("#save", Button).press()
        await pilot.pause(0)

        assert Config.gps_max_accuracy_m == 12.0


@pytest.mark.asyncio
async def test_regulatory_country_preference_can_be_saved(monkeypatch):
    monkeypatch.setattr(Config, "wifi_regulatory_country", "00")
    monkeypatch.setattr(Config, "save", staticmethod(lambda: None))
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        app.screen.query_one("#wifi_regulatory_country", Select).value = "US"
        app.screen.query_one("#save", Button).press()
        await pilot.pause(0)

        assert Config.wifi_regulatory_country == "US"


@pytest.mark.asyncio
async def test_history_deletion_is_not_available_in_preferences():
    app = _Host()
    async with app.run_test() as pilot:
        app.push_screen(PreferencesModal())
        await pilot.pause(0)
        assert len(app.screen.query("#clear-history-btn")) == 0
        assert len(app.screen.query("#clear-ap-history")) == 0


def test_wps_pbc_hotkey_is_not_shown_in_wifi_footers():
    assert not any(binding.key == "w" for binding in ScannerView.BINDINGS)
    assert not any(
        binding.key == "w" and binding.description == "WPS PBC"
        for binding in FocusViewV2.BINDINGS
    )
