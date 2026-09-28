from unittest.mock import Mock

import pytest
from textual.widgets import Button, Checkbox, Input

from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.clear_history import ClearHistoryModal, HistoryClearSelection
from wifit3.ui.screens.splash import SplashView


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_history_menu_exists_only_on_startup_and_requires_exact_phrase():
    app = WifiteApp()
    async with app.run_test(size=(100, 40)) as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)
        assert len(splash.query("#clear-history-btn")) == 0
        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, ClearHistoryModal)

        modal = app.screen
        dialog = modal.query_one("#history-dialog")
        assert dialog.region.height < 24
        assert modal.query_one("#history-options").region.height == 4
        modal.query_one("#clear-wifi-history", Checkbox).value = True
        confirmation = modal.query_one("#history-confirmation", Input)
        confirmation.value = "delete now!"
        await pilot.pause(0)
        assert modal.query_one("#confirm-history-clear", Button).disabled

        confirmation.value = "DELETE NOW!"
        await pilot.pause(0)
        assert not modal.query_one("#confirm-history-clear", Button).disabled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_confirmed_menu_can_clear_wifi_and_bluetooth_independently():
    app = WifiteApp()
    app.ap_history_store.clear = Mock()
    app.hidden_ssid_store.clear = Mock()
    app.wifi_profile_store.clear = Mock()
    app.enterprise_session_store.clear = Mock()
    app.bluetooth_history_store.clear = Mock()
    app.bluetooth_manager.forget_devices = Mock()
    app.target_store.clear_medium = Mock()

    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.press("c")
        await pilot.pause()
        modal = app.screen
        modal.query_one("#clear-bluetooth-history", Checkbox).value = True
        modal.query_one("#history-confirmation", Input).value = "DELETE NOW!"
        await pilot.pause(0)
        modal.query_one("#confirm-history-clear", Button).press()
        await pilot.pause(0)

        app.bluetooth_history_store.clear.assert_called_once_with()
        app.bluetooth_manager.forget_devices.assert_called_once_with()
        app.target_store.clear_medium.assert_called_once_with("bluetooth")
        app.ap_history_store.clear.assert_not_called()
        assert isinstance(app.screen, SplashView)

        app.screen._clear_history(HistoryClearSelection(wifi=True, bluetooth=False))
        app.ap_history_store.clear.assert_called_once_with()
        app.hidden_ssid_store.clear.assert_called_once_with()
        app.wifi_profile_store.clear.assert_called_once_with()
        app.enterprise_session_store.clear.assert_called_once_with()
        app.bluetooth_history_store.clear.assert_called_once_with()
        assert app.target_store.clear_medium.call_args_list[-1].args == ("wifi",)

        app.screen._disable_history_deletion()
        assert app.screen.check_action("clear_db", ()) is None
