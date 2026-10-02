import pytest
from textual.app import App
from textual.widgets import Button, Input

from wifit3.models import AccessPoint, CaptureType
from wifit3.persist.vault import Vault
from wifit3.ui.screens.vault_import import VaultImportModal


class _Host(App):
    def __init__(self):
        super().__init__()
        self.vault = Vault()


@pytest.mark.asyncio
async def test_manual_wpa_credential_import_is_saved_locally():
    app = _Host()
    results = []
    async with app.run_test() as pilot:
        app.push_screen(VaultImportModal(), results.append)
        await pilot.pause(0)
        app.screen.query_one("#import-ssid", Input).value = "Test Network"
        app.screen.query_one("#import-bssid", Input).value = "00:11:22:33:44:55"
        app.screen.query_one("#import-secret", Input).value = "TEST_PASSPHRASE"
        app.screen.query_one("#import-save", Button).press()
        await pilot.pause()

        assert results == [True]
        captures = app.vault.persisted("00:11:22:33:44:55")
        assert len(captures) == 1
        assert captures[0].type == CaptureType.WPA_PSK


@pytest.mark.asyncio
async def test_contextual_wpa_import_prefills_ap_and_focuses_secret():
    app = _Host()
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="Selected Network",
    )

    async with app.run_test() as pilot:
        app.push_screen(VaultImportModal(ap))
        await pilot.pause()

        assert app.screen.query_one("#import-ssid", Input).value == "Selected Network"
        assert app.screen.query_one("#import-bssid", Input).value == ap.bssid
        assert app.focused is app.screen.query_one("#import-secret", Input)
