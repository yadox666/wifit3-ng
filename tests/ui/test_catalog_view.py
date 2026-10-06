import pytest
from textual.widgets import Button, DataTable, Input, Static

from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.catalog import CatalogView
from wifit3.ui.screens.vault_item import ConfirmModal


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_catalog_lists_families_and_filters_by_search():
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.push_screen(CatalogView())
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, CatalogView)
        table = screen.query_one("#catalog-table", DataTable)
        labels = [str(table.get_row(key)[3]) for key in table.rows]
        assert "Flock Safety Cameras" in labels
        assert "Penguin" in labels
        detail = screen.query_one("#catalog-detail", Static)
        assert "hypothesis" in _plain(detail)

        screen.query_one("#catalog-filter-text", Input).value = "xuntong"
        await pilot.pause()
        labels = [str(table.get_row(key)[3]) for key in table.rows]
        assert labels == ["Penguin"]
        assert "0x09C8" in _plain(detail)

        screen.query_one("#clear-catalog-filter-text", Button).press()
        await pilot.pause()
        labels = [str(table.get_row(key)[3]) for key in table.rows]
        assert "Flock Safety Cameras" in labels
        assert screen.query_one("#catalog-filter-text", Input).value == ""


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_catalog_apply_to_offline_db_runs_store_reapply(monkeypatch):
    reloaded: list[str] = []
    monkeypatch.setattr(
        "wifit3.ui.screens.catalog.reload_catalog",
        lambda: reloaded.append("reload"),
    )
    app = WifiteApp()
    wifi_calls: list[int] = []
    bt_calls: list[int] = []
    app.ap_history_store.reapply_product_catalog = lambda: wifi_calls.append(1) or 2
    app.bluetooth_history_store.reapply_product_catalog = (
        lambda: bt_calls.append(1) or 5
    )
    async with app.run_test() as pilot:
        pilot.app.push_screen(CatalogView())
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(pilot.app.screen, ConfirmModal)
        pilot.app.screen.query_one("#yes", Button).press()
        await pilot.pause(0.5)
    assert reloaded == ["reload"]
    assert wifi_calls == [1]
    assert bt_calls == [1]


def _plain(detail: Static) -> str:
    rendered = detail.render()
    return rendered.plain if hasattr(rendered, "plain") else str(rendered)
