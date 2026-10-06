import pytest
from textual.widgets import Button, Input, Select

from wifit3.observe import product_catalog as catalog
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.catalog import CatalogView
from wifit3.ui.screens.catalog_editor import CatalogEditPanel


@pytest.fixture
def user_catalog_path(tmp_path, monkeypatch):
    path = tmp_path / "product-catalog-user.json"
    monkeypatch.setattr(catalog, "user_catalog_path", lambda: path)
    catalog.reload_catalog()
    yield path
    catalog.reload_catalog()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_catalog_editor_saves_new_family(user_catalog_path):
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.push_screen(CatalogView())
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, CatalogView)
        screen.action_new_family()
        await pilot.pause()
        editor = screen.query_one(CatalogEditPanel)
        editor.query_one("#catalog-edit-id", Input).value = "test-gadget"
        editor.query_one("#catalog-edit-label", Input).value = "Test Gadget"
        editor.query_one("#catalog-edit-class", Input).value = "Other"
        editor.query_one("#catalog-edit-notes", Input).value = "A test note"
        editor.query_one(".catalog-clue-text", Input).value = "GadgetX"
        editor.query_one("#catalog-save", Button).press()
        await pilot.pause()
        assert any(f.id == "test-gadget" for f in catalog.families())
        detail = screen.query_one("#catalog-detail")
        assert detail.display is True or not screen.has_class("-editing")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_catalog_add_clue_mounts_visible_row(user_catalog_path):
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.push_screen(CatalogView())
        await pilot.pause()
        screen = app.screen
        screen.action_new_family()
        await pilot.pause()
        editor = screen.query_one(CatalogEditPanel)
        assert len(editor.query(".catalog-clue-row")) == 1
        editor.query_one("#catalog-add-clue", Button).press()
        await pilot.pause()
        assert len(editor.query(".catalog-clue-row")) == 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_catalog_editor_rejects_invalid_name_regex(user_catalog_path):
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.push_screen(CatalogView())
        await pilot.pause()
        screen = app.screen
        screen.action_new_family()
        await pilot.pause()
        editor = screen.query_one(CatalogEditPanel)
        editor.query_one("#catalog-edit-id", Input).value = "bad-regex"
        editor.query_one("#catalog-edit-label", Input).value = "Bad Regex"
        row = editor.query_one(".catalog-clue-row")
        row.query_one(".catalog-clue-kind", Select).value = "name_regex"
        await pilot.pause()
        row.query_one(".catalog-clue-text", Input).value = "[unclosed"
        editor.query_one("#catalog-save", Button).press()
        await pilot.pause()
        assert not any(f.id == "bad-regex" for f in catalog.families())
        status = editor.query_one(".catalog-clue-regex-status")
        assert "-invalid" in status.classes
