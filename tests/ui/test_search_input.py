import pytest

from wifit3.ui.search_input import SearchInput


@pytest.mark.asyncio
async def test_search_input_toggles_has_text_class():
    from textual.app import App, ComposeResult

    class Host(App):
        def compose(self) -> ComposeResult:
            yield SearchInput(id="search")

    app = Host()
    async with app.run_test() as pilot:
        field = app.query_one("#search", SearchInput)
        assert "-has-text" not in field.classes
        field.value = "office"
        await pilot.pause(0)
        assert "-has-text" in field.classes
        field.value = ""
        await pilot.pause(0)
        assert "-has-text" not in field.classes
