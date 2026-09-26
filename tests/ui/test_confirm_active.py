import pytest
from textual.app import App

from wifit3.ui.screens.confirm_active import ConfirmActiveActionModal


@pytest.mark.asyncio
async def test_active_action_confirmation_requires_explicit_proceed():
    app = App()
    results = []
    async with app.run_test() as pilot:
        app.push_screen(
            ConfirmActiveActionModal(
                "Broadcast deauthentication",
                "Test Network (00:11:22:33:44:55)",
                "May disconnect clients.",
            ),
            results.append,
        )
        await pilot.pause(0)
        app.screen.action_cancel()
        await pilot.pause(0)
        assert results == [False]
