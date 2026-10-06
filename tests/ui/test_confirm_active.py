import pytest
from textual.app import App

from wifit3.ui.screens.confirm_active import (
    ConfirmActiveActionModal,
    ConfirmEndScanModal,
    ConfirmLeaveFocusModal,
)


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


@pytest.mark.asyncio
async def test_leave_focus_confirmation_lists_actions_and_requires_confirm():
    app = App()
    results = []
    async with app.run_test() as pilot:
        app.push_screen(
            ConfirmLeaveFocusModal(
                ["Background monitor", "Focused packet capture"],
                destination="the scanner",
            ),
            results.append,
        )
        await pilot.pause(0)
        app.screen.action_cancel()
        await pilot.pause(0)
        assert results == [False]

        results.clear()
        app.push_screen(
            ConfirmLeaveFocusModal(["Probe honeypot"], destination="the client list"),
            results.append,
        )
        await pilot.pause(0)
        app.screen.action_confirm()
        await pilot.pause(0)
        assert results == [True]


@pytest.mark.asyncio
async def test_end_scan_confirmation_requires_explicit_confirm():
    app = App()
    results: list[bool] = []
    async with app.run_test() as pilot:
        app.push_screen(ConfirmEndScanModal(), results.append)
        await pilot.pause(0)
        app.screen.action_cancel()
        await pilot.pause(0)
        assert results == [False]

        results.clear()
        app.push_screen(ConfirmEndScanModal(), results.append)
        await pilot.pause(0)
        app.screen.action_confirm()
        await pilot.pause(0)
        assert results == [True]
