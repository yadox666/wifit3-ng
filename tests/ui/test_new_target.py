import pytest
from textual.app import App
from textual.widgets import Button, Input

from wifit3.targeting import TargetCandidate
from wifit3.ui.screens.new_target import NewTargetModal, NewTargetResult


class _Host(App):
    def __init__(self, candidate):
        super().__init__()
        self.candidate = candidate
        self.result = "pending"

    def on_mount(self):
        self.push_screen(NewTargetModal(self.candidate), self._completed)

    def _completed(self, result):
        self.result = result


def _candidate():
    return TargetCandidate(
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        title="Office",
        details={"ssid": "Office", "channel": 6},
    )


@pytest.mark.asyncio
async def test_new_target_requires_alias_and_can_save_and_lock():
    app = _Host(_candidate())
    async with app.run_test() as pilot:
        await pilot.pause(0)
        modal = app.screen
        modal.query_one("#target-lock", Button).press()
        await pilot.pause(0)
        assert "Alias is required" in modal.query_one("#target-error").render().plain

        modal.query_one("#target-alias", Input).value = "Main router"
        modal.query_one("#target-lock", Button).press()
        await pilot.pause(0)
        assert app.result == NewTargetResult(alias="Main router", lock=True)


@pytest.mark.asyncio
async def test_new_target_save_and_continue_does_not_lock():
    app = _Host(_candidate())
    async with app.run_test() as pilot:
        await pilot.pause(0)
        app.screen.query_one("#target-alias", Input).value = "Observe only"
        app.screen.query_one("#target-save", Button).press()
        await pilot.pause(0)
        assert app.result == NewTargetResult(alias="Observe only", lock=False)
