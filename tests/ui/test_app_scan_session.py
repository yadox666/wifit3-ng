"""App startup scan session wiring (CLI --case vs auto name)."""
import pytest

from wifit3.ui.app import WifiteApp


@pytest.mark.asyncio
async def test_default_launch_starts_session_without_modal():
    app = WifiteApp(case_prompt=False)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.active_scan_session is not None
        assert app.active_scan_session.name.strip()


@pytest.mark.asyncio
async def test_case_prompt_opens_session_modal(monkeypatch):
    opened = False

    def _prompt(self) -> None:
        nonlocal opened
        opened = True
        self.start_scan_session(
            {"wifi", "bluetooth"},
            mode="app",
            name="test-case",
        )

    monkeypatch.setattr(WifiteApp, "_prompt_scan_session", _prompt)

    app = WifiteApp(case_prompt=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert opened is True
        assert app.active_scan_session is not None
        assert app.active_scan_session.name == "test-case"
