import pytest
from textual.app import App
from textual.widgets import Input, Static

from wifit3.gps import GpsStatus
from wifit3.models.location import LocationFix
from wifit3.ui.screens.session_start_modal import SessionStartInput, SessionStartModal


@pytest.mark.asyncio
async def test_session_start_modal_returns_edited_values():
    app = App()
    results: list[SessionStartInput] = []
    async with app.run_test() as pilot:
        app.push_screen(SessionStartModal("cedar-orbit"), results.append)
        await pilot.pause()
        app.screen.query_one("#session-name", Input).value = "client-demo-march"
        app.screen.query_one("#session-description", Input).value = (
            "Rooftop pass — building B"
        )
        await pilot.click("#session-start")
        await pilot.pause()
    assert len(results) == 1
    assert results[0].name == "client-demo-march"
    assert results[0].description == "Rooftop pass — building B"


@pytest.mark.asyncio
async def test_session_start_modal_enter_accepts_and_closes():
    app = App()
    results: list[SessionStartInput] = []
    async with app.run_test() as pilot:
        app.push_screen(SessionStartModal("cedar-orbit"), results.append)
        await pilot.pause()
        # The name input is focused on mount; Enter should accept immediately.
        await pilot.press("enter")
        await pilot.pause()
    assert len(results) == 1
    assert results[0].name == "cedar-orbit"
    assert results[0].description == ""


@pytest.mark.asyncio
async def test_session_start_modal_enter_accepts_edited_name_from_notes():
    app = App()
    results: list[SessionStartInput] = []
    async with app.run_test() as pilot:
        app.push_screen(SessionStartModal("cedar-orbit"), results.append)
        await pilot.pause()
        app.screen.query_one("#session-name", Input).value = "client-demo"
        app.screen.query_one("#session-description", Input).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    assert len(results) == 1
    assert results[0].name == "client-demo"


@pytest.mark.asyncio
async def test_session_start_modal_hides_gps_row_without_receiver():
    app = App()
    async with app.run_test() as pilot:
        app.push_screen(SessionStartModal("cedar-orbit"))
        await pilot.pause()
        assert not list(app.screen.query("#session-gps"))


@pytest.mark.asyncio
async def test_session_start_modal_shows_configured_port_search():
    app = App()
    async with app.run_test() as pilot:
        app.push_screen(
            SessionStartModal("cedar-orbit", gps_configured_port="/dev/ttyUSB0"),
        )
        await pilot.pause()
        gps = app.screen.query_one("#session-gps", Static)
        assert "/dev/ttyUSB0" in gps.render().plain


@pytest.mark.asyncio
async def test_session_start_modal_shows_fix():
    app = App()
    fix = LocationFix(
        latitude=51.5,
        longitude=-0.12,
        altitude_m=10.0,
        accuracy_m=3.0,
        observed_at=1.0,
        source="nmea:gga",
    )
    async with app.run_test() as pilot:
        app.push_screen(SessionStartModal("cedar-orbit", gps_fix=fix))
        await pilot.pause()
        gps = app.screen.query_one("#session-gps", Static)
        assert "51.50000" in gps.render().plain


@pytest.mark.asyncio
async def test_session_start_modal_shows_waiting_when_connected():
    app = App()
    status = GpsStatus(port="/dev/ttyUSB0", baudrate=9600, product="GPS")
    async with app.run_test() as pilot:
        app.push_screen(
            SessionStartModal("cedar-orbit", gps_status=status),
        )
        await pilot.pause()
        gps = app.screen.query_one("#session-gps", Static)
        assert "waiting for satellite fix" in gps.render().plain.casefold()
