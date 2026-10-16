"""The scanner header's right slot shows the live hopped channel(s), padded so hops
don't resize it, instead of a wall clock, and it renders without needing a window resize."""
from types import SimpleNamespace

import pytest
import pytest_asyncio
from textual.app import App, ComposeResult

from wifit3.ui.screens.scanner import _ChannelReadout, _ScannerHeader


def _array(*channels):
    return SimpleNamespace(members=[SimpleNamespace(current_channel=c) for c in channels])


class _Host(App):
    def __init__(self, array=None):
        super().__init__()
        self.array = array

    def compose(self) -> ComposeResult:
        yield _ScannerHeader()


@pytest.mark.asyncio
async def test_single_card_channel_is_visible_on_first_paint():
    # Own boot: the slot sizes at first paint; a shared header is already past it.
    app = _Host(_array(1))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        readout = app.query_one(_ChannelReadout)
        # The readout renders a trailing "  |  " separator so it sits cleanly
        # next to the NotificationBell icon in the header's right slot.
        assert readout.channels == "APS: 0  STA: 0  |  CH:  1  |  "
        assert readout.region.width > 0


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def channel_readout():
    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        yield app.query_one(_ChannelReadout)


@pytest.mark.asyncio(loop_scope="module")
async def test_multi_card_joined_and_width_padded(channel_readout):
    channel_readout.app.array = _array(9, 149)
    channel_readout._poll()
    assert channel_readout.channels == "APS: 0  STA: 0  |  CH:  9 | CH:149  |  "


@pytest.mark.asyncio(loop_scope="module")
async def test_no_array_is_blank(channel_readout):
    channel_readout.app.array = None
    channel_readout._poll()
    assert channel_readout.channels == ""

@pytest.mark.asyncio(loop_scope="module")
async def test_header_counts_rows_on_screen(channel_readout):
    channel_readout.app.array = SimpleNamespace(
        members=[SimpleNamespace(current_channel=6)],
        access_points={"old": object()},
        clients={"gone": object()},
    )
    app = channel_readout.app
    app._view_mode = "aps"
    app._row_states = {
        "aa": SimpleNamespace(clients=2),
        "bb": SimpleNamespace(clients=0),
    }
    try:
        channel_readout._poll()
        assert channel_readout.channels == "APS: 2  STA: 2  |  CH:  6  |  "
    finally:
        for name in ("_view_mode", "_row_states"):
            if hasattr(app, name):
                delattr(app, name)

