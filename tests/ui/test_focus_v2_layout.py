"""Geometry contract for the Focus v2 shell: the layout half we can verify
without a human eyeball (placement / no-overlap / width-cap / band-height ladder),
plus that the green-LED breathe actually changes the art. Aesthetics ("does it
look good") stay the human's call, fed by the exported SVGs.

Sizes are pinned headless via ``run_test(size=...)``: no real terminal."""
import types

import pytest_asyncio
from textual.app import App

from wifit3.models import AccessPoint
from wifit3.campaigns.pin import WpsCampaign
from wifit3.ui import focus_model as fm
from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.focus_v2.art import BreathingArt, art_size, breathe
from wifit3.ui.screens.focus_v2.screen import _client_connection_segments

_TOPBAR_H = 3
_CHROME_H = 2          # Header (1 row) + Footer (1 row)
_CENTER_MAX, _CENTER_MIN, _BOTTOM_MIN = 13, 7, 6


class _Host(App):
    """Minimal host: push the v2 screen straight in (no device manager)."""
    target_ap = None
    array = None

    def __init__(self) -> None:
        super().__init__()
        self.vault_context = None

    def action_toggle_vault(self, access_point=None) -> None:
        self.vault_context = access_point

    def on_mount(self) -> None:
        self.push_screen(FocusViewV2())


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def layout_host():
    app = _Host()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        yield app.screen


async def test_layout_geometry():
    app = _Host()
    async with app.run_test(size=(80, 24)) as pilot:
        for w, h in [(80, 24), (80, 30), (100, 35), (120, 40)]:
            await pilot.resize_terminal(w, h)
            await pilot.pause(0)
            scr = app.screen

            def reg(sel):
                return scr.query_one(sel).region

            card, dash, router = reg("#card"), reg("#dashboard"), reg("#router")
            # Card column is 20 cells (one dongle) or 40 (two); dashboard fills the middle.
            pad = max(0, round((w - 80) * 0.4))
            assert card.width in (20, 40) and router.width == 20
            assert card.x == pad and card.right == dash.x
            assert dash.right == router.x and router.right == w - pad
            assert dash.width == w - 2 * pad - card.width - router.width

            log, clients = reg("#log"), reg("#clients")
            # Clients is a fixed exact-fit column; log takes the rest; no overlap.
            assert clients.width == 54
            assert log.x == 0 and log.right == clients.x and clients.right == w

            header, footer = reg("Header"), reg("Footer")
            top, mid, bot = reg("#topbar"), reg("#mid"), reg("#bottom")
            assert header.y == 0 and header.height == 1
            assert footer.bottom == h and footer.height == 1
            assert top.y == header.bottom and top.height == _TOPBAR_H
            assert top.bottom == mid.y and mid.bottom == bot.y and bot.bottom == footer.y
            avail = h - _TOPBAR_H - _CHROME_H
            expected_center = min(_CENTER_MAX, max(_CENTER_MIN, avail - _BOTTOM_MIN))
            assert mid.height == expected_center
            assert bot.height == avail - expected_center


async def test_focus_vault_uses_current_ap_as_psk_context():
    app = _Host()
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="Focused Network",
    )

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen._target_ap = ap
        app.screen.action_open_vault()

        assert app.vault_context is ap


async def test_client_connector_is_overlaid_only_while_clients_exist():
    app = _Host()
    async with app.run_test(size=(120, 40)):
        screen = app.screen
        screen._target_ap = types.SimpleNamespace()
        original = screen._live_client_list
        screen._live_client_list = lambda: [types.SimpleNamespace(is_fake=False)]
        try:
            screen._refresh_client_connector()
            horizontal = screen.query_one("#client-connector-horizontal")
            vertical = screen.query_one("#client-connector-vertical")
            junction = screen.query_one("#client-connector-junction")
            assert horizontal.display is True
            assert horizontal.styles.width.value > 1
            assert vertical.display is True
            assert vertical.styles.width.value == 1
            assert junction.display is True
        finally:
            screen._live_client_list = original
            screen._refresh_client_connector()
        assert all(piece.display is False for piece in (horizontal, vertical, junction))


async def test_router_has_no_inline_wps_probe_button(layout_host):
    assert not list(layout_host.query("#ap-probe"))


def test_dashboard_rows_and_rate_vs_count():
    # WPA family: beacon + data + eapol + inject + deauth.
    rows = fm.dashboard_rows(types.SimpleNamespace(encryption="WPA2"))
    assert len(rows) == 5
    as_rate = {r.key: r.as_rate for r in rows}
    # eapol reads as a recent count (a handshake is ~4 frames); the rest /s.
    assert as_rate["eapol"] is False
    assert all(as_rate[k] for k in ("beacon", "data", "inject", "deauth"))


def test_wps_info_hotkey_is_available_without_footer_duplication():
    screen = FocusViewV2()
    ap = AccessPoint(bssid="00:11:22:33:44:55", wps=True)
    screen._target_ap = ap

    assert screen.check_action("wps_info", ()) is True
    ap.wps = False
    assert screen.check_action("wps_info", ()) is None
    binding = next(
        binding for binding in FocusViewV2.BINDINGS
        if binding.key == "i" and binding.description == "WPS Info"
    )
    assert binding.show is False
    assert WpsCampaign.hotkey == ("n", "WPS PIN")


def test_breathe_changes_green_leds():
    dark = breathe("focus-card.ans", 0.0)
    bright = breathe("focus-card.ans", 0.5)
    # Same glyphs + geometry: only the LED cells' colour changes.
    assert dark.plain == bright.plain
    assert art_size("focus-card.ans") == (20, 10)

    def led_greens(text):
        out = set()
        for span in text.spans:
            for col in (getattr(span.style, "color", None), getattr(span.style, "bgcolor", None)):
                trip = col.triplet if col is not None else None
                if trip is not None and trip.red == 0 and trip.blue == 0:
                    out.add(trip.green)
        return out

    # The bright frame must push the LED green above the dark (0,128,0) baseline.
    assert max(led_greens(bright)) > max(led_greens(dark))


def test_art_pure_black_is_transparent():
    """The .ans negative space is pure black; the loader must drop it so the art
    blends into the theme surface instead of painting a black rectangle."""
    from wifit3.ui.ansi_art import is_black
    from wifit3.ui.screens.focus_v2.art import _transparent

    for name in ("focus-card.ans", "focus-ap.ans"):
        for span in _transparent(name).spans:
            assert not is_black(span.style.color)
            assert not is_black(span.style.bgcolor)


def test_client_connector_points_both_ways():
    right_h, right_v, right_join = _client_connection_segments(10, 16, 4)
    left_h, left_v, left_join = _client_connection_segments(16, 10, 4)

    assert "━━━━━━┓" in right_h
    assert "┃\n┃" in right_v
    assert "┴" in right_join
    assert "┏━━━━━━" in left_h
    assert "┃\n┃" in left_v
    assert "┴" in left_join


def test_flicker_spikes_above_the_breathe_band():
    """A packet flicker must be unmistakably brighter than the dim idle breathe,
    so activity reads as a spike, not a slightly-brighter glow."""
    from wifit3.ui.screens.focus_v2.art import (
        _BREATHE_HI, _BREATHE_LO, _FLICKER_GREEN, _breathe_green,
    )
    assert _breathe_green(0.0) == _BREATHE_LO
    assert _breathe_green(0.5) == _BREATHE_HI
    assert _FLICKER_GREEN > _BREATHE_HI


def test_flicker_state_machine_caps_rate_then_decays():
    """pulse() lights ON for one frame, then a refractory forces it dim; a pulse
    arriving mid-refractory only arms the *next* blink (no strobe). With no more
    pulses the LED settles back to idle (breathe only)."""

    art = BreathingArt("focus-card.ans")          # not mounted, drive it by hand
    assert art._blink == "idle"
    art.pulse()
    assert art._blink == "on"                     # bright this frame
    art._advance_blink()
    assert art._blink == "refractory"             # forced dim …
    art.pulse()                                   # … a fresh pulse can't strobe it
    assert art._blink == "refractory"
    art._advance_blink()
    art._advance_blink()                          # refractory done → pending → on
    assert art._blink == "on"
    # No further pulses → on → refractory → idle.
    art._advance_blink()
    assert art._blink == "refractory"
    art._advance_blink()
    art._advance_blink()
    assert art._blink == "idle"
