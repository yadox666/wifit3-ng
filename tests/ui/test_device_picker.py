"""Splash card list stays one line per adapter, and the band control is part of that line."""
import pytest
from textual.widgets import Checkbox

from wifit3.models.device_id import DeviceID
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.device_picker import default_scan_bands
from wifit3.ui.screens.splash import SplashView


def test_dual_band_card_defaults_to_the_uncovered_band(monkeypatch):
    only_24 = DeviceID(1, 1, "ONLY24", bus=1, address=1)
    dual = DeviceID(2, 2, "DUAL", bus=1, address=2)
    only_5 = DeviceID(3, 3, "ONLY5", bus=1, address=3)
    other_dual = DeviceID(4, 4, "DUAL2", bus=1, address=4)
    bands = {
        (1, 1): frozenset({"2g"}),
        (2, 2): frozenset({"2g", "5g"}),
        (3, 3): frozenset({"5g"}),
        (4, 4): frozenset({"2g", "5g"}),
    }
    monkeypatch.setattr(
        "wifit3.ui.screens.device_picker.hardware_scan_bands",
        lambda vid, pid: bands[(vid, pid)],
    )

    assert default_scan_bands([only_24, dual]) == {dual.instance_key: "5g"}
    assert default_scan_bands([only_5, dual]) == {dual.instance_key: "2g"}
    assert default_scan_bands([only_24, only_5, dual]) == {}
    assert default_scan_bands([dual, other_dual]) == {}
    assert default_scan_bands([dual]) == {}


def _cards():
    return [
        DeviceID(0x0BDA, 0x8813, "RTL8814AU", product_name="AWUS1900", bus=1, address=2),
        DeviceID(
            0x0CF3, 0x9271, "AR9271",
            product_name="AWUS036NHA / TL-WN722N v1", bus=1, address=4,
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_band_segments_are_one_line_and_clickable():
    app = WifiteApp()
    async with app.run_test(size=(100, 40)) as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)
        splash.render_devices(_cards())
        await pilot.pause()

        picker = splash.query_one("#device-picker")
        # Frame plus one line per card. No hint row, no padded buttons.
        assert picker.region.height == 4
        assert picker.region.width <= 80
        assert picker.query_one("#device-row-0").region.height == 1
        assert picker.query_one("#device-band-0").region.height == 1

        # RTL8814AU tunes both bands. AR9271 is 2.4 GHz only, so 5G is not offered.
        dual = picker.query_one("#device-band-0")
        only_24 = picker.query_one("#device-band-1")
        assert {opt.band_key for opt in dual.query(".band-opt")} == {"all", "2g", "5g"}
        assert [opt.band_key for opt in only_24.query(".band-opt")] == ["2g"]
        assert only_24.has_class("-fixed")
        # The 2.4-only card already covers 2.4 GHz, so the dual-band card starts on 5 GHz.
        assert dual.value == "5g"

        await pilot.click("#device-band-0 .band-5g")
        await pilot.pause()
        plan = picker.collect_band_plan()
        rtl, ar9271 = _cards()
        assert plan[rtl.instance_key] == "5g"
        assert plan[ar9271.instance_key] == "all"
        assert picker.highlighted == 0

        splash.query_one("#device-chk-0", Checkbox).focus()
        await pilot.press("left")
        await pilot.pause()
        assert picker.collect_band_plan()[rtl.instance_key] == "2g"

        picker.highlighted = 1
        splash.query_one("#device-chk-1", Checkbox).focus()
        await pilot.press("right")
        await pilot.pause()
        assert picker.collect_band_plan()[ar9271.instance_key] == "all"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_highlight_marker_only_appears_with_more_than_one_card():
    """A lone card carries no highlight cursor; the marker returns with a choice."""
    app = WifiteApp()
    async with app.run_test(size=(100, 40)) as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)

        splash.render_devices(_cards()[:1])
        await pilot.pause()
        assert not splash.query_one("#device-row-0").has_class("-focus")

        splash.render_devices(_cards())
        await pilot.pause()
        focused = [
            r for r in splash.query(".device-row") if r.has_class("-focus")
        ]
        assert len(focused) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_returning_to_splash_rebuilds_rows():
    """reset_for_reentry clears the list and paints the live cards in one turn."""
    app = WifiteApp()
    cards = _cards()
    async with app.run_test(size=(100, 40)) as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)
        splash.render_devices(cards)
        await pilot.pause()
        splash.render_devices(list(reversed(cards)))
        await pilot.pause()
        app.device_watch.present = lambda: cards
        splash.reset_for_reentry()
        await pilot.pause()

        rows = list(splash.query(".device-row"))
        assert len(rows) == 2
        assert splash.query_one("#device-row-0")
        assert splash.query_one("#device-chk-1", Checkbox).value is True
        assert splash.query_one("#device-picker").display is True
