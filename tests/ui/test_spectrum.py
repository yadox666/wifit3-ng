import pytest
from textual.widgets import DataTable
from textual.widgets.data_table import ColumnKey

from wifit3.sdr.sweep import HackRfSweepError, SpectrumPoint
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.spectrum import (
    RF_CHANNELS,
    RfSpectrumView,
    SPANS,
    SpectrumPlot,
    ble_channel_frequency_mhz,
    bluetooth_channel_frequency_mhz,
    channels_in_span,
    selected_span,
    spectrum_bin_width_hz,
    wifi_channel_frequency_mhz,
)


def test_wifi_channel_frequency_centers_cover_supported_bands():
    assert wifi_channel_frequency_mhz("2g", 1) == 2412
    assert wifi_channel_frequency_mhz("2g", 14) == 2484
    assert wifi_channel_frequency_mhz("5g", 36) == 5180
    assert wifi_channel_frequency_mhz("6g", 1) == 5955


def test_24_ghz_scope_includes_wifi_and_bluetooth():
    channels = channels_in_span(SPANS["2g"])

    assert any(channel.technology == "Wi-Fi 2.4" for channel in channels)
    assert {channel.label for channel in channels
            if channel.technology == "BT Classic"} == {
        str(channel) for channel in range(79)
    }
    assert {channel.label for channel in channels if channel.technology == "BLE ADV"} == {
        "37", "38", "39",
    }
    assert {channel.label for channel in channels if channel.technology == "BLE DATA"} == {
        str(channel) for channel in range(37)
    }
    assert not any(channel.technology == "Wi-Fi 5" for channel in channels)


def test_bluetooth_and_ble_channel_center_frequencies():
    assert bluetooth_channel_frequency_mhz(0) == 2402
    assert bluetooth_channel_frequency_mhz(78) == 2480
    assert ble_channel_frequency_mhz(37) == 2402
    assert ble_channel_frequency_mhz(0) == 2404
    assert ble_channel_frequency_mhz(10) == 2424
    assert ble_channel_frequency_mhz(38) == 2426
    assert ble_channel_frequency_mhz(11) == 2428
    assert ble_channel_frequency_mhz(36) == 2478
    assert ble_channel_frequency_mhz(39) == 2480
    assert len([channel for channel in RF_CHANNELS
                if channel.technology == "BT Classic"]) == 79
    assert len([channel for channel in RF_CHANNELS
                if channel.technology.startswith("BLE")]) == 40


def test_specific_channel_centers_sweep_without_exceeding_hackrf_limit():
    channel_36 = selected_span("5g", "5g:36")
    partial_6g_channel_9 = selected_span("6g", "6g:9")

    assert (channel_36.start_mhz, channel_36.stop_mhz) == (5170, 5190)
    assert (partial_6g_channel_9.start_mhz, partial_6g_channel_9.stop_mhz) == (
        5985,
        6000,
    )


def test_fft_resolution_adapts_to_the_selected_span():
    assert spectrum_bin_width_hz(selected_span("2g", "2g:1")) == 100_000
    assert spectrum_bin_width_hz(SPANS["2g"]) == 250_000
    assert spectrum_bin_width_hz(SPANS["5g"]) == 500_000
    assert spectrum_bin_width_hz(SPANS["all"]) == 1_000_000


def test_five_ghz_ruler_marks_every_wifi_channel_across_two_rows():
    plot = SpectrumPlot()
    channels = channels_in_span(SPANS["5g"])
    plot.reset(SPANS["5g"], channels)

    first_row, second_row = plot._channel_axes(160)
    ruler = first_row + second_row

    for channel in channels:
        if channel.technology == "Wi-Fi 5":
            assert f"│{channel.label}" in ruler
    assert "5 GHz" in plot._band_axis(160)


def test_selected_channel_overlay_marks_passband_edges_and_center():
    channel = next(channel for channel in channels_in_span(SPANS["5g"])
                   if channel.key == "5g:36")
    span = selected_span("5g", channel.key)
    plot = SpectrumPlot()
    plot.reset(span, channels_in_span(span), channel)

    assert plot._overlay_columns(101) == (0, 50, 100)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_spectrum_screen_surfaces_usb_open_error(monkeypatch):
    async def unavailable(_self, _start_mhz, _stop_mhz, **_kwargs):
        raise HackRfSweepError("USB access denied")

    monkeypatch.setattr(
        "wifit3.ui.screens.spectrum.HackRfSweep.start",
        unavailable,
    )
    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        app.push_screen("spectrum")
        await pilot.pause(0)
        screen = app.screen
        assert isinstance(screen, RfSpectrumView)

        screen.activate()
        await pilot.pause(0)

        assert "UNAVAILABLE" in screen.query_one("#spectrum-status").render().plain
        assert screen.query_one("#spectrum-plot").border_title == "LIVE RF POWER · dBFS"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_spectrum_screen_maps_samples_to_channel_occupation(monkeypatch):
    start_args = {}

    async def started(_self, start_mhz, stop_mhz, **kwargs):
        start_args.update(start_mhz=start_mhz, stop_mhz=stop_mhz, **kwargs)
        return None

    monkeypatch.setattr("wifit3.ui.screens.spectrum.HackRfSweep.start", started)
    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        app.push_screen("spectrum")
        await pilot.pause(0)
        screen = app.screen
        screen.activate()
        await pilot.pause(0)
        assert start_args == {
            "start_mhz": 2400,
            "stop_mhz": 2500,
            "bin_width_hz": 250_000,
            "lna_gain": 16,
            "vga_gain": 20,
        }
        screen._accept_points([
            SpectrumPoint(2_411_500_000, -80.0),
            SpectrumPoint(2_412_500_000, -58.0),
        ])
        screen._refresh_visuals()

        row = screen.query_one("#spectrum-table").get_row("2g:1")
        assert row[3].plain == "-58.0 dBFS"
        assert row[4].plain.endswith("100%")
        assert row[5].plain == "CONGESTED"
        assert "Wi-Fi 2.4 1" in screen.query_one("#spectrum-insights").render().plain
        assert "Strongest bin now" in screen.query_one("#stat-peak").render().plain
        assert "Background RF level" in screen.query_one("#stat-noise").render().plain
        assert "Highest activity" in screen.query_one("#stat-busiest").render().plain
        assert "Selected range sampled" in (
            screen.query_one("#stat-coverage").render().plain
        )

        screen._sweep._clip_ratio = 0.01
        screen._refresh_visuals()

        assert "OVERLOAD" in screen.query_one("#stat-peak").render().plain
        assert "reduce gain" in screen.query_one("#stat-peak").render().plain


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_touching_spectrum_header_selects_and_reverses_sort():
    app = WifiteApp()
    async with app.run_test(size=(130, 45)) as pilot:
        app.push_screen("spectrum")
        await pilot.pause(0)
        screen = app.screen
        table = screen.query_one("#spectrum-table", DataTable)
        column_key = ColumnKey("channel")
        event = DataTable.HeaderSelected(
            table,
            column_key,
            table.get_column_index(column_key),
            table.columns[column_key].label,
        )

        screen.sort_from_header(event)
        assert table.columns[column_key].label.plain == "CHANNEL ▲"

        screen.sort_from_header(event)
        assert table.columns[column_key].label.plain == "CHANNEL ▼"
