import time
from types import SimpleNamespace

import pytest
from textual.widgets import DataTable, Link

from wifit3.gps import GpsStatus
from wifit3.models import LocationFix
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.diagnostics import AdapterDiagnosticsModal


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_modal_handles_no_active_adapters():
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        assert isinstance(app.screen, AdapterDiagnosticsModal)
        assert app.screen.query_one("#diagnostics-table", DataTable).row_count == 0
        gps_table = app.screen.query_one("#gps-table", DataTable)
        assert gps_table.row_count == 1
        assert gps_table.get_row("gps")[0] == "Auto-detect"
        assert app.screen.query_one("#gps-map-link", Link).disabled is True
        assert "0 active adapters" in app.screen.query_one("#diagnostics-summary").render().plain


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_modal_includes_active_bluetooth_scanner():
    app = WifiteApp()
    app.bluetooth_manager._scanner = object()
    app.bluetooth_manager.scan_started_at = 1.0
    app.bluetooth_manager.last_advertisement_at = 2.0
    app.bluetooth_manager.received_advertisements = 7
    app.bluetooth_manager.observations_by_radio["BLE"] = 7
    app.bluetooth_manager.last_observation_by_radio["BLE"] = 2.0

    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        table = app.screen.query_one("#diagnostics-table", DataTable)
        assert table.row_count == 1
        row = table.get_row("bluetooth-ble")
        assert row[0] == "System Bluetooth BLE"
        assert row[2] == "BLE"
        assert row[4].plain == "7"
        assert "1 active adapter" in app.screen.query_one("#diagnostics-summary").render().plain


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_separates_ble_and_classic_stats():
    app = WifiteApp()
    controller = SimpleNamespace(
        chipset="RTL8761B",
        supports_le=True,
        supports_classic=True,
    )
    app.bluetooth_manager._usb_scanner = SimpleNamespace(
        controller=controller,
        is_scanning=True,
    )
    app.bluetooth_manager.scan_started_at = time.time()
    app.bluetooth_manager.observations_by_radio.update(BLE=12, BT=5)
    app.bluetooth_manager.last_observation_by_radio.update(
        BLE=time.time(),
        BT=time.time(),
    )
    app.bluetooth_manager._devices = {
        "ble": SimpleNamespace(radio_types=("BLE",)),
        "classic": SimpleNamespace(radio_types=("BT",)),
        "dual": SimpleNamespace(radio_types=("BLE", "BT")),
    }

    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        table = app.screen.query_one("#diagnostics-table", DataTable)
        assert table.row_count == 2
        ble = table.get_row("bluetooth-ble")
        classic = table.get_row("bluetooth-bt")
        assert ble[0] == "USB Bluetooth BLE"
        assert ble[2] == "BLE"
        assert ble[3].plain == "2"
        assert ble[4].plain == "12"
        assert classic[0] == "USB Bluetooth Classic"
        assert classic[2] == "BT"
        assert classic[3].plain == "2"
        assert classic[4].plain == "5"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_modal_shows_gps_fix():
    app = WifiteApp()
    app.gps_manager.status = GpsStatus("/dev/cu.usbserial-test", 4800)
    app.gps_manager.latest_fix = LocationFix(
        latitude=28.129365,
        longitude=-15.442715,
        altitude_m=9.4,
        accuracy_m=9.5,
        observed_at=time.time(),
        source="nmea:gga",
        satellites=4,
        fix_quality=1,
    )

    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        row = app.screen.query_one("#gps-table", DataTable).get_row("gps")
        assert row[0] == "/dev/cu.usbserial-test"
        assert row[1].plain == "4800"
        assert row[2] == "28.129365, -15.442715"
        assert row[3].plain == "4"
        assert row[4].plain == "9.5 m"
        assert row[6].plain == "FIX"
        link = app.screen.query_one("#gps-map-link", Link)
        assert link.disabled is False
        assert link.url.startswith("https://www.google.com/maps/place/")
        assert "/@28.1293650,-15.4427150," in link.url
        assert "place/28.1293650%2C-15.4427150/@" in link.url


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_marks_fix_below_required_accuracy():
    app = WifiteApp()
    app.gps_manager.status = GpsStatus("COM7", 9600)
    app.gps_manager.latest_fix = LocationFix(
        51.0, 0.0, None, 25.0, time.time(), "nmea:gga", satellites=3,
    )

    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        row = app.screen.query_one("#gps-table", DataTable).get_row("gps")
        assert row[6].plain == "LOW ACCURACY"
