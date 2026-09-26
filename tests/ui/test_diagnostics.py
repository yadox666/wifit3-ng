import pytest
from textual.widgets import DataTable

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
        assert "0 active adapters" in app.screen.query_one("#diagnostics-summary").render().plain


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_diagnostics_modal_includes_active_bluetooth_scanner():
    app = WifiteApp()
    app.bluetooth_manager._scanner = object()
    app.bluetooth_manager.scan_started_at = 1.0
    app.bluetooth_manager.last_advertisement_at = 2.0
    app.bluetooth_manager.received_advertisements = 7

    async with app.run_test() as pilot:
        app.action_diagnostics()
        await pilot.pause(0)
        table = app.screen.query_one("#diagnostics-table", DataTable)
        assert table.row_count == 1
        row = table.get_row("bluetooth")
        assert row[0] == "System Bluetooth"
        assert row[2] == "BLE"
        assert row[4].plain == "7"
        assert "1 active adapter" in app.screen.query_one("#diagnostics-summary").render().plain
