"""Scanner table layout and dynamic SSID sizing."""
import pytest
from textual.app import App, ComposeResult
from textual.widgets.data_table import ColumnKey

from wifit3.models import AccessPoint
from wifit3.persist.vault import Vault
from wifit3.ui.screens.scanner import ScannerView, _APScanTable


class _SsidTableApp(App):
    def compose(self) -> ComposeResult:
        table = _APScanTable(id="ssid_table")
        table.add_column("SSID  ", key="ssid")
        table.add_column("CH  ", key="channel")
        yield table


@pytest.mark.asyncio
async def test_ap_scan_table_ssid_column_clamps_to_min_width():
    app = _SsidTableApp()
    async with app.run_test() as pilot:
        table = app.query_one("#ssid_table", _APScanTable)
        col = table.columns[ColumnKey("ssid")]
        assert col.content_width == _APScanTable.SSID_MIN_WIDTH

        table.add_row("Net1", "1", key="r1")
        await pilot.pause(0)
        assert col.content_width == _APScanTable.SSID_MIN_WIDTH

        table.update_cell("r1", "ssid", "A", update_width=True)
        await pilot.pause(0)
        assert col.content_width == _APScanTable.SSID_MIN_WIDTH


@pytest.mark.asyncio
async def test_ap_scan_table_ssid_column_expands_to_long_ssid():
    app = _SsidTableApp()
    async with app.run_test() as pilot:
        table = app.query_one("#ssid_table", _APScanTable)
        col = table.columns[ColumnKey("ssid")]

        long_ssid = "Super Long Test Access Point 30"
        table.add_row(long_ssid, "6", key="r2")
        await pilot.pause(0)
        assert col.content_width == len(long_ssid)


class _FakeDeviceManager:
    def __init__(self, aps):
        self.access_points = {ap.bssid: ap for ap in aps}
        self.clients = {}
        self.forged_macs = set()
        self.supported_channels = [1, 6, 11]
        self.members = []

    def get_access_points(self, include_eviltwin: bool = True):
        return list(self.access_points.values())

    async def start_hopping(self, *a, **k):
        pass

    async def stop_hopping(self):
        pass


class _ScannerHostApp(App):
    def __init__(self, array):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.vault = Vault()
    def on_mount(self):
        self.push_screen(ScannerView())


@pytest.mark.asyncio
async def test_scanner_view_ssid_width_decloaks_and_caps():
    ap_hidden = AccessPoint(bssid="00:11:22:33:44:01", ssid=None)
    ap_hidden.signal_by_card = {"card0": -50}

    fake_mgr = _FakeDeviceManager([ap_hidden])
    app = _ScannerHostApp(fake_mgr)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        assert isinstance(scanner, ScannerView)
        table = scanner.query_one("#ap-table", _APScanTable)
        col = table.columns[ColumnKey("ssid")]

        scanner.refresh_table()
        await pilot.pause(0)
        assert col.content_width == _APScanTable.SSID_MIN_WIDTH

        ap_hidden.ssid = "Super Long Test Access Point 30"
        scanner.refresh_table()
        await pilot.pause(0)
        assert col.content_width == len(ap_hidden.ssid) + 2  # plain target-marker slot

        ap_huge = AccessPoint(bssid="00:11:22:33:44:02", ssid="A" * 50)
        ap_huge.signal_by_card = {"card0": -40}
        fake_mgr.access_points[ap_huge.bssid] = ap_huge
        scanner.refresh_table()
        await pilot.pause(0)
        assert col.content_width == ScannerView._SSID_CELL_MAX + 2


@pytest.mark.asyncio
async def test_ap_scan_table_bssid_column_clamps_after_wide_cell():
    app = _SsidTableApp()
    async with app.run_test() as pilot:
        table = app.query_one("#ssid_table", _APScanTable)
        table.add_column("BSSID  ", key="bssid", width=_APScanTable.BSSID_COL_WIDTH)
        col = table.columns[ColumnKey("bssid")]
        long_key = "infrastructure:movistar-wifi6-a250-extra-padding"
        table.add_row("SSID", long_key, key="group")
        table.update_cell("group", "bssid", long_key, update_width=True)
        await pilot.pause(0)
        assert col.content_width <= _APScanTable.BSSID_COL_WIDTH
