"""AP identity and associated-client manufacturer columns."""
import pytest
from textual.app import App

from wifit3.id import oui_db
from wifit3.models import AccessPoint, Client
from wifit3.persist.vault import Vault
from wifit3.ui.screens.scanner import ScannerView


@pytest.fixture(autouse=True)
def _restore_oui():
    prior = dict(oui_db.mapping())
    yield
    oui_db.install(prior)


class _FakeArray:
    def __init__(self, aps, clients):
        self.access_points = {ap.bssid: ap for ap in aps}
        self.clients = {c.mac: c for c in clients}
        self.forged_macs = set()
        self.supported_channels = [1, 6, 11]
        self.members = []

    def get_access_points(self, include_eviltwin: bool = True):
        return list(self.access_points.values())

    async def start_hopping(self, *a, **k):
        pass

    async def stop_hopping(self):
        pass


class _Host(App):
    def __init__(self, array):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.vault = Vault()

    def on_mount(self):
        self.push_screen(ScannerView())

    def sdr_jam_available(self) -> bool:
        return False


def _plain(cell) -> str:
    return cell.plain if hasattr(cell, "plain") else str(cell)


@pytest.mark.asyncio
async def test_scanner_table_uses_vendor_id_and_client_manufacturers():
    ap = AccessPoint(bssid="00:11:22:33:44:55", ssid="Lab")
    ap.signal_by_card = {"card0": -40}
    ap.capabilities.phy_modes = {"802.11ax"}
    ap.capabilities.channel_widths_mhz = {20, 40, 80}
    ap.capabilities.max_spatial_streams = 2
    ap.capabilities.supported_rates_mbps = {6.0, 12.0, 24.0}
    ap.capabilities.capability_flags = {"ESS"}
    ap.capabilities.vendor_ouis = {"00:50:F2"}
    clients = [
        Client(mac="11:22:33:00:00:01", bssid=ap.bssid),
        Client(mac="aa:bb:cc:00:00:03", bssid=ap.bssid),
        Client(mac="aa:bb:cc:00:00:02", bssid=ap.bssid),
        Client(mac="02:00:00:00:00:01", bssid=ap.bssid),
    ]
    array = _FakeArray([ap], clients)
    array.forged_macs.add("aa:bb:cc:00:00:09")
    array.clients["aa:bb:cc:00:00:09"] = Client(mac="aa:bb:cc:00:00:09", bssid=ap.bssid)

    app = _Host(array)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        assert isinstance(scanner, ScannerView)
        scanner.refresh_table()
        await pilot.pause(0)

        oui_db.install({
            "001122": "Acme",
            "112233": "Zebra",
            "AABBCC": "Apple",
        })
        scanner.refresh_table()
        await pilot.pause(0)

        table = scanner.query_one("#ap-table")
        assert "mfr" not in table.columns
        assert _plain(table.get_cell(ap.bssid, "identity")) == "Acme"
        column_keys = [key.value for key in table.columns]
        assert column_keys.index("identity") + 1 == column_keys.index("catalog_class")
        assert column_keys.index("catalog_class") + 1 == (
            column_keys.index("catalog_family")
        )
        assert column_keys.index("catalog_family") + 1 == (
            column_keys.index("clients")
        )
        assert column_keys.index("clients") + 1 == (
            column_keys.index("stations")
        )
        assert column_keys.index("last_seen") + 1 == (
            column_keys.index("location")
        )
        assert column_keys.index("ssid") + 1 == column_keys.index("captures")
        assert column_keys.index("captures") + 1 == column_keys.index("channel")
        assert column_keys.index("signal") + 1 == column_keys.index("country")
        assert column_keys.index("bssid") + 1 == column_keys.index("identity")
        assert _plain(table.get_cell(ap.bssid, "catalog_class")) == "·"
        assert _plain(table.get_cell(ap.bssid, "catalog_family")) == "·"
        assert _plain(table.get_cell(ap.bssid, "stations")) == "Zebra, Apple, Apple"
        assert scanner._row_states[ap.bssid].clients == 4
