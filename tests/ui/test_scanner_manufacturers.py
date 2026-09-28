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


def _plain(cell) -> str:
    return cell.plain if hasattr(cell, "plain") else str(cell)


@pytest.mark.asyncio
async def test_scanner_table_uses_vendor_id_and_client_manufacturers():
    ap = AccessPoint(bssid="00:11:22:33:44:55", ssid="Lab")
    ap.signal_by_card = {"card0": -40}
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
        assert _plain(table.get_cell(ap.bssid, "stations")) == "Zebra, Apple, Apple"
        assert scanner._row_states[ap.bssid].clients == 4
