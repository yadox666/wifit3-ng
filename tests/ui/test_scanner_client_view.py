import pytest
from textual.app import App
from textual.widgets import DataTable

from wifit3.models import AccessPoint, Client
from wifit3.persist.targets import TargetStore
from wifit3.persist.vault import Vault
from wifit3.ui.screens.filter import ScanFilter
from wifit3.ui.screens.scanner import ScannerView


class _Array:
    def __init__(self, ap, clients):
        self.access_points = {ap.bssid: ap}
        self.clients = {client.mac: client for client in clients}
        self.forged_macs = set()
        self.supported_channels = [1, 6, 11]
        self.members = []

    def get_access_points(self, include_eviltwin=True):
        return list(self.access_points.values())

    async def start_hopping(self, *args, **kwargs):
        pass

    async def stop_hopping(self):
        pass


class _Host(App):
    def __init__(self, array):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.vault = Vault()

    def persist_config(self):
        pass

    def on_mount(self):
        self.push_screen(ScannerView())


def _plain(value):
    return value.plain if hasattr(value, "plain") else str(value)


@pytest.mark.asyncio
async def test_scanner_switches_between_ap_and_client_tables():
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    ap.signal_by_card = {"card0": -40}
    connected = Client(
        mac="18:7f:88:aa:bb:cc", bssid=ap.bssid, packets=14,
        probed_ssids={"CoffeeShop", "Home"},
    )
    connected.signal_by_card = {"card0": -48}
    roaming = Client(
        mac="02:00:00:00:00:01", packets=3, probed_ssids={"Airport"},
    )
    roaming.signal_by_card = {"card0": -70}

    app = _Host(_Array(ap, [connected, roaming]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner.refresh_table()
        assert table.row_count == 1
        assert _plain(table.get_cell(ap.bssid, "last_seen")) == "now / 30s"

        scanner.action_toggle_pause()
        ap.signal_by_card["card0"] = -20
        scanner.refresh_table()
        assert _plain(table.get_cell(ap.bssid, "signal")) == "-40 dBm"
        scanner.action_toggle_pause()
        assert _plain(table.get_cell(ap.bssid, "signal")) == "-20 dBm"

        scanner.action_toggle_view()
        await pilot.pause(0)
        assert scanner._view_mode == "clients"
        assert [key.value for key in table.columns] == [
            "ssid", "client", "signal", "packets", "last_seen", "manufacturer", "probes",
        ]
        assert table.row_count == 2
        assert _plain(table.get_cell(connected.mac, "manufacturer")) == "Ring"
        assert _plain(table.get_cell(connected.mac, "ssid")) == f"Office  ·  {ap.bssid}"
        assert _plain(table.get_cell(connected.mac, "probes")) == "CoffeeShop  ·  Home"
        assert _plain(table.get_cell(connected.mac, "last_seen")) == "now"
        assert _plain(table.get_cell(roaming.mac, "ssid")) == "‹unassociated›"
        assert _plain(table.get_cell(roaming.mac, "client")).startswith("~ ")

        scanner._scan_filter = ScanFilter(association="unassociated")
        scanner.refresh_table()
        assert table.row_count == 1
        assert roaming.mac in scanner._client_cache

        scanner._scan_filter = ScanFilter(text="coffee")
        scanner.refresh_table()
        assert table.row_count == 1
        assert connected.mac in scanner._client_cache

        scanner._scan_filter = ScanFilter()
        scanner.action_toggle_view()
        await pilot.pause(0)
        assert scanner._view_mode == "aps"
        assert table.row_count == 1
        assert ap.bssid in scanner.ap_cache


@pytest.mark.asyncio
async def test_saved_targets_mark_only_ap_ssid_and_full_client_row_red(tmp_path):
    ap = AccessPoint(
        bssid="00:03:93:11:22:33", ssid="Office", channel=6, wps=True,
    )
    client = Client(mac="18:7f:88:aa:bb:cc", bssid=ap.bssid)
    app = _Host(_Array(ap, [client]))
    app.target_store = TargetStore(tmp_path / "targets.json")
    app.target_store.upsert(
        alias="Router", medium="wifi", kind="ap",
        identifier=ap.bssid, details={},
    )
    app.target_store.upsert(
        alias="Phone", medium="wifi", kind="client",
        identifier=client.mac, details={},
    )

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner._ssid_chips_markup = (
            lambda _ap: "[green]✓HS[/green] [magenta]✓WPS[/magenta]"
        )
        scanner._forget_row(ap.bssid, drop_from_array=False)
        scanner.refresh_table()
        ap_cell = table.get_cell(ap.bssid, "ssid")
        assert ap_cell.plain.startswith("! ")
        assert ap_cell.justify == "right"
        red_spans = [
            span for span in ap_cell.spans if "red" in str(span.style)
        ]
        for badge in ("✓HS", "✓WPS"):
            start = ap_cell.plain.index(badge)
            end = start + len(badge)
            assert not any(span.start < end and span.end > start for span in red_spans)
        ssid_start = ap_cell.plain.index(ap.ssid)
        assert any(
            span.start <= ssid_start and span.end >= ssid_start + len(ap.ssid)
            for span in red_spans
        )
        for column in ("channel", "wps", "encryption"):
            cell = table.get_cell(ap.bssid, column)
            assert not any("red" in str(span.style) for span in cell.spans)

        scanner.action_toggle_view()
        await pilot.pause(0)
        client_cell = table.get_cell(client.mac, "ssid")
        assert client_cell.plain.startswith("! ")
        assert any("red" in str(span.style) for span in client_cell.spans)


@pytest.mark.asyncio
async def test_same_ssid_aps_collapse_into_expandable_infrastructure():
    first = AccessPoint(
        bssid="00:03:93:11:22:33", ssid="Hotel WiFi", channel=1,
    )
    second = AccessPoint(
        bssid="00:03:93:11:22:44", ssid="Hotel WiFi", channel=6,
    )
    first.signal_by_card = {"card0": -55}
    second.signal_by_card = {"card0": -40}
    array = _Array(first, [])
    array.access_points[second.bssid] = second
    app = _Host(array)

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner.refresh_table()

        assert table.row_count == 1
        grouped = table.get_row_at(0)
        assert grouped[0].plain == "▸ Hotel WiFi · 2 APs"
        assert grouped[1].plain == "1,6"
        assert grouped[2].plain == "-40 dBm"

        await pilot.press("enter")
        await pilot.pause(0)
        assert table.row_count == 2
        assert all(
            table.get_row_at(index)[0].plain.startswith("└ ")
            for index in range(2)
        )

        scanner.action_toggle_infrastructure()
        await pilot.pause(0)
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_observed_weak_enterprise_method_is_visible_in_ap_table():
    ap = AccessPoint(
        bssid="00:03:93:11:22:33",
        ssid="Corporate",
        channel=6,
        encryption="WPA2",
        akms=["EAP"],
        pairwise_ciphers=["CCMP"],
        pmf_capable=True,
    )
    ap.enterprise.server_eap_types.add(17)
    app = _Host(_Array(ap, []))

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        encryption = scanner.query_one("#ap-table", DataTable).get_cell(
            ap.bssid, "encryption",
        )
        assert "!WEAK" in encryption.plain
