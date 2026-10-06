"""ScannerView sorting contract: real-time deterministic sorting, WPS hierarchy,
and tie-breaking.
"""
from typing import List, Optional
import pytest
from textual.app import App
from textual.widgets import DataTable
from textual.widgets.data_table import ColumnKey

from wifit3.models import AccessPoint, Client
from wifit3.persist.config import Config
from wifit3.persist.vault import Vault
from wifit3.ui.screens.scanner import ScannerView, _APScanTable, _ChannelReadout


@pytest.fixture(autouse=True)
def _zero_sort_delay(monkeypatch):
    monkeypatch.setattr(Config, "scanner_sort_delay", 0.0)


def _make_ap(
    bssid: str,
    ssid: Optional[str] = None,
    signal: int = -100,
    beacons: int = 0,
    wps: bool = False,
    wps_locked: bool = False,
) -> AccessPoint:
    ap = AccessPoint(
        bssid=bssid,
        ssid=ssid,
        beacons=beacons,
        wps=wps,
        wps_locked=wps_locked,
    )
    ap.signal_by_card = {"card0": signal}
    return ap


class _FakeIface:
    def __init__(self, supported: List[int]):
        self.supported_channels = supported
        self.current_channel = supported[0] if supported else 1
        self.chipset = "test"
        self.instance_key = ("test", id(self))
        self._is_hopping = True

    async def stop_hopping(self) -> None:
        self._is_hopping = False

    async def start_hopping(self, channels=None, interval=0.25) -> None:
        self._is_hopping = True


class _FakeArray:
    def __init__(self, aps: List[AccessPoint], supported: List[int]):
        self.access_points = {ap.bssid: ap for ap in aps}
        self.clients = {}
        self.forged_macs = set()
        self.supported_channels = supported
        self.members = [_FakeIface(supported)] if supported else []

    def get_access_points(self, include_eviltwin: bool = True) -> List[AccessPoint]:
        return list(self.access_points.values())

    async def start_hopping(
        self, channels=None, interval=0.25, member_channels=None,
    ) -> None:
        pass

    async def stop_hopping(self) -> None:
        pass


class _ScannerHost(App):
    def __init__(self, array: _FakeArray):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.vault = Vault()
        self.vault_context = None

    def persist_config(self) -> None:
        pass

    def action_toggle_vault(self, access_point=None) -> None:
        self.vault_context = access_point

    def sdr_jam_available(self) -> bool:
        return False

    def on_mount(self) -> None:
        self.push_screen(ScannerView())


@pytest.mark.asyncio
async def test_sort_change_shows_toast_and_header_status():
    app = _ScannerHost(_FakeArray([], [1, 6, 11]))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        scanner = app.screen
        toasts = []
        scanner.notify = lambda message, **kwargs: toasts.append(
            (kwargs.get("title"), message)
        )
        readout = scanner.query_one(_ChannelReadout)
        readout._poll()

        assert readout.channels.startswith("Sorted: POWER (>)")
        scanner.action_cycle_sort()
        assert readout.channels.startswith("Sorted: CC (>)")
        assert toasts[-1] == ("Sort changed", "Sorted by CC descending")

        scanner.action_toggle_sort_dir()
        assert readout.channels.startswith("Sorted: CC (<)")
        assert toasts[-1] == ("Sort changed", "Sorted by CC ascending")


@pytest.mark.asyncio
async def test_touching_wifi_header_selects_and_reverses_sort():
    app = _ScannerHost(_FakeArray([], [1, 6, 11]))

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        column_key = next(key for key in table.columns if key.value == "ssid")
        event = DataTable.HeaderSelected(
            table,
            column_key,
            table.get_column_index(column_key),
            table.columns[column_key].label,
        )

        scanner.sort_from_header(event)
        assert table.columns[column_key].label.plain == "▲ SSID"

        scanner.sort_from_header(event)
        assert table.columns[column_key].label.plain == "▼ SSID"


@pytest.mark.asyncio
async def test_sort_aps_short_circuits_when_order_unchanged():
    ap1 = _make_ap("aa:bb:cc:00:00:01", ssid="A", signal=-50)
    ap2 = _make_ap("aa:bb:cc:00:00:02", ssid="B", signal=-60)

    app = _ScannerHost(_FakeArray([ap1, ap2], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner._apply_sort(scroll_to_cursor=False)

        # Re-running sort when data has not moved returns False (no-op short circuit)
        order_changed = table.sort_aps("signal", lambda bssid, val: (0, scanner.ap_cache[bssid].signal), reverse=True)
        assert order_changed is False


@pytest.mark.asyncio
async def test_ap_scan_ends_with_unclipped_client_manufacturer():
    ap = _make_ap("aa:bb:cc:00:00:01", ssid="Visible AP", signal=-50)
    app = _ScannerHost(_FakeArray([ap], []))

    async with app.run_test() as pilot:
        await pilot.pause()
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner.refresh_table()

        keys = [key for key, _label in scanner._COLUMNS]
        assert keys[-1] == "stations"
        assert keys.index("bssid") < keys.index("stations")
        assert table.get_cell(ap.bssid, "bssid").plain == ap.bssid

        long_manufacturers = "Manufacturer One · Manufacturer Two · Manufacturer Three"
        scanner._station_labels[ap.bssid] = long_manufacturers
        assert scanner._render_cell(ap, "stations", False).plain == long_manufacturers


@pytest.mark.asyncio
async def test_sort_channel_ascending_breaks_ties_with_stronger_power():
    # Two APs on channel 6: one strong (-35 dBm), one weak (-80 dBm).
    # One AP on channel 1 (-50 dBm).
    # Sorting by channel ascending: channel 1 first, then channel 6.
    # On channel 6, the stronger AP (-35) must be above the weaker AP (-80).
    ap_ch1 = _make_ap("aa:bb:cc:00:00:01", ssid="Net1", signal=-50)
    ap_ch1.channel = 1
    ap_ch6_weak = _make_ap("aa:bb:cc:00:00:02", ssid="Net6Weak", signal=-80)
    ap_ch6_weak.channel = 6
    ap_ch6_strong = _make_ap("aa:bb:cc:00:00:03", ssid="Net6Strong", signal=-35)
    ap_ch6_strong.channel = 6

    app = _ScannerHost(_FakeArray([ap_ch6_weak, ap_ch1, ap_ch6_strong], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner._sort_idx = next(i for i, (col, _) in enumerate(scanner._COLUMNS) if col == "channel")
        scanner._sort_reverse = False  # Ascending

        scanner._apply_sort(scroll_to_cursor=False)

        ordered_keys = [r.value for r in list(table._row_locations)]
        assert ordered_keys == [
            "aa:bb:cc:00:00:01",  # Channel 1
            "aa:bb:cc:00:00:03",  # Channel 6 strong (-35)
            "aa:bb:cc:00:00:02",  # Channel 6 weak (-80)
        ]


@pytest.mark.asyncio
async def test_sort_ssid_ascending_sinks_hidden_networks():
    ap_b = _make_ap("aa:bb:cc:00:00:02", ssid="Bravo", signal=-50)
    ap_a = _make_ap("aa:bb:cc:00:00:01", ssid="Alpha", signal=-60)
    ap_hidden = _make_ap("aa:bb:cc:00:00:03", ssid=None, signal=-20)  # Strong but hidden

    app = _ScannerHost(_FakeArray([ap_b, ap_hidden, ap_a], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner._sort_idx = next(i for i, (col, _) in enumerate(scanner._COLUMNS) if col == "ssid")
        scanner._sort_reverse = False  # Ascending

        scanner._apply_sort(scroll_to_cursor=False)

        ordered_keys = [r.value for r in list(table._row_locations)]
        assert ordered_keys == [
            "aa:bb:cc:00:00:01",  # Alpha
            "aa:bb:cc:00:00:02",  # Bravo
            "aa:bb:cc:00:00:03",  # Hidden sinks to bottom despite strong signal
        ]


@pytest.mark.asyncio
async def test_selected_ap_bssid_follows_its_row_during_resort():
    ap1 = _make_ap("aa:bb:cc:00:00:01", ssid="AP1", signal=-40)
    ap2 = _make_ap("aa:bb:cc:00:00:02", ssid="AP2", signal=-60)

    app = _ScannerHost(_FakeArray([ap1, ap2], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner._sort_idx = next(i for i, (col, _) in enumerate(scanner._COLUMNS) if col == "signal")
        scanner._sort_reverse = True
        scanner.refresh_table()

        # Cursor starts on row 0 (ap1)
        assert table.cursor_coordinate.row == 0

        # Move cursor to ap2 (row 1)
        table.move_cursor(row=1, animate=False)
        assert table.cursor_coordinate.row == 1

        # Now ap2's signal jumps to -20 (stronger than ap1)
        ap2.signal_by_card["card0"] = -20
        scanner.refresh_table()

        # ap2 jumps to row 0 and the highlight follows the same selected BSSID.
        assert [r.value for r in list(table._row_locations)] == [
            "aa:bb:cc:00:00:02",
            "aa:bb:cc:00:00:01",
        ]
        assert table.cursor_coordinate.row == 0
        selected = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        assert selected == "aa:bb:cc:00:00:02"


@pytest.mark.asyncio
async def test_open_vault_carries_highlighted_ap_context():
    first = _make_ap("aa:bb:cc:00:00:01", ssid="First", signal=-40)
    selected = _make_ap("aa:bb:cc:00:00:02", ssid="Selected", signal=-60)
    app = _ScannerHost(_FakeArray([first, selected], []))

    async with app.run_test() as pilot:
        await pilot.pause()
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        table.move_cursor(row=1, animate=False)

        scanner.action_open_vault()

        assert app.vault_context is selected


@pytest.mark.asyncio
async def test_selected_client_mac_follows_its_row_during_resort():
    ap = _make_ap("aa:bb:cc:00:00:01", ssid="AP", signal=-40)
    first = Client(mac="10:00:00:00:00:01", bssid=ap.bssid)
    second = Client(mac="10:00:00:00:00:02", bssid=ap.bssid)
    first.signal_by_card["card0"] = -40
    second.signal_by_card["card0"] = -60
    array = _FakeArray([ap], [1, 6, 11])
    array.clients = {first.mac: first, second.mac: second}

    app = _ScannerHost(array)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        await pilot.pause(0)
        table = scanner.query_one("#ap-table", DataTable)
        table.move_cursor(row=1, animate=False)

        second.signal_by_card["card0"] = -20
        scanner.refresh_table()

        assert table.cursor_coordinate.row == 0
        selected = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        assert selected == second.mac


@pytest.mark.asyncio
async def test_selected_client_survives_row_removal_before_resort():
    ap = _make_ap("aa:bb:cc:00:00:01", ssid="AP", signal=-40)
    first = Client(mac="10:00:00:00:00:01", bssid=ap.bssid)
    selected_client = Client(mac="10:00:00:00:00:02", bssid=ap.bssid)
    third = Client(mac="10:00:00:00:00:03", bssid=ap.bssid)
    first.signal_by_card["card0"] = -20
    selected_client.signal_by_card["card0"] = -40
    third.signal_by_card["card0"] = -60
    array = _FakeArray([ap], [1, 6, 11])
    array.clients = {
        first.mac: first,
        selected_client.mac: selected_client,
        third.mac: third,
    }

    app = _ScannerHost(array)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        await pilot.pause(0)
        table = scanner.query_one("#ap-table", DataTable)
        table.move_cursor(row=1, animate=False)
        assert table.coordinate_to_cell_key(
            table.cursor_coordinate,
        ).row_key.value == selected_client.mac

        array.clients.pop(first.mac)
        scanner.refresh_table()
        await pilot.pause(0)

        assert table.coordinate_to_cell_key(
            table.cursor_coordinate,
        ).row_key.value == selected_client.mac


@pytest.mark.asyncio
async def test_hidden_guess_always_sorts_directly_below_named_sibling():
    sibling = _make_ap("02:00:00:00:00:01", ssid="Named", signal=-80)
    hidden = _make_ap("02:00:00:00:00:02", ssid=None, signal=-20)
    other = _make_ap("10:00:00:00:00:01", ssid="Other", signal=-30)
    hidden.siblings = [sibling.bssid]
    sibling.siblings = [hidden.bssid]
    array = _FakeArray([hidden, other, sibling], [1, 6, 11])

    app = _ScannerHost(array)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner._sort_idx = next(
            index for index, (column, _) in enumerate(scanner._COLUMNS)
            if column == "signal"
        )
        scanner._sort_reverse = True

        scanner.refresh_table()

        order = [row.value for row in table._row_locations]
        assert order.index(hidden.bssid) == order.index(sibling.bssid) + 1


@pytest.mark.asyncio
async def test_guess_stays_with_infrastructure_when_collapsed_and_expanded():
    """A hidden guess follows its named SSID through collapse and expand.

    Power sort would otherwise lift the strong guess above the group and
    scatter the weaker members once the group is opened.
    """
    lead = _make_ap("02:00:00:00:00:01", ssid="MOVISTAR-WIFI6-A250", signal=-40, beacons=10)
    named = _make_ap("02:00:00:00:00:02", ssid="MOVISTAR-WIFI6-A250", signal=-90, beacons=200)
    tail = _make_ap("02:00:00:00:00:03", ssid="MOVISTAR-WIFI6-A250", signal=-95, beacons=1)
    hidden = _make_ap("02:00:00:00:00:04", ssid=None, signal=-20)
    louder = _make_ap("10:00:00:00:00:01", ssid="Louder", signal=-30)
    quieter = _make_ap("10:00:00:00:00:02", ssid="Quieter", signal=-70)
    hidden.siblings = [lead.bssid, named.bssid, tail.bssid]
    group_key = "infrastructure:movistar-wifi6-a250"

    app = _ScannerHost(_FakeArray(
        [hidden, louder, lead, quieter, named, tail], [1, 6, 11],
    ))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner._sort_idx = next(
            index for index, (column, _) in enumerate(scanner._COLUMNS)
            if column == "signal"
        )
        scanner._sort_reverse = True
        scanner.refresh_table()

        collapsed = [row.value for row in table._row_locations]
        assert collapsed == [
            louder.bssid,
            group_key,
            hidden.bssid,
            quieter.bssid,
        ]
        assert table.get_cell(group_key, "bssid").plain == "3 BSSIDs"

        table.move_cursor(row=collapsed.index(group_key), animate=False)
        scanner.action_toggle_infrastructure()

        expanded = [row.value for row in table._row_locations]
        assert expanded == [
            louder.bssid,
            lead.bssid,
            named.bssid,
            hidden.bssid,
            tail.bssid,
            quieter.bssid,
        ]
        assert table.get_cell(lead.bssid, "ssid").plain == "  MOVISTAR-WIFI6-A250"
        assert table.get_cell(named.bssid, "ssid").plain == "  └ MOVISTAR-WIFI6-A250"
        assert table.get_cell(tail.bssid, "ssid").plain == "  └ MOVISTAR-WIFI6-A250"
        assert table.get_cell(hidden.bssid, "ssid").plain == "  MOVISTAR-WIFI6-A250 [guess]"
        bssid_col = table.columns[ColumnKey("bssid")]
        assert bssid_col.content_width <= _APScanTable.BSSID_COL_WIDTH

        bssid_col.content_width = 60
        table.move_cursor(row=expanded.index(lead.bssid), animate=False)
        scanner.action_toggle_infrastructure()
        await pilot.pause(0)
        assert table.get_cell(group_key, "bssid").plain == "3 BSSIDs"
        assert bssid_col.content_width <= _APScanTable.BSSID_COL_WIDTH


@pytest.mark.asyncio
async def test_forget_row_evicts_ap_and_its_clients():
    from wifit3.models import Client
    ap1 = _make_ap("aa:bb:cc:00:00:01", ssid="AP1", signal=-40)
    ap2 = _make_ap("aa:bb:cc:00:00:02", ssid="AP2", signal=-60)
    c1 = Client(mac="11:22:33:44:55:01", bssid=ap1.bssid)
    c2 = Client(mac="11:22:33:44:55:02", bssid=ap2.bssid)

    fake_array = _FakeArray([ap1, ap2], [1, 6, 11])
    fake_array.clients = {c1.mac: c1, c2.mac: c2}
    app = _ScannerHost(fake_array)
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()

        # Evict ap1 from scanner and array
        scanner._forget_row(ap1.bssid, drop_from_array=True)

        assert ap1.bssid not in fake_array.access_points
        assert ap1.bssid not in scanner.ap_cache
        # c1 was associated with ap1, must be pruned
        assert c1.mac not in fake_array.clients
        # c2 was associated with ap2, must NOT be pruned
        assert c2.mac in fake_array.clients


def test_ap_expiry_uses_configured_timeout(monkeypatch):
    scanner = ScannerView()
    monkeypatch.setattr(Config, "scanner_ap_expiry", 120.0)
    assert scanner._ap_has_expired(119.9) is False
    assert scanner._ap_has_expired(120.0) is True

    monkeypatch.setattr(Config, "scanner_ap_expiry", -1.0)
    assert scanner._ap_has_expired(100_000.0) is False


