from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Select

from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.probe import wpa2_beacon
from wifit3.models import AccessPoint, Client, ProbeObservation, SignalPosition
from wifit3.persist.targets import TargetStore
from wifit3.persist.vault import Vault
from wifit3.targeting import client_candidate
from wifit3.ui.screens.filter import ScanFilter
from wifit3.ui.screens.scanner import CLIENT_STALE_DURATION_S, ScannerView
from wifit3.ui.screens.open_probe_modal import OpenProbeSsidModal


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
        self.target_sightings = []
        self._target_sighting_ids = set()

    def persist_config(self):
        pass

    def record_target_sighting(self, target, where):
        if target.id in self._target_sighting_ids:
            return
        self._target_sighting_ids.add(target.id)
        self.target_sightings.append((target, where))

    def on_mount(self):
        self.push_screen(ScannerView())


class _ModalHost(App):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.result = None

    def on_mount(self):
        self.push_screen(OpenProbeSsidModal(self.client), self._finished)

    def _finished(self, result):
        self.result = result


def _plain(value):
    return value.plain if hasattr(value, "plain") else str(value)


def _footer_descriptions(scanner):
    return {
        binding.description
        for _, binding, _, _ in scanner.active_bindings.values()
        if binding.show
    }


@pytest.mark.asyncio
async def test_filter_text_focus_keeps_footer_shortcuts():
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    app = _Host(_Array(ap, []))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        baseline = _footer_descriptions(scanner)
        assert "Channel Lock" in baseline
        assert "Pause" in baseline
        filter_input = scanner.query_one("#filter-text", Input)
        filter_input.focus()
        filter_input.value = "office"
        await pilot.pause(0)
        assert _footer_descriptions(scanner) == baseline


@pytest.mark.asyncio
async def test_scanner_switches_between_ap_and_client_tables():
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    ap.signal_by_card = {"card0": -40}
    ap.positions = [
        SignalPosition(51.501, -0.142, None, 4.0, 10, "gps", -40),
    ]
    connected = Client(
        mac="18:7f:88:aa:bb:cc", bssid=ap.bssid, packets=14,
        probed_ssids={"CoffeeShop", "Home"},
    )
    connected.signal_by_card = {"card0": -48}
    connected.positions = [
        SignalPosition(51.502, -0.143, None, 6.0, 11, "gps", -48),
    ]
    roaming = Client(
        mac="02:00:00:00:00:01", packets=3, probed_ssids={"Airport"},
    )
    roaming.signal_by_card = {"card0": -70}

    app = _Host(_Array(ap, [connected, roaming]))
    app.ap_history_store = SimpleNamespace(
        aps_for_client=lambda mac: (
            [
                SimpleNamespace(
                    bssid="00:03:93:11:22:44",
                    ssid="Old Office",
                ),
            ]
            if mac == connected.mac
            else []
        ),
    )
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)
        scanner.refresh_table()
        assert scanner.check_action("open_probe_ap", ()) is False
        assert "Probe Honeypot" not in _footer_descriptions(scanner)
        assert table.row_count == 1
        assert _plain(table.get_cell(ap.bssid, "last_seen")) == "now"
        assert _plain(table.get_cell(ap.bssid, "location")) == "🌐"
        assert scanner._table_map_urls[ap.bssid].startswith(
            "https://www.google.com/maps/place/"
        )

        scanner.action_toggle_pause()
        ap.signal_by_card["card0"] = -20
        scanner.refresh_table()
        assert _plain(table.get_cell(ap.bssid, "signal")) == "-40 dBm"
        scanner.action_toggle_pause()
        assert _plain(table.get_cell(ap.bssid, "signal")) == "-20 dBm"

        scanner.action_toggle_view()
        await pilot.pause(0)
        assert scanner._view_mode == "clients"
        assert scanner.check_action("open_probe_ap", ()) is True
        assert scanner.check_action("open_vault", ()) is True
        assert scanner.check_action("toggle_infrastructure", ()) is False
        assert "Probe Honeypot" in _footer_descriptions(scanner)
        assert "Vault" in _footer_descriptions(scanner)
        assert "Infrastructure" not in _footer_descriptions(scanner)
        assert [key.value for key in table.columns] == [
            "client", "manufacturer", "signal", "packets", "last_seen",
            "location",
            "ssid", "probes",
        ]
        assert table.row_count == 2
        assert _plain(table.get_cell(connected.mac, "manufacturer")) == "Ring"
        assert _plain(table.get_cell(connected.mac, "ssid")) == f"Office  ·  {ap.bssid}"
        assert _plain(table.get_cell(connected.mac, "probes")) == (
            "CoffeeShop  ·  Home  ·  Old Office [connect_hist]"
        )
        assert _plain(table.get_cell(connected.mac, "last_seen")) == "now"
        assert _plain(table.get_cell(connected.mac, "location")) == "🌐"
        assert scanner._table_map_urls[connected.mac].startswith(
            "https://www.google.com/maps/place/"
        )
        assert "/@51.5020000,-0.1430000," in scanner._table_map_urls[connected.mac]
        assert (
            "place/51.5020000%2C-0.1430000/@"
            in scanner._table_map_urls[connected.mac]
        )
        assert _plain(table.get_cell(roaming.mac, "ssid")) == "‹unassociated›"
        assert _plain(table.get_cell(roaming.mac, "client")) == roaming.mac
        assert _plain(table.get_cell(roaming.mac, "manufacturer")) == "~"

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
        assert scanner._view_mode == "split"
        split_clients = scanner.query_one("#client-table", DataTable)
        assert split_clients.display
        assert split_clients.row_count == 1
        assert connected.mac in split_clients.rows
        assert roaming.mac not in split_clients.rows

        scanner.action_toggle_view()
        await pilot.pause(0)
        assert scanner._view_mode == "aps"
        assert not split_clients.display
        assert scanner.check_action("open_probe_ap", ()) is False
        assert scanner.check_action("open_vault", ()) is True
        assert scanner.check_action("toggle_infrastructure", ()) is True
        assert table.row_count == 1
        assert ap.bssid in scanner.ap_cache


@pytest.mark.asyncio
async def test_client_refresh_rebuilds_row_missing_from_table():
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    client = Client(mac="18:7f:88:aa:bb:cc", bssid=ap.bssid, packets=1)
    app = _Host(_Array(ap, [client]))

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        await pilot.pause(0)
        table = scanner.query_one("#ap-table", DataTable)
        assert table.row_count == 1
        assert client.mac in scanner._client_row_states

        table.remove_row(client.mac)
        client.packets = 2
        scanner.refresh_table()

        assert table.row_count == 1
        assert _plain(table.get_cell(client.mac, "packets")) == "2"


@pytest.mark.asyncio
async def test_split_view_tracks_clients_of_highlighted_ap():
    first_ap = AccessPoint(
        bssid="00:03:93:11:22:33",
        ssid="First",
        channel=1,
    )
    second_ap = AccessPoint(
        bssid="00:03:93:11:22:44",
        ssid="Second",
        channel=6,
    )
    first_client = Client(mac="18:7f:88:aa:bb:01", bssid=first_ap.bssid)
    second_client = Client(mac="18:7f:88:aa:bb:02", bssid=second_ap.bssid)
    array = _Array(first_ap, [first_client, second_client])
    array.access_points[second_ap.bssid] = second_ap
    app = _Host(array)

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        scanner.action_toggle_view()
        await pilot.pause(0)

        ap_table = scanner.query_one("#ap-table", DataTable)
        client_table = scanner.query_one("#client-table", DataTable)
        ap_table.move_cursor(
            row=ap_table.get_row_index(second_ap.bssid),
            animate=False,
        )
        await pilot.pause(0)

        assert second_client.mac in client_table.rows
        assert first_client.mac not in client_table.rows


@pytest.mark.asyncio
async def test_open_probe_action_opens_configuration_modal(monkeypatch):
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    client = Client(
        mac="02:11:22:33:44:55",
        probed_ssids={"DefaultSSID"},
        probe_observations={
            "DefaultSSID": ProbeObservation(channel=6, first_seen=1, last_seen=2, count=3),
        },
    )
    app = _Host(_Array(ap, [client]))

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        await pilot.pause(0)
        pushed = []
        monkeypatch.setattr(
            app,
            "push_screen",
            lambda screen, callback=None: pushed.append((screen, callback)),
        )

        scanner.action_open_probe_ap()

        assert len(pushed) == 1
        assert isinstance(pushed[0][0], OpenProbeSsidModal)


@pytest.mark.asyncio
async def test_honeypot_prefers_matching_live_ap_rsn_profile():
    ap = AccessPoint(
        bssid="00:03:93:11:22:33",
        ssid="DefaultSSID",
        channel=6,
        encryption="WPA2",
        akms=["PSK"],
        akm_suites=[2],
    )
    ap.last_beacon_frame = wpa2_beacon(
        bytes.fromhex("000393112233"), ap.ssid, ap.channel,
    )
    app = _Host(_Array(ap, []))

    async with app.run_test() as pilot:
        await pilot.pause(0)
        rsn_ie, source, profile_ies = app.screen._honeypot_rsn_profile(
            "DefaultSSID", 6,
        )

        assert rsn_ie == GENERIC_RSN_IE
        assert "live AP 00:03:93:11:22:33" in source
        assert isinstance(profile_ies, bytes)


@pytest.mark.asyncio
async def test_open_probe_modal_asks_for_one_to_five_minutes():
    client = Client(
        mac="02:11:22:33:44:55",
        probed_ssids={"DefaultSSID"},
        probe_observations={
            "DefaultSSID": ProbeObservation(
                channel=6, first_seen=1, last_seen=2, count=3,
            ),
        },
    )
    app = _ModalHost(client)

    async with app.run_test() as pilot:
        await pilot.pause(0)
        duration = app.screen.query_one("#probe-duration", Select)
        assert [value for _, value in duration._options] == [60, 120, 180, 240, 300]
        duration.value = 300
        app.screen.query_one("#probe-encryption", Select).value = "WPA2"
        app.screen.query_one("#start", Button).press()
        await pilot.pause(0)

        assert app.result == ("DefaultSSID", 300, "WPA2")


@pytest.mark.asyncio
async def test_own_open_fake_ap_is_a_separate_marked_row():
    real = AccessPoint(
        bssid="00:03:93:11:22:33", ssid="DefaultSSID", channel=6,
    )
    fake = AccessPoint(
        bssid="02:de:ad:be:ef:01",
        ssid="DefaultSSID",
        channel=6,
        encryption="OPEN",
        is_own_fake=True,
        own_fake_active=True,
    )
    array = _Array(real, [])
    array.access_points[fake.bssid] = fake
    app = _Host(array)

    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        table = scanner.query_one("#ap-table", DataTable)

        assert table.row_count == 2
        assert "FAKE AP [ACTIVE]" in _plain(table.get_cell(fake.bssid, "ssid"))
        assert "OUR HONEYPOT AP · ACTIVE" == _plain(
            table.get_cell(fake.bssid, "identity"),
        )


@pytest.mark.asyncio
async def test_saved_targets_mark_ap_ssid_and_client_identity_with_icon(tmp_path):
    ap = AccessPoint(
        bssid="00:03:93:11:22:33", ssid="Office", channel=6, wps=True,
        encryption="WPA2", akms=["PSK"],
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
        cap_cell = table.get_cell(ap.bssid, "captures")
        assert ap_cell.plain.startswith("⌖ ")
        assert "Office" in ap_cell.plain
        assert "✓HS" in cap_cell.plain
        assert "✓WPS" in cap_cell.plain
        for badge in ("✓HS", "✓WPS"):
            assert badge not in ap_cell.plain
        assert any("red" in str(span.style) for span in ap_cell.spans)
        for column in ("channel", "wps", "encryption", "captures"):
            cell = table.get_cell(ap.bssid, column)
            assert not any("cyan" in str(span.style) for span in cell.spans)

        scanner.action_toggle_view()
        await pilot.pause(0)
        assert not table.get_cell(client.mac, "ssid").plain.startswith("⌖ ")
        client_cell = table.get_cell(client.mac, "client")
        assert client_cell.plain.startswith("⌖ ")
        assert "red" in str(client_cell.style)


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
        group_key = "infrastructure:hotel wifi"
        assert table.get_cell(group_key, "ssid").plain == "  ▸ Hotel WiFi · 2 APs"
        assert table.get_cell(group_key, "channel").plain == "1,6"
        assert table.get_cell(group_key, "signal").plain == "-40 dBm"

        await pilot.press("enter")
        await pilot.pause(0)
        assert table.row_count == 2
        assert table.get_row_at(0)[0].plain == "  Hotel WiFi"
        assert table.get_row_at(1)[0].plain == "  └ Hotel WiFi"

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
        assert encryption.plain.startswith("WPA2")
        assert "!WEAK" not in encryption.plain
        assert any(getattr(span, "style", None) == "bright_red" for span in encryption._spans)


@pytest.mark.asyncio
async def test_client_text_filter_tolerates_missing_ap_vendor(monkeypatch):
    ap = AccessPoint(bssid="86:aa:9c:2c:0c:ef", ssid="MOVISTAR_0CE6", channel=112)
    client = Client(mac="d8:74:ef:fa:c6:78", bssid=ap.bssid, packets=1)
    app = _Host(_Array(ap, [client]))
    monkeypatch.setattr(
        "wifit3.ui.screens.scanner.vendor_for_mac",
        lambda _mac: None,
    )
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner.action_toggle_view()
        await pilot.pause(0)
        scanner._scan_filter = ScanFilter(text="movistar")
        scanner.refresh_table()
        table = scanner.query_one("#ap-table", DataTable)
        assert table.row_count == 1


def test_client_display_age_grace_after_ap_focus():
    scanner = ScannerView()
    now = 1_000.0
    client = Client(
        mac="18:7f:88:aa:bb:cc",
        bssid="00:03:93:11:22:33",
        last_seen=now - 120.0,
    )
    scanner._client_stale_grace_from[client.mac] = now
    assert scanner._client_display_age(client, now) == 0.0
    assert (
        scanner._client_display_age(client, now + CLIENT_STALE_DURATION_S + 0.5)
        > CLIENT_STALE_DURATION_S
    )


def test_client_display_age_stays_dim_until_resighted():
    scanner = ScannerView()
    now = 2_000.0
    client = Client(mac="18:7f:88:aa:bb:cc", last_seen=now - 500.0)
    scanner._client_dim_until_resight[client.mac] = client.last_seen
    assert scanner._client_display_age(client, now) > CLIENT_STALE_DURATION_S
    client.last_seen = now
    assert scanner._client_display_age(client, now) == 0.0
    assert client.mac not in scanner._client_dim_until_resight


@pytest.mark.asyncio
async def test_ap_focus_resume_applies_client_stale_policy():
    import time

    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Office", channel=6)
    active = Client(mac="18:7f:88:aa:bb:cc", bssid=ap.bssid, last_seen=time.time() - 5.0)
    stale = Client(
        mac="02:00:00:00:00:01",
        bssid=ap.bssid,
        last_seen=time.time() - (CLIENT_STALE_DURATION_S + 10.0),
    )
    app = _Host(_Array(ap, [active, stale]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        scanner._client_dim_before_ap_focus = {stale.mac}
        scanner._apply_client_stale_policy_after_ap_focus()
        assert active.mac in scanner._client_stale_grace_from
        assert stale.mac in scanner._client_dim_until_resight
        now = time.time()
        assert scanner._client_display_age(active, now) < 1.0
        assert scanner._client_display_age(stale, now) > CLIENT_STALE_DURATION_S
