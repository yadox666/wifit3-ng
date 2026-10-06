"""The Scanner applies its ScanFilter as a display-only predicate: a filtered-out
AP loses its table row but keeps its registry entry, so widening the filter brings
it straight back without having to rediscover it."""
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import DataTable

from wifit3.models import AccessPoint, IdKey, IdSource
from wifit3.persist.vault import Vault
from wifit3.ui.screens.filter import (
    EncryptionFilter,
    ScanFilter,
)
from wifit3.ui.screens.scanner import ScannerView


class _FakeIface:
    def __init__(self, supported):
        self.supported_channels = supported
        self.current_channel = supported[0] if supported else 1
        self.chipset = "test"
        self.instance_key = ("test", id(self))
        self._is_hopping = True
        self.stop_calls = 0
        self.start_calls = 0

    async def stop_hopping(self):
        self.stop_calls += 1
        self._is_hopping = False

    async def start_hopping(
        self, channels=None, interval=0.25, member_channels=None,
    ):
        self.start_calls += 1
        self._is_hopping = True


class _FakeArray:
    def __init__(self, aps, supported):
        self.access_points = {ap.bssid: ap for ap in aps}
        self.clients = {}
        self.forged_macs = set()
        self.supported_channels = supported
        self.members = [_FakeIface(supported)] if supported else []
        self.stop_calls = 0
        self.start_calls = 0

    def get_access_points(self, include_eviltwin=True):
        return list(self.access_points.values())

    def select_iface(self, channel):
        return next((iface for iface in self.members if channel in iface.supported_channels), None)

    async def start_hopping(
        self, channels=None, interval=0.25, member_channels=None,
    ):
        self.start_calls += 1

    async def stop_hopping(self):
        self.stop_calls += 1

    @asynccontextmanager
    async def claim(self, iface):
        await iface.stop_hopping()
        try:
            yield iface
        finally:
            await iface.start_hopping()


class _ScannerHost(App):
    def __init__(self, array):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.vault = Vault()

    def persist_config(self) -> None:
        pass

    def sdr_jam_available(self) -> bool:
        return False

    def on_mount(self) -> None:
        self.push_screen(ScannerView())


def test_scan_band_plan_logs_only_when_configuration_changes(monkeypatch):
    scanner = ScannerView()
    writes = []
    log = SimpleNamespace(write=writes.append)
    monkeypatch.setattr(scanner, "query_one", lambda *_args, **_kwargs: log)
    member = SimpleNamespace(instance_key="wlan1", name="wlan1")
    array = SimpleNamespace(members=[member])

    scanner._log_scan_band_plan(array, {"wlan1": "5g"})
    scanner._log_scan_band_plan(array, {"wlan1": "5g"})
    scanner._log_scan_band_plan(array, {"wlan1": "all"})

    assert len(writes) == 2
    assert "5 GHz" in writes[0]
    assert "all bands" in writes[1]


@pytest.mark.asyncio
async def test_encryption_filter_hides_rows_but_keeps_registry():
    open_ap = AccessPoint(bssid="aa:bb:cc:00:00:01", ssid="OpenNet", channel=1, encryption="OPEN")
    wpa2_ap = AccessPoint(bssid="aa:bb:cc:00:00:02", ssid="SecureNet", channel=1, akms=["PSK"])

    app = _ScannerHost(_FakeArray([open_ap, wpa2_ap], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        assert isinstance(scanner, ScannerView)
        table = scanner.query_one("#ap-table", DataTable)

        scanner.refresh_table()
        assert table.row_count == 2

        scanner._scan_filter = ScanFilter(encryption=EncryptionFilter.WPA)
        scanner.refresh_table()
        assert table.row_count == 1
        assert wpa2_ap.bssid in scanner.ap_cache
        assert open_ap.bssid not in scanner.ap_cache
        # Display-only: the hidden AP is still in the registry.
        assert open_ap.bssid in app.array.access_points

        scanner._scan_filter = ScanFilter()
        scanner.refresh_table()
        assert table.row_count == 2
        assert open_ap.bssid in scanner.ap_cache


@pytest.mark.asyncio
async def test_catalog_family_filter_limits_visible_aps():
    flock = AccessPoint(
        bssid="b4:1e:52:10:20:30", ssid="Flock-ABC123", channel=6, akms=["PSK"],
    )
    other = AccessPoint(
        bssid="aa:bb:cc:00:00:99", ssid="OpenNet", channel=6, encryption="OPEN",
    )

    app = _ScannerHost(_FakeArray([flock, other], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner.refresh_table()
        assert table.row_count == 2

        scanner._scan_filter = ScanFilter(catalog_family_id="flock-cameras")
        scanner.refresh_table()
        assert table.row_count == 1
        assert flock.bssid in scanner.ap_cache
        assert other.bssid not in scanner.ap_cache
        assert other.bssid in app.array.access_points


@pytest.mark.asyncio
async def test_text_filter_matches_hidden_ap_via_guessed_sibling():
    named = AccessPoint(bssid="aa:bb:cc:00:00:10", ssid="Castle Crasher", channel=6,
                        akms=["PSK"], beacons=50)
    hidden = AccessPoint(bssid="aa:bb:cc:00:00:11", ssid=None, channel=6,
                         akms=["PSK"], siblings=[named.bssid])
    other = AccessPoint(bssid="aa:bb:cc:00:00:12", ssid="OpenNet", channel=6, encryption="OPEN")

    app = _ScannerHost(_FakeArray([named, hidden, other], [1, 6, 11]))
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#ap-table", DataTable)

        scanner._scan_filter = ScanFilter(text="castle")
        scanner.refresh_table()
        assert table.row_count == 2
        assert named.bssid in scanner.ap_cache              # matches by its own SSID
        assert hidden.bssid in scanner.ap_cache             # matches via the guessed sibling name
        assert other.bssid not in scanner.ap_cache


def test_scanner_identity_cell_shows_manufacturer_and_model():
    scanner = ScannerView()
    scanner._theme_fg = "white"
    ap = AccessPoint(
        bssid="02:00:00:00:00:01",
        ssid="Lab",
        channel=1,
    )
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "MikroTik")
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MODEL_NAME, "hAP ac²")
    cell = scanner._identity_cell(ap)
    assert cell.plain == "MikroTik hAP ac²"


def test_scanner_identity_cell_blank_when_unknown():
    scanner = ScannerView()
    scanner._theme_fg = "white"
    ap = AccessPoint(bssid="02:00:00:00:00:01")
    assert scanner._identity_cell(ap).plain == ""


def test_scanner_identity_cell_shows_summary():
    scanner = ScannerView()
    scanner._theme_fg = "white"
    ap = AccessPoint(
        bssid="02:00:00:00:00:01",
        ssid="Vodafone-123456",
    )
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "Celeno")
    assert scanner._identity_cell(ap).plain == "Celeno"


def test_scanner_identity_cell_oui_fallback():
    scanner = ScannerView()
    scanner._theme_fg = "white"
    ap = AccessPoint(bssid="00:03:93:11:22:33", ssid="Alice’s iPhone")
    assert scanner._identity_cell(ap).plain == "Apple"


def test_scanner_capture_badges_live_in_cap_column_not_ssid():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
    scanner = ScannerView()
    scanner._theme_fg = "white"
    scanner._ssid_chips_markup = (
        lambda _ap: "[green]✓HS[/green] [green]✓PMK[/green] [green]✓PSK[/green]"
    )
    cap = scanner._captures_cell(ap)
    ssid = scanner._ssid_cell(ap)
    assert "✓HS" in cap.plain
    assert "✓PMK" in cap.plain
    assert "✓PSK" in cap.plain
    assert "✓HS" not in ssid.plain
    assert ssid.plain.strip() == "Net"


def test_scanner_catalog_class_and_family_columns_separate_from_identity():
    scanner = ScannerView()
    scanner._theme_fg = "white"
    ap = AccessPoint(bssid="b4:1e:52:10:20:30", ssid="Flock-ABC123")
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "Flock Safety")
    ap.capabilities.catalog_labels = ("Flock Safety Cameras",)
    ap.capabilities.catalog_class = "Surveillance"
    ap.capabilities.catalog_attention = "Roadside camera match."
    assert scanner._identity_cell(ap).plain == "Flock Safety"
    assert scanner._catalog_class_cell(ap).plain == "Surveillance"
    family = scanner._catalog_family_cell(ap)
    assert "Flock Safety Cameras" in family.plain
    assert "◆" in family.plain
