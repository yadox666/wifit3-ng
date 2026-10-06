"""ScanFilter predicate (text + encryption) and FilterBar message wiring."""
import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input, Select

from wifit3.models import AccessPoint
from wifit3.ui.encryption_format import EncryptionType
from wifit3.ui.screens.filter import (
    EncryptionFilter,
    FilterBar,
    ScanFilter,
    text_matches,
)


def _ap(**kw) -> AccessPoint:
    return AccessPoint(bssid="AA:BB:CC:DD:EE:FF", **kw)


# ---- text_matches ----------------------------------------------------------

def test_empty_query_matches_everything():
    assert text_matches("", "AA:BB:CC:DD:EE:FF", None)
    assert text_matches("   ", "AA:BB:CC:DD:EE:FF", "anything")


def test_substring_is_case_insensitive_over_ssid_and_bssid():
    assert text_matches("net", "AA:BB:CC:DD:EE:FF", "NetGear")
    assert text_matches("bb:cc", "AA:BB:CC:DD:EE:FF", None)


def test_space_separated_tokens_are_anded():
    assert text_matches("net 5g", "AA:BB:CC:DD:EE:FF", "Net Home 5G")
    assert not text_matches("net xyz", "AA:BB:CC:DD:EE:FF", "Net Home 5G")


def test_single_char_token_matches_ssid_only():
    assert text_matches("f", "AA:BB:CC:DD:EE:FF", "wolf")
    # 'f' is all over the BSSID, but a lone char never matches the BSSID.
    assert not text_matches("f", "AA:BB:CC:DD:EE:FF", "xyz")


def test_not_fuzzy_subsequence():
    assert not text_matches("ntgr", "AA:BB:CC:DD:EE:FF", "netgear")


# ---- EncryptionType.from_ap (shared by the ENCRYPT column and the filter) --

@pytest.mark.parametrize("kw, expected", [
    (dict(encryption="WEP"), EncryptionType.WEP),
    (dict(akms=["PSK"]), EncryptionType.WPA2),
    (dict(wpa3=True), EncryptionType.WPA3),
    (dict(wpa3=True, transition_mode=True), EncryptionType.WPA3_TRANSITION),
    (dict(akms=["OWE"]), EncryptionType.OWE),
    (dict(encryption="OPEN"), EncryptionType.OPEN),
    (dict(encryption="WPA"), EncryptionType.WPA1),
    (dict(), EncryptionType.OPEN),  # default encryption "Unknown" -> OPEN
])
def test_encryption_type_from_ap(kw, expected):
    assert EncryptionType.from_ap(_ap(**kw)) is expected


# ---- EncryptionFilter.matches ----------------------------------------------

def test_all_matches_every_ap():
    for kw in (dict(), dict(encryption="WEP"), dict(wpa3=True), dict(akms=["PSK"])):
        assert EncryptionFilter.ALL.matches(_ap(**kw))


def test_encryption_filters_select_their_bucket():
    assert EncryptionFilter.OPEN.matches(_ap(encryption="OPEN"))
    assert EncryptionFilter.WEP.matches(_ap(encryption="WEP"))
    assert EncryptionFilter.WPA3.matches(_ap(wpa3=True))
    assert EncryptionFilter.WPA3_TRANSITION.matches(_ap(wpa3=True, transition_mode=True))
    assert not EncryptionFilter.WEP.matches(_ap(akms=["PSK"]))


def test_wpa_filter_merges_wpa1_and_wpa2():
    assert EncryptionFilter.WPA.matches(_ap(encryption="WPA"))   # legacy WPA1
    assert EncryptionFilter.WPA.matches(_ap(akms=["PSK"]))       # RSN WPA2
    assert not EncryptionFilter.WPA.matches(_ap(wpa3=True))
    assert not EncryptionFilter.WPA.matches(_ap(encryption="OPEN"))


@pytest.mark.parametrize("akm", [
    "EAP", "FT-EAP", "EAP-SHA256", "EAP-SUITE-B", "EAP-SUITE-B-192",
    "FT-EAP-SHA384",
])
def test_enterprise_filter_matches_eap_akms(akm):
    assert EncryptionFilter.ENTERPRISE.matches(_ap(akms=[akm]))


def test_enterprise_filter_excludes_personal_and_open_networks():
    for kw in (
        dict(akms=["PSK"]),
        dict(akms=["SAE"]),
        dict(akms=["OWE"]),
        dict(encryption="OPEN"),
        dict(encryption="WEP"),
    ):
        assert not EncryptionFilter.ENTERPRISE.matches(_ap(**kw))


def test_enterprise_filter_includes_mixed_psk_eap_network():
    assert EncryptionFilter.ENTERPRISE.matches(_ap(akms=["PSK", "EAP"]))


def test_transition_ap_is_not_pure_wpa3():
    ap = _ap(wpa3=True, transition_mode=True)
    assert not EncryptionFilter.WPA3.matches(ap)
    assert not EncryptionFilter.WPA.matches(ap)


# ---- ScanFilter (text AND encryption) --------------------------------------

def test_default_scan_filter_matches_all():
    assert ScanFilter().matches(_ap(ssid="whatever", encryption="WEP"))


def test_scan_filter_ands_text_and_encryption():
    ap = _ap(ssid="netgear", akms=["PSK"])
    assert ScanFilter(text="net", encryption=EncryptionFilter.WPA).matches(ap)
    assert not ScanFilter(text="zzz", encryption=EncryptionFilter.WPA).matches(ap)
    assert not ScanFilter(text="net", encryption=EncryptionFilter.WPA3).matches(ap)


def test_hidden_ap_found_by_guessed_ssid():
    hidden = _ap(ssid=None)
    assert not ScanFilter(text="castle").matches(hidden)
    assert ScanFilter(text="castle").matches(hidden, ssid="Castle Crasher")


def test_scan_filter_catalog_family():
    from wifit3.models import AccessPoint
    from wifit3.ui.screens.filter import ScanFilter

    flock = AccessPoint(bssid="b4:1e:52:10:20:30", ssid="Flock-ABC123")
    other = _ap(ssid="RandomNet")
    filt = ScanFilter(catalog_family_id="flock-cameras")
    assert filt.catalog_family_matches(flock)
    assert not filt.catalog_family_matches(other)
    assert ScanFilter().catalog_family_matches(other)


def test_scan_filter_supports_signal_wps_and_country():
    ap = _ap(ssid="Office", wps=True, country_code="US")
    ap.signal_by_card = {"card0": -65}
    assert ScanFilter(min_signal=-70, wps=True).matches(ap)
    assert not ScanFilter(min_signal=-60).matches(ap)
    assert not ScanFilter(wps=False).matches(ap)
    assert ScanFilter(text="US").matches(ap)


# ---- FilterBar message wiring ----------------------------------------------

class _Host(App):
    def __init__(self, supported):
        super().__init__()
        self._supported = supported
        self.events = []

    def compose(self) -> ComposeResult:
        yield FilterBar(self._supported)

    def on_filter_bar_scan_filter_changed(self, m: FilterBar.ScanFilterChanged):
        self.events.append(("scan", m.scan_filter))

    def on_filter_bar_edit_channels(self, m: FilterBar.EditChannels):
        self.events.append(("channels", None))


async def test_typing_emits_scan_filter():
    app = _Host([1, 6, 11, 36, 40])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.events.clear()
        app.query_one("#filter-text", Input).value = "net"
        await pilot.pause()
        scan = [e for e in app.events if e[0] == "scan"]
        assert scan and scan[-1][1].text == "net"


async def test_encryption_select_emits_scan_filter():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.events.clear()
        app.query_one("#filter-encryption", Select).value = EncryptionFilter.WPA
        await pilot.pause()
        scan = [e for e in app.events if e[0] == "scan"]
        assert scan and scan[-1][1].encryption is EncryptionFilter.WPA


async def test_enterprise_encryption_select_emits_scan_filter():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.events.clear()
        app.query_one("#filter-encryption", Select).value = EncryptionFilter.ENTERPRISE
        await pilot.pause()
        scan = [e for e in app.events if e[0] == "scan"]
        assert scan and scan[-1][1].encryption is EncryptionFilter.ENTERPRISE


async def test_signal_and_wps_selects_emit_scan_filter():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.events.clear()
        app.query_one("#filter-signal", Select).value = -70
        app.query_one("#filter-wps", Select).value = "yes"
        await pilot.pause()
        scan = [event for event in app.events if event[0] == "scan"]
        assert scan[-1][1].min_signal == -70
        assert scan[-1][1].wps is True


async def test_catalog_family_select_emits_scan_filter():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        options = app.query_one("#filter-catalog-family", Select)._options
        family_id = next(value for _label, value in options if value)
        app.events.clear()
        app.query_one("#filter-catalog-family", Select).value = family_id
        await pilot.pause()
        scan = [event for event in app.events if event[0] == "scan"]
        assert scan[-1][1].catalog_family_id == family_id


async def test_association_select_emits_client_filter():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        bar = app.query_one(FilterBar)
        bar.set_view("clients")
        app.events.clear()
        app.query_one("#filter-association", Select).value = "unassociated"
        await pilot.pause()
        scan = [event for event in app.events if event[0] == "scan"]
        assert scan[-1][1].association == "unassociated"


async def test_channels_button_requests_dialog():
    app = _Host([1, 6, 11, 36, 40])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.events.clear()
        app.query_one("#filter-channels", Button).press()
        await pilot.pause()
        assert any(e[0] == "channels" for e in app.events)


async def test_clear_filter_text_button_clears_search():
    app = _Host([1, 6, 11])
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#filter-text", Input).value = "net"
        await pilot.pause()
        app.query_one("#clear-filter-text", Button).press()
        await pilot.pause()
        assert app.query_one("#filter-text", Input).value == ""
        scan = [e for e in app.events if e[0] == "scan"]
        assert scan and scan[-1][1].text == ""


def test_channels_label_drops_band_prefix_for_partial_sets():
    bar = FilterBar(list(range(1, 12)) + [36, 40, 44, 48])
    assert bar._channels_text(None).endswith("2.4G + 5G")            # all
    assert bar._channels_text([1, 3, 4, 6]).endswith("1, 3-4, 6")    # partial 2.4, no band name
    assert bar._channels_text(list(range(1, 12)) + [44]).endswith("2.4G + 44")
    assert bar._channels_text([36, 40, 44, 48]).endswith("5G")       # whole 5 GHz band

