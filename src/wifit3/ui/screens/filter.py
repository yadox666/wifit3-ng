"""The Scanner's filter bar and the ScanFilter predicate."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Button, Input, Label, Select

from wifit3.ui.search_input import SearchInput, sync_search_input_has_text

from wifit3.models import AccessPoint
from wifit3.id import vendor_for_mac
from wifit3.ui.encryption_format import EncryptionType
from wifit3.observe.product_catalog import catalog_family_select_options, matched_wifi_family_ids
from wifit3.ui.target_filter import build_target_select_options, refresh_target_select
from wifit3.wlan.channels import band_ranges


def _token_matches(token: str, bssid: str, ssid: str) -> bool:
    if len(token) == 1:
        return token in ssid
    return token in bssid or token in ssid


def text_matches(query: str, bssid: str, ssid: Optional[str]) -> bool:
    """Whitespace tokens AND-matched case-insensitively; a single-char token hits the SSID only."""
    bssid_l = bssid.lower()
    ssid_l = (ssid or "").lower()
    return all(_token_matches(t, bssid_l, ssid_l) for t in query.lower().split())


class EncryptionFilter(Enum):
    """ENCRYPT dropdown choices; ``value`` doubles as the label. WPA/2 merges WPA1+WPA2."""
    ALL = "All"
    OPEN = "Open"
    WEP = "WEP"
    ENTERPRISE = "Enterprise"
    WPA = "WPA/2"
    WPA3_TRANSITION = "WPA3→2"
    WPA3 = "WPA3"

    def matches(self, ap: AccessPoint) -> bool:
        if self is EncryptionFilter.ALL:
            return True
        if self is EncryptionFilter.ENTERPRISE:
            return any(
                akm.startswith("EAP") or akm.startswith("FT-EAP")
                for akm in ap.akms
            )
        return EncryptionType.from_ap(ap) in _FILTER_TYPES[self]


_FILTER_TYPES = {
    EncryptionFilter.OPEN: {EncryptionType.OPEN},
    EncryptionFilter.WEP: {EncryptionType.WEP},
    EncryptionFilter.WPA: {EncryptionType.WPA1, EncryptionType.WPA2},
    EncryptionFilter.WPA3_TRANSITION: {EncryptionType.WPA3_TRANSITION},
    EncryptionFilter.WPA3: {EncryptionType.WPA3},
}


@dataclass(frozen=True)
class ScanFilter:
    text: str = ""
    encryption: EncryptionFilter = EncryptionFilter.ALL
    min_signal: int = -100
    wps: Optional[bool] = None
    association: str = "all"
    target_id: str = ""
    catalog_family_id: str = ""

    def catalog_family_matches(self, ap: AccessPoint) -> bool:
        wanted = (self.catalog_family_id or "").strip()
        if not wanted:
            return True
        return wanted in matched_wifi_family_ids(
            ap.ssid,
            ap.bssid,
            ap.capabilities.vendor_ouis,
            catalog_family_id=ap.capabilities.catalog_family_id,
        )

    def matches(self, ap: AccessPoint, *, ssid: Optional[str] = None) -> bool:
        """``ssid`` overrides ap.ssid so a hidden AP is searchable by its guessed name."""
        searchable = " ".join(filter(None, (
            ssid or ap.ssid,
            vendor_for_mac(ap.bssid),
            ap.identity.summary,
            ap.country_code,
            ap.capabilities.remote_id,
            ap.capabilities.signature_label,
            ap.capabilities.catalog_class,
            ap.capabilities.catalog_live,
            ap.capabilities.catalog_attention,
            " ".join(ap.capabilities.catalog_labels),
        )))
        return (
            self.encryption.matches(ap)
            and ap.signal >= self.min_signal
            and (self.wps is None or ap.wps is self.wps)
            and text_matches(self.text, ap.bssid, searchable)
        )


class FilterBar(Horizontal):
    """One row above the AP table: text query, encryption select, channels button."""

    ALLOW_SELECT = False

    DEFAULT_CSS = """
    FilterBar {
        height: auto;
        padding: 0 1;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    FilterBar > Label { margin-right: 1; color: $text-muted; }
    FilterBar > Select { width: 12; margin-right: 1; }
    FilterBar > #filter-wps { width: 10; }
    FilterBar > #filter-association { width: 14; }
    FilterBar > #filter-catalog-family { width: 26; }
    FilterBar > #filter-target { width: 18; margin-right: 1; }
    FilterBar > #filter-channels { margin-right: 1; }
    FilterBar > #filter-text-box {
        width: 1fr;
        min-width: 18;
        height: auto;
        padding: 0;
        margin: 0;
    }
    FilterBar #filter-text {
        width: 1fr;
        min-width: 12;
        border: none;
        padding: 0 1;
        margin: 0;
        background: transparent;
    }
    FilterBar #filter-text.-has-text {
        background: $surface-darken-2;
    }
    FilterBar #clear-filter-text {
        width: 3;
        min-width: 3;
        max-width: 3;
        height: 1;
        min-height: 1;
        border: none;
        padding: 0;
        margin: 0;
        background: transparent;
        color: $text-muted;
        content-align: center middle;
    }
    FilterBar #clear-filter-text:hover,
    FilterBar #clear-filter-text:focus {
        background: $primary;
        color: $text;
    }
    FilterBar Select.-expanded SelectOverlay { border: round $primary !important; background: $surface; }
    """

    BINDINGS = [Binding("escape", "leave", "", show=False)]

    class ScanFilterChanged(Message):
        def __init__(self, scan_filter: ScanFilter) -> None:
            super().__init__()
            self.scan_filter = scan_filter

    class EditChannels(Message):
        pass

    def __init__(self, supported_channels: List[int]) -> None:
        super().__init__()
        self._supported = sorted(set(supported_channels))
        self._view_mode = "aps"
        self._paused = False
        self.border_title = "FILTER"

    def compose(self) -> ComposeResult:
        enc = Label("[u]E[/u]ncryption")
        enc.ALLOW_SELECT = False
        yield enc
        yield Select(
            [(f.value, f) for f in EncryptionFilter], value=EncryptionFilter.ALL,
            allow_blank=False, id="filter-encryption", compact=True,
        )
        yield Select(
            [("Any power", -100), ("≥ -80 dBm", -80), ("≥ -70 dBm", -70),
             ("≥ -60 dBm", -60), ("≥ -50 dBm", -50)],
            value=-100, allow_blank=False, id="filter-signal", compact=True,
        )
        yield Select(
            [("Any WPS", "all"), ("WPS only", "yes"), ("No WPS", "no")],
            value="all", allow_blank=False, id="filter-wps", compact=True,
        )
        yield Select(
            list(catalog_family_select_options()),
            value="",
            allow_blank=False,
            id="filter-catalog-family",
            compact=True,
        )
        association = Select(
            [("Any client", "all"), ("Connected", "connected"),
             ("Unassociated", "unassociated")],
            value="all", allow_blank=False, id="filter-association", compact=True,
        )
        association.display = False
        yield association
        yield Select(
            build_target_select_options(None),
            value="",
            allow_blank=False,
            id="filter-target",
            compact=True,
        )
        yield Button(self._channels_text(None), id="filter-channels", compact=True)
        yield Horizontal(
            SearchInput(
                placeholder="SSID, vendor, country, family…",
                id="filter-text",
                compact=True,
            ),
            Button(
                "×",
                id="clear-filter-text",
                tooltip="Clear search",
                compact=True,
            ),
            id="filter-text-box",
        )

    def on_mount(self) -> None:
        self.refresh_target_options()
        self.refresh_catalog_family_options()

    def refresh_catalog_family_options(self) -> None:
        select = self.query_one("#filter-catalog-family", Select)
        current = str(select.value or "")
        options = list(catalog_family_select_options())
        select.set_options(options)
        valid = {value for _label, value in options}
        if current not in valid:
            current = ""
            select.value = ""
        else:
            select.value = current

    def refresh_target_options(self) -> None:
        store = getattr(self.app, "target_store", None)
        refresh_target_select(self.query_one("#filter-target", Select), store)

    def focus_text(self) -> None:
        self.query_one("#filter-text", Input).focus()

    def focus_encryption(self) -> None:
        select = self.query_one("#filter-encryption", Select)
        select.focus()
        select.expanded = True

    def set_view(self, view_mode: str) -> None:
        self._view_mode = view_mode
        text = self.query_one("#filter-text", Input)
        text.placeholder = (
            "client, AP, vendor, or probe…"
            if view_mode == "clients"
            else "SSID, vendor, country, family…"
        )
        self._update_title()
        self.query_one("#filter-association", Select).display = view_mode == "clients"
        self.query_one("#filter-catalog-family", Select).display = view_mode != "clients"
        if view_mode == "clients":
            catalog = self.query_one("#filter-catalog-family", Select)
            with catalog.prevent(Select.Changed):
                catalog.value = ""

    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        self._update_title()

    def _update_title(self) -> None:
        title = "CLIENT FILTER" if self._view_mode == "clients" else "AP FILTER"
        self.border_title = f"{title} · PAUSED" if self._paused else title

    def set_channels(self, active: Optional[List[int]]) -> None:
        button = self.query_one("#filter-channels", Button)
        button.label = self._channels_text(active)
        button.refresh(layout=True)   # label reactive alone does not repaint the compact button

    def _channels_text(self, active: Optional[List[int]]) -> str:
        chans = set(active if active is not None else self._supported)
        parts = []
        for short, band in (("2.4G", [c for c in self._supported if c <= 14]),
                            ("5G", [c for c in self._supported if c > 14])):
            picked = [c for c in band if c in chans]
            if picked:
                parts.append(short if set(picked) == set(band) else band_ranges(picked)[0][1])
        return "[u]C[/u]hannels: " + (" + ".join(parts) or "none")

    def action_leave(self) -> None:
        self._focus_table()

    def on_input_submitted(self) -> None:
        self._focus_table()

    def on_input_changed(self) -> None:
        self._emit_scan_filter()

    def on_select_changed(self) -> None:
        self._emit_scan_filter()
        self._focus_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "clear-filter-text":
            event.stop()
            search = self.query_one("#filter-text", Input)
            if search.value:
                search.value = ""
            sync_search_input_has_text(search)
            search.focus()
            return
        if event.button.id == "filter-channels":
            self.post_message(self.EditChannels())

    def _emit_scan_filter(self) -> None:
        text = self.query_one("#filter-text", Input).value
        encryption = self.query_one("#filter-encryption", Select).value
        min_signal = int(self.query_one("#filter-signal", Select).value)
        raw_wps = self.query_one("#filter-wps", Select).value
        wps = None if raw_wps == "all" else raw_wps == "yes"
        association = str(self.query_one("#filter-association", Select).value)
        target_id = str(self.query_one("#filter-target", Select).value or "")
        catalog_family_id = str(
            self.query_one("#filter-catalog-family", Select).value or "",
        )
        self.post_message(self.ScanFilterChanged(
            ScanFilter(
                text=text,
                encryption=encryption,
                min_signal=min_signal,
                wps=wps,
                association=association,
                target_id=target_id,
                catalog_family_id=catalog_family_id,
            )
        ))

    def _focus_table(self) -> None:
        tables = self.screen.query("#ap-table")
        if tables:
            tables.first().focus()
