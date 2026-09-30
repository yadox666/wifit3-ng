"""Filter bar and predicates for the offline history database view."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Input, Select

from wifit3.id import vendor_for_mac
from wifit3.ui.encryption_format import EncryptionType
from wifit3.ui.screens.filter import EncryptionFilter, text_matches
from wifit3.ui.target_filter import (
    build_target_select_options,
    offline_record_matches_target_filter,
    refresh_target_select,
)


_OFFLINE_ENC_TYPES = {
    EncryptionFilter.OPEN: {EncryptionType.OPEN, EncryptionType.UNKNOWN},
    EncryptionFilter.WEP: {EncryptionType.WEP},
    EncryptionFilter.WPA: {EncryptionType.WPA1, EncryptionType.WPA2},
    EncryptionFilter.WPA3_TRANSITION: {EncryptionType.WPA3_TRANSITION},
    EncryptionFilter.WPA3: {EncryptionType.WPA3},
}


def encryption_type_from_record(record: dict[str, Any]) -> EncryptionType:
    security = record.get("security") or {}
    akms = list(security.get("akms") or [])
    if security.get("wpa3") and security.get("transition_mode"):
        return EncryptionType.WPA3_TRANSITION
    if security.get("wpa3"):
        return EncryptionType.WPA3
    if "OWE" in akms:
        return EncryptionType.OWE
    if akms:
        return EncryptionType.WPA2
    enc = str(record.get("encryption") or "").upper()
    if enc in ("", "OPEN", "UNKNOWN"):
        return EncryptionType.OPEN
    if enc == "WEP":
        return EncryptionType.WEP
    if enc == "WPA" or enc.startswith("WPA-"):
        return EncryptionType.WPA1
    return EncryptionType.UNKNOWN


def _record_has_gps(record: dict[str, Any]) -> bool:
    positions = record.get("positions")
    return isinstance(positions, list) and bool(positions)


def _channel_band(channel: Any) -> str | None:
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return None
    if ch <= 14:
        return "2.4"
    if ch <= 196:
        return "5"
    return "6"


def _tri_state(value: str, present: bool) -> bool:
    if value == "all":
        return True
    if value == "yes":
        return present
    return not present


@dataclass(frozen=True)
class OfflineFilters:
    text: str = ""
    encryption: EncryptionFilter = EncryptionFilter.ALL
    wps: str = "all"
    ap_clients: str = "all"
    gps: str = "all"
    channel_band: str = "all"
    client_aps: str = "all"
    bt_category: str = "All"
    bt_radio: str = "all"
    target_id: str = ""


def record_matches(
    kind: str,
    record: dict[str, Any],
    filters: OfflineFilters,
    *,
    target_store=None,
) -> bool:
    if target_store is not None and not offline_record_matches_target_filter(
        target_store, kind, record, filters.target_id,
    ):
        return False
    if kind == "aps":
        return _matches_ap(record, filters)
    if kind == "clients":
        return _matches_client(record, filters)
    return _matches_bluetooth(record, filters)


def _matches_ap(record: dict[str, Any], filters: OfflineFilters) -> bool:
    if not _tri_state(filters.gps, _record_has_gps(record)):
        return False
    if not _tri_state(filters.ap_clients, bool(record.get("clients"))):
        return False
    wps = record.get("wps") or {}
    wps_on = bool(wps.get("enabled"))
    if not _tri_state(filters.wps, wps_on):
        return False
    if filters.channel_band != "all":
        band = _channel_band(record.get("channel"))
        if band != filters.channel_band:
            return False
    if not _matches_encryption(filters.encryption, record):
        return False
    bssid = str(record.get("bssid", ""))
    clients = " ".join(
        str(item.get("client_mac", ""))
        for item in (record.get("clients") or [])
        if isinstance(item, dict)
    )
    searchable = " ".join(filter(None, (
        record.get("ssid"),
        bssid,
        vendor_for_mac(bssid),
        record.get("encryption"),
        record.get("country_code"),
        f"ch{record.get('channel')}" if record.get("channel") is not None else "",
        clients,
        _identity_blob(record.get("identity_evidence")),
    )))
    return text_matches(filters.text, bssid, searchable)


def _matches_client(record: dict[str, Any], filters: OfflineFilters) -> bool:
    if not _tri_state(filters.gps, _record_has_gps(record)):
        return False
    ap_count = int(record.get("access_point_count") or 0)
    if not _tri_state(filters.client_aps, ap_count > 0):
        return False
    mac = str(record.get("client_mac", ""))
    aps = " ".join(
        " ".join(filter(None, (
            str(item.get("ssid") or ""),
            str(item.get("bssid") or ""),
        )))
        for item in (record.get("access_points") or [])
        if isinstance(item, dict)
    )
    searchable = " ".join(filter(None, (
        mac,
        vendor_for_mac(mac),
        aps,
    )))
    return text_matches(filters.text, mac, searchable)


def _matches_bluetooth(record: dict[str, Any], filters: OfflineFilters) -> bool:
    if filters.bt_category != "All":
        protocol = record.get("protocol") or {}
        analysis = record.get("analysis") or {}
        category = str(
            protocol.get("category")
            or analysis.get("classification", {}).get("category")
            or "",
        )
        if category != filters.bt_category:
            return False
    radios = {str(item) for item in (record.get("radio_types") or [])}
    if filters.bt_radio == "ble" and radios != {"BLE"}:
        return False
    if filters.bt_radio == "bt" and radios != {"BT"}:
        return False
    if filters.bt_radio == "both" and not ({"BLE", "BT"} <= radios):
        return False
    identifier = str(record.get("identifier", ""))
    protocol = record.get("protocol") or {}
    searchable = " ".join(filter(None, (
        record.get("name"),
        identifier,
        record.get("manufacturer"),
        record.get("address_type"),
        protocol.get("type"),
        protocol.get("category"),
        " ".join(str(uuid) for uuid in (record.get("service_uuids") or [])),
        " ".join(str(item) for item in (record.get("radio_types") or [])),
    )))
    return text_matches(filters.text, identifier, searchable)


def _matches_encryption(filter: EncryptionFilter, record: dict[str, Any]) -> bool:
    if filter is EncryptionFilter.ALL:
        return True
    security = record.get("security") or {}
    akms = security.get("akms") or []
    if filter is EncryptionFilter.ENTERPRISE:
        return any(
            str(akm).startswith("EAP") or str(akm).startswith("FT-EAP")
            for akm in akms
        )
    bucket = encryption_type_from_record(record)
    return bucket in _OFFLINE_ENC_TYPES[filter]


def _identity_blob(evidence: Any) -> str:
    if not isinstance(evidence, list):
        return ""
    parts: list[str] = []
    for item in evidence:
        if isinstance(item, dict) and item.get("value"):
            parts.append(str(item["value"]))
    return " ".join(parts)


_BT_CATEGORIES = (
    "All", "Audio", "Wearable", "Input", "Beacon", "Health",
    "Phone", "Computer", "Network", "Sensor", "Display",
    "Appliance", "Vehicle", "Ambiguous", "Other", "Unknown",
)


class OfflineFilterBar(Horizontal):
    """Tab-specific filters above the offline history tables."""

    ALLOW_SELECT = False

    DEFAULT_CSS = """
    OfflineFilterBar {
        height: auto;
        padding: 0 1;
        margin-top: 1;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    OfflineFilterBar > Select {
        height: 1;
        min-height: 1;
        max-height: 1;
        margin-right: 1;
        text-wrap: nowrap;
    }
    OfflineFilterBar > #offline-filter-encryption { width: 14; }
    OfflineFilterBar > #offline-filter-wps { width: 10; }
    OfflineFilterBar > #offline-filter-ap-clients { width: 14; }
    OfflineFilterBar > #offline-filter-channel { width: 11; }
    OfflineFilterBar > #offline-filter-gps { width: 10; }
    OfflineFilterBar > #offline-filter-client-aps { width: 15; }
    OfflineFilterBar > #offline-filter-bt-category { width: 14; }
    OfflineFilterBar > #offline-filter-bt-radio { width: 12; }
    OfflineFilterBar > #offline-filter-target { width: 18; }
    OfflineFilterBar > Input { width: 1fr; min-width: 16; }
    """

    BINDINGS = [Binding("escape", "leave", "", show=False)]

    class FilterChanged(Message):
        def __init__(self, filters: OfflineFilters) -> None:
            super().__init__()
            self.filters = filters

    def __init__(self) -> None:
        super().__init__(id="offline-filters")
        self._kind = "aps"
        self.border_title = "SEARCH"

    def compose(self) -> ComposeResult:
        yield Select(
            [(f.value, f) for f in EncryptionFilter],
            value=EncryptionFilter.ALL,
            allow_blank=False,
            compact=True,
            id="offline-filter-encryption",
        )
        yield Select(
            [("Any WPS", "all"), ("WPS only", "yes"), ("No WPS", "no")],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-wps",
        )
        yield Select(
            [("Any client", "all"), ("Has clients", "yes"), ("No clients", "no")],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-ap-clients",
        )
        yield Select(
            [("Any band", "all"), ("2.4 GHz", "2.4"), ("5 GHz", "5"), ("6 GHz", "6")],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-channel",
        )
        yield Select(
            [("Any GPS", "all"), ("Has GPS", "yes"), ("No GPS", "no")],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-gps",
        )
        yield Select(
            [("Any APs", "all"), ("Associated", "yes"), ("Unassociated", "no")],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-client-aps",
        )
        yield Select(
            [(category, category) for category in _BT_CATEGORIES],
            value="All",
            allow_blank=False,
            compact=True,
            id="offline-filter-bt-category",
        )
        yield Select(
            [
                ("Any radio", "all"), ("BLE only", "ble"), ("Classic only", "bt"),
                ("BLE + BT", "both"),
            ],
            value="all",
            allow_blank=False,
            compact=True,
            id="offline-filter-bt-radio",
        )
        yield Select(
            build_target_select_options(None),
            value="",
            allow_blank=False,
            compact=True,
            id="offline-filter-target",
        )
        yield Input(placeholder="SSID, BSSID, vendor…", compact=True, id="offline-filter-text")

    def on_mount(self) -> None:
        store = getattr(self.app, "target_store", None)
        refresh_target_select(self.query_one("#offline-filter-target", Select), store)

    def refresh_target_options(self) -> None:
        store = getattr(self.app, "target_store", None)
        refresh_target_select(self.query_one("#offline-filter-target", Select), store)

    def set_kind(self, kind: str) -> None:
        self._kind = kind
        self._update_visibility()
        placeholders = {
            "aps": "SSID, BSSID, vendor, channel, client MAC…",
            "clients": "client MAC, vendor, associated SSID or BSSID…",
            "bluetooth": "name, address, manufacturer, service UUID…",
        }
        self.query_one("#offline-filter-text", Input).placeholder = placeholders[kind]
        titles = {
            "aps": "AP SEARCH",
            "clients": "CLIENT SEARCH",
            "bluetooth": "BT / BLE SEARCH",
        }
        self.border_title = titles[kind]
        self._emit()

    def focus_text(self) -> None:
        self.query_one("#offline-filter-text", Input).focus()

    def action_leave(self) -> None:
        from wifit3.ui.screens.offline import OfflineDatabaseView

        if isinstance(self.screen, OfflineDatabaseView):
            self.screen._table(self.screen._active).focus()

    def on_input_submitted(self) -> None:
        self.action_leave()

    def on_input_changed(self) -> None:
        self._emit()

    def on_select_changed(self) -> None:
        self._emit()

    def _update_visibility(self) -> None:
        ap = self._kind == "aps"
        client = self._kind == "clients"
        bt = self._kind == "bluetooth"
        self.query_one("#offline-filter-encryption", Select).display = ap
        self.query_one("#offline-filter-wps", Select).display = ap
        self.query_one("#offline-filter-ap-clients", Select).display = ap
        self.query_one("#offline-filter-channel", Select).display = ap
        self.query_one("#offline-filter-gps", Select).display = ap or client
        self.query_one("#offline-filter-client-aps", Select).display = client
        self.query_one("#offline-filter-bt-category", Select).display = bt
        self.query_one("#offline-filter-bt-radio", Select).display = bt

    def _emit(self) -> None:
        self.post_message(self.FilterChanged(self._current_filters()))

    def _current_filters(self) -> OfflineFilters:
        return OfflineFilters(
            text=self.query_one("#offline-filter-text", Input).value,
            encryption=self.query_one("#offline-filter-encryption", Select).value,
            wps=str(self.query_one("#offline-filter-wps", Select).value),
            ap_clients=str(self.query_one("#offline-filter-ap-clients", Select).value),
            gps=str(self.query_one("#offline-filter-gps", Select).value),
            channel_band=str(self.query_one("#offline-filter-channel", Select).value),
            client_aps=str(self.query_one("#offline-filter-client-aps", Select).value),
            bt_category=str(self.query_one("#offline-filter-bt-category", Select).value),
            bt_radio=str(self.query_one("#offline-filter-bt-radio", Select).value),
            target_id=str(self.query_one("#offline-filter-target", Select).value or ""),
        )

    def current_filters(self) -> OfflineFilters:
        return self._current_filters()
