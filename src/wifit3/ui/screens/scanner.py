import asyncio
import copy
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Set

from textual import work
from textual._two_way_dict import TwoWayDict
from textual.app import ComposeResult, RenderResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import Reactive
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, RichLog, Static
from textual.widgets._header import HeaderClock, HeaderIcon, HeaderTitle
from textual.widgets.data_table import CellKey, ColumnKey, RowKey
from rich.markup import escape
from rich.text import Text

from ..selectable_rich_log import SelectableRichLog

from wifit3.campaigns import treelog
from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.open_probe_ap import OpenProbeApCampaign
from wifit3.campaigns.pbc import PbcWatcher, WpsPbcCapture
from wifit3.campaigns.wps.registrar import PinResult
from wifit3.dot11.ie import (
    beacon_rsn_ie,
    compatible_wpa2_profile_ies,
    force_psk_akm,
)
from wifit3.id import oui_db, vendor_for_mac
from wifit3.persist.config import Config
from wifit3.persist.rsn_profiles import load_scan_rsn_profiles
from wifit3.persist.targets import SavedTarget, TargetStoreError
from wifit3.models import AccessPoint, Client, IdKey, IdSource
from wifit3.targeting import TargetCandidate, ap_candidate, client_candidate
from wifit3.wlan.enterprise_risk import enterprise_findings
from wifit3.crack.handshake import pmkid_crackable
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.ui.signal_bar import dbm_style
from wifit3.ui.scan_export import export_scan_snapshot
from wifit3.ui.screens.confirm_active import ConfirmActiveActionModal

from ..capture_events import (
    CAPTURE_TOAST_TITLES, DECLOAK_METHOD_LABELS, CaptureEvent, CaptureEventDetector, CaptureKind,
)
from .. import focus_model as fm
from ..encryption_format import EncryptionType, format_encryption_markup, wep_key_ascii
from wifit3.wlan.channels import band_ranges

from .channel_filter import ChannelFilterDialog
from .filter import EncryptionFilter, FilterBar, ScanFilter
from .new_target import NewTargetModal, NewTargetResult
from .open_probe_modal import OpenProbeSsidModal

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


STALE_DURATION_S = 10.0  # Seconds without a beacon before an AP row is dimmed.
_AP_MFR_MAX = 28
_CLIENT_MFR_MAX = 36
_INFRASTRUCTURE_PREFIX = "infrastructure:"


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _format_age(seconds: int) -> str:
    if seconds < 1:
        return "now"
    if seconds < 60:
        return f"{seconds}s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{remainder:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _is_local_mac(mac: str) -> bool:
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _ssid_infrastructures(
    access_points: list[AccessPoint],
) -> dict[str, list[AccessPoint]]:
    grouped: dict[str, list[AccessPoint]] = {}
    for ap in access_points:
        if not ap.ssid or ap.decloak_method == "history" or ap.is_own_fake:
            continue
        grouped.setdefault(ap.ssid.casefold(), []).append(ap)
    return {ssid: members for ssid, members in grouped.items() if len(members) > 1}



@dataclass(slots=True)
class _APRowState:
    signal: int
    beacons: int
    last_seen: int
    clients: int
    is_stale: bool
    flash: bool = False
    wps: bool = False
    wps_locked: bool = False
    ssid: Optional[str] = None
    chips_markup: str = ""
    identity: str = ""
    channel: int = 0
    encryption: str = ""
    manufacturer: str = ""
    stations: str = ""
    is_target: bool = False
    infrastructure_signature: tuple = ()


@dataclass(slots=True)
class _ClientRowState:
    manufacturer: str
    bssid: str
    ssid: str
    signal: int
    packets: int
    last_seen: int
    probes: str
    is_target: bool = False


def device_scan_summary(members) -> Optional[str]:
    """The scanning pool as a log line: 'N devices: CHIP (2+5G)', 2.4 GHz cyan, 5 GHz green."""
    if not members:
        return None
    tags = []
    for m in members:
        lo = any(c <= 14 for c in m.supported_channels)
        hi = any(c > 14 for c in m.supported_channels)
        bands = []
        if lo:
            bands.append("[bold cyan]2[/]" if hi else "[bold cyan]2G[/]")
        if hi:
            bands.append("[bold green]5G[/]")
        tags.append(f"[bold]{m.chipset}[/] ({'+'.join(bands)})")
    noun = "device" if len(members) == 1 else "devices"
    return f"Scanning with [bold cyan]{len(members)}[/] {noun}: {', '.join(tags)}"


class _ChannelReadout(HeaderClock):
    """Header right slot: active sort and live hopped channels."""
    DEFAULT_CSS = "_ChannelReadout { width: auto; }"
    # layout=True so a change re-sizes this auto-width slot; a plain repaint
    # leaves it 0-wide until the next resize.
    channels: Reactive[str] = Reactive("", layout=True)

    def _on_mount(self, event) -> None:
        self._poll()                          # populate before the first layout
        self.set_interval(0.25, self._poll)   # hop cadence

    def _poll(self) -> None:
        array = getattr(self.app, "array", None)
        members = array.members if array else []
        channel_text = " | ".join(f"CH:{m.current_channel:>3}" for m in members)
        sort_summary = getattr(self.screen, "_sort_summary", None)
        sort_text = sort_summary() if callable(sort_summary) else ""
        self.channels = "  |  ".join(part for part in (sort_text, channel_text) if part)

    def render(self) -> RenderResult:
        return Text(self.channels)


class _ScannerHeader(Header):
    """Header whose right slot shows the hopped channel(s) in place of the clock."""
    def compose(self) -> ComposeResult:
        yield HeaderIcon().data_bind(Header.icon)
        yield HeaderTitle()
        yield _ChannelReadout()


class _APScanTable(DataTable):
    """Scanner table with stable column sizing and deterministic row sorting."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    SSID_MIN_WIDTH: int = 20
    _suppress_scroll: bool = False

    def add_column(
        self,
        label: Any,
        *,
        width: Optional[int] = None,
        key: Optional[str] = None,
        default: Any = None,
    ) -> ColumnKey:
        col_key = super().add_column(label, width=width, key=key, default=default)
        if (key == "ssid" or col_key.value == "ssid") and width is None:
            col = self.columns.get(col_key)
            if col and col.content_width < self.SSID_MIN_WIDTH:
                col.content_width = self.SSID_MIN_WIDTH
        return col_key

    def _update_dimensions(self, new_rows: Iterable[RowKey]) -> None:
        col = self.columns.get(ColumnKey("ssid"))
        if col and col.content_width < self.SSID_MIN_WIDTH:
            col.content_width = self.SSID_MIN_WIDTH
        super()._update_dimensions(new_rows)
        if col and col.content_width < self.SSID_MIN_WIDTH:
            col.content_width = self.SSID_MIN_WIDTH

    def _update_column_widths(self, updated_cells: Set[CellKey]) -> None:
        super()._update_column_widths(updated_cells)
        col = self.columns.get(ColumnKey("ssid"))
        if col and col.content_width < self.SSID_MIN_WIDTH:
            col.content_width = self.SSID_MIN_WIDTH

    def _scroll_cursor_into_view(self, animate: bool = False) -> None:
        if self._suppress_scroll:
            return
        super()._scroll_cursor_into_view(animate=animate)

    def pin_cursor_row(self, row: int) -> None:
        """Move the highlight with its selected key without moving the viewport."""
        self._suppress_scroll = True
        self.move_cursor(row=row, animate=False)
        self.call_after_refresh(self._release_scroll)

    def _release_scroll(self) -> None:
        self._suppress_scroll = False

    def sort_aps(
        self,
        sort_key: str,
        key_func: Callable[[str, Any], Any],
        reverse: bool,
        *,
        child_parents: dict[str, str] | None = None,
        keep_together: dict[str, str] | None = None,
    ) -> bool:
        """Sort rows, keep expanded infrastructures contiguous, and pin guesses.

        ``keep_together`` maps a row key to a group id. Members of a group stay
        in their relative sort order, anchored where the lead member sorted.
        ``child_parents`` then places each child immediately after its parent,
        so a hidden guess stays under the sibling or collapsed group that
        supplied its displayed SSID.
        """
        ordered_rows = sorted(
            self._data.items(),
            key=lambda r: key_func(r[0].value, r[1].get(sort_key)),
            reverse=reverse,
        )
        ordered_keys = [row_key for row_key, _ in ordered_rows]
        if keep_together:
            members_by_group: dict[str, list[RowKey]] = {}
            for key in ordered_keys:
                group_id = keep_together.get(key.value)
                if group_id:
                    members_by_group.setdefault(group_id, []).append(key)
            emitted: set[str] = set()
            clustered: list[RowKey] = []
            for key in ordered_keys:
                group_id = keep_together.get(key.value)
                if not group_id:
                    clustered.append(key)
                    continue
                if group_id in emitted:
                    continue
                emitted.add(group_id)
                clustered.extend(members_by_group[group_id])
            ordered_keys = clustered
        if child_parents:
            by_value = {key.value: key for key in ordered_keys}
            children: dict[str, list[RowKey]] = {}
            for key in ordered_keys:
                parent = child_parents.get(key.value)
                if parent in by_value and parent != key.value:
                    children.setdefault(parent, []).append(key)
            child_keys = {key for values in children.values() for key in values}
            grouped: list[RowKey] = []
            for key in ordered_keys:
                if key in child_keys:
                    continue
                grouped.append(key)
                grouped.extend(children.get(key.value, ()))
            ordered_keys = grouped
        if ordered_keys == list(self._row_locations):
            return False
        self._row_locations = TwoWayDict(
            {row_key: idx for idx, row_key in enumerate(ordered_keys)}
        )
        self._update_count += 1
        self.refresh()
        return True


class ScannerView(Screen):
    """The main AP scanning list screen."""

    app: "WifiteApp"

    CSS = """
    #open-probe-active {
        height: 1;
        display: none;
        content-align: center middle;
        color: $error;
        text-style: bold blink;
    }
    """

    BINDINGS = [
        Binding("escape", "go_back", "Devices", show=True),
        Binding("c", "change_channel", "Channel Lock", show=True),
        Binding("e", "focus_encryption", "Encryption", show=True),
        Binding("s", "cycle_sort", "Sort Col", show=True),
        Binding("o", "toggle_sort_dir", "Sort Asc/Desc", show=True),
        Binding("p", "toggle_pause", "Pause", show=True),
        Binding("f", "focus_filter", "Filter", show=True),
        Binding("/", "focus_filter", "Filter", show=False),
        Binding("l", "toggle_log", "Toggle Log", show=True),
        Binding("t", "toggle_view", "APs/Clients", show=True),
        Binding("i", "toggle_infrastructure", "Infrastructure", show=True),
        Binding("n", "new_target", "New Target", show=True),
        Binding("a", "open_probe_ap", "Probe Honeypot", show=True),
        Binding("v", "open_vault", "Vault", show=True),
        Binding("x", "export_scan", "Export", show=True),
        Binding("home", "scroll_home", "Top", show=False, priority=True),
        Binding("end", "scroll_end", "Bottom", show=False, priority=True),
        Binding("g", "scroll_home", "Top", show=False, priority=True),
        Binding("G", "scroll_end", "Bottom", show=False, priority=True),
    ]

    # (column_key, display_label). Order here = on-screen order.
    _COLUMNS = [
        ("ssid", "SSID"),
        ("channel", "CH"),
        ("signal", "POWER"),
        ("beacons", "🥓"),
        ("last_seen", "SEEN / LEFT"),
        ("clients", "💻"),
        ("encryption", "ENCRYPT"),
        ("wps", "WPS"),
        ("identity", "VENDOR/ID"),
        ("mfr", "AP MFR"),
        ("stations", "CLIENT MFR"),
    ]

    _CLIENT_COLUMNS = [
        ("ssid", "CONNECTED NETWORK"),
        ("client", "CLIENT"),
        ("signal", "POWER"),
        ("packets", "PKTS"),
        ("last_seen", "SEEN"),
        ("manufacturer", "MANUFACTURER"),
        ("probes", "PROBE REQUESTS"),
    ]

    # Columns whose values are right-aligned in display.
    _RIGHT_ALIGNED = {
        "ssid", "channel", "signal", "beacons", "last_seen", "clients", "packets",
    }

    # Columns whose values are numeric for sorting.
    _NUMERIC_COLS = {"channel", "signal", "beacons", "last_seen", "clients"}

    # How long to flash the 🥓 cell when a beacon arrives.
    BEACON_FLASH_S = 0.2

    def __init__(self):
        super().__init__()
        self.ap_cache: Dict[str, AccessPoint] = {}
        self._refresh_timer = None
        self._sort_idx = 2         # Default to POWER
        self._sort_reverse = True  # Descending
        self._last_sort_time: float = 0.0
        self._channel_filter: Optional[List[int]] = None
        self._scan_filter: ScanFilter = ScanFilter()
        self._events = CaptureEventDetector(granular_eapol=False)
        # Per-BSSID prev-beacon-count + flash-deadline for "beacon arrived"
        # cell highlight.
        self._prev_beacons: Dict[str, int] = {}
        self._beacon_flash_until: Dict[str, float] = {}
        # Per-BSSID dynamic row state.
        self._row_states: Dict[str, _APRowState] = {}
        # WPS PBC auto-invade. ON by default. The enabled flag lives on the app
        # (app.pbc_enabled). Watcher + capturing serialization stay Scanner-local.
        self._pbc_watcher = PbcWatcher()
        self._pbc_capturing = False          # serialize: one invade at a time
        self._oui_generation = -1
        self._oui_request = 0
        self._station_labels: Dict[str, str] = {}
        self._view_mode = "aps"
        self._ap_sort_state = (self._sort_idx, self._sort_reverse)
        self._client_sort_state = (2, True)
        self._client_row_states: Dict[str, _ClientRowState] = {}
        self._client_cache: Dict[str, Client] = {}
        self._paused = False
        self._target_navigation_pending = False
        self._open_probe_campaign: OpenProbeApCampaign | None = None
        self._open_probe_event_index = 0
        self._open_probe_saved_clients: set[str] = set()
        self._infrastructure_members: dict[str, tuple[AccessPoint, ...]] = {}
        self._expanded_infrastructures: set[str] = set()
        self._expanded_member_ssids: dict[str, str] = {}
        self._secondary_member_bssids: set[str] = set()

    # ----- Compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        yield _ScannerHeader()
        yield Static("", id="open-probe-active")
        array = self.app.array
        supported = list(array.supported_channels) if array else []
        with Vertical():
            yield FilterBar(supported)
            table = _APScanTable(cursor_type="row", id="ap-table")
            for key, label in self._COLUMNS:
                # Reserve 2 chars in every header to account for sort indicator
                table.add_column(label + "  ", key=key, width=13 if key == "last_seen" else None)
            yield table
            yield SelectableRichLog(id="system-log", markup=True, highlight=True)
        yield GlobalJobTracker()
        yield Footer()

    async def on_mount(self) -> None:
        log = self.query_one("#system-log", RichLog)
        scanner_sort = "identity" if Config.scanner_sort in ("vendor", "brand") else Config.scanner_sort
        self._sort_idx = next(
            (i for i, (key, _label) in enumerate(self._COLUMNS) if key == scanner_sort), 2)
        self._sort_reverse = Config.scanner_sort_reverse
        self._update_column_headers()
        self.query_one("#ap-table", DataTable).focus()
        array = self.app.array

        log.write(treelog.header("Scanner initialized"))
        rows: List[str] = []
        summary = self.app.vault.summary()
        if summary:
            rows.append(f"Existing [bold]{Config.captures_dir}/[/bold]: {summary}")
        if array:
            device_line = device_scan_summary(array.members)
            if device_line:
                rows.append(device_line)
        else:
            rows.append("[yellow]No active interface[/yellow]")
        for i, row in enumerate(rows):
            log.write(treelog.leaf(row) if i == len(rows) - 1 else treelog.branch(row))

        if array:
            # 15 FPS in-place value updates and sort refreshes.
            self._refresh_timer = self.set_interval(1 / 15, self.refresh_table)
            self._pbc_timer = self.set_interval(1.0, self._poll_pbc)
            self._log_pbc_status()  # Auto-invade is ON by default

        if "PYTEST_CURRENT_TEST" not in os.environ:
            self._schedule_oui_load(False)

    async def on_screen_resume(self) -> None:
        # Restart channel hopper
        array = self.app.array
        if not array:
            return
        await array.start_hopping(
            channels=self._channel_filter, interval=0.25
        )

    # ----- Column header / sort indicator ------------------------------------

    def _active_columns(self) -> list[tuple[str, str]]:
        return self._CLIENT_COLUMNS if self._view_mode == "clients" else self._COLUMNS

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        if self._view_mode == "clients" and action == "toggle_infrastructure":
            return False
        if self._view_mode != "clients" and action == "open_probe_ap":
            return False
        return True

    def _sort_summary(self) -> str:
        key, label = self._active_columns()[self._sort_idx]
        label = {"beacons": "BEACONS", "clients": "CLIENTS"}.get(key, label)
        direction = ">" if self._sort_reverse else "<"
        return f"Sorted: {label} ({direction})"

    def _announce_sort(self) -> None:
        key, label = self._active_columns()[self._sort_idx]
        label = {"beacons": "BEACONS", "clients": "CLIENTS"}.get(key, label)
        direction = "descending" if self._sort_reverse else "ascending"
        self.notify(f"Sorted by {label} {direction}", title="Sort changed")
        self.query_one(_ChannelReadout)._poll()

    def _update_column_headers(self) -> None:
        table = self.query_one("#ap-table", DataTable)
        columns = self._active_columns()
        sort_key, _ = columns[self._sort_idx]
        arrow = "▼" if self._sort_reverse else "▲"

        for key, base_label in columns:
            is_sorted = key == sort_key
            if key in self._RIGHT_ALIGNED:
                # Right-align column header to rows
                prefix = f"{arrow} " if is_sorted else "  "
                label = Text(prefix + base_label, justify="right")
            else:
                # Left-aligned text columns: arrow trails the label.
                suffix = f" {arrow}" if is_sorted else "  "
                label = Text(base_label + suffix, justify="left")
            if key in table.columns:
                table.columns[key].label = label
        table.refresh()

    # ----- Per-tick refresh --------------------------------------------------

    def refresh_table(self) -> None:
        if not self.app.array:
            return
        self._poll_open_probe_campaign()
        array = self.app.array
        self._maybe_lock_target(array)
        if self._paused:
            return
        table = self.query_one("#ap-table", DataTable)
        self._theme_fg = self.app.theme_variables.get("foreground", "#ffffff")

        if self._view_mode == "clients":
            self._refresh_client_table(array, table)
            return

        self._evict_expired_aps()
        self._sync_oui_generation()
        client_counts, self._station_labels = self._station_columns()

        now = time.time()
        observed: list[AccessPoint] = []
        for ap in array.get_access_points(include_eviltwin=False):
            guessed_ssid = (
                self._best_named_sibling_ssid(ap)
                if self._scan_filter.text and ap.ssid is None
                else None
            )
            if not ap.is_own_fake and not self._scan_filter.matches(ap, ssid=guessed_ssid):
                if ap.bssid in self.ap_cache:
                    self._forget_row(ap.bssid, drop_from_array=False)
                continue
            if self._ap_has_expired(self._ap_row_age(ap, now)):
                continue
            observed.append(ap)
            self._drain_capture_events(ap, array.forged_macs)

        displayed = self._grouped_access_points(observed, client_counts)
        displayed_keys = {ap.bssid for ap in displayed}
        for row_key in set(self._row_states) - displayed_keys:
            self._forget_row(row_key, drop_from_array=False)

        for ap in displayed:
            guessed_ssid = (
                self._best_named_sibling_ssid(ap)
                if self._scan_filter.text and ap.ssid is None
                else None
            )
            if not self._scan_filter.matches(ap, ssid=guessed_ssid):
                if ap.bssid in self.ap_cache:
                    self._forget_row(ap.bssid, drop_from_array=False)
                continue

            age = self._ap_row_age(ap, now)
            if self._ap_has_expired(age):
                continue

            is_stale = age > STALE_DURATION_S
            n_cli = client_counts.get(ap.bssid, 0)

            # Beacon-arrival flash: bump the deadline when beacon count changes.
            prev = self._prev_beacons.get(ap.bssid)
            if prev is not None and ap.beacons > prev:
                self._beacon_flash_until[ap.bssid] = now + self.BEACON_FLASH_S
            self._prev_beacons[ap.bssid] = ap.beacons
            flash_bacon = now < self._beacon_flash_until.get(ap.bssid, 0.0)

            shown_beacons = ap.beacons
            chips_markup = self._ssid_chips_markup(ap)
            enc_markup = self._encryption_markup(ap)
            ident_summary = ap.identity.summary
            mfr = vendor_for_mac(ap.bssid) or ""
            stations = self._station_labels.get(ap.bssid, "")
            is_target = self._ap_is_saved_target(ap)
            infrastructure = self._infrastructure_members.get(ap.bssid)
            infrastructure_signature = (
                tuple(
                    (member.bssid, member.channel, member.encryption, member.wps)
                    for member in infrastructure
                )
                if infrastructure is not None else ()
            )

            prev_state = self._row_states.get(ap.bssid)
            if prev_state is None:
                self.ap_cache[ap.bssid] = ap
                self._row_states[ap.bssid] = _APRowState(
                    signal=ap.signal,
                    beacons=shown_beacons,
                    last_seen=int(age),
                    clients=n_cli,
                    is_stale=is_stale,
                    flash=flash_bacon,
                    wps=ap.wps,
                    wps_locked=ap.wps_locked,
                    ssid=ap.ssid,
                    chips_markup=chips_markup,
                    identity=ident_summary,
                    channel=ap.channel,
                    encryption=enc_markup,
                    manufacturer=mfr,
                    stations=stations,
                    is_target=is_target,
                    infrastructure_signature=infrastructure_signature,
                )
                row_cells = [
                    self._render_target_cell(
                        ap, col_k, is_stale, n_cli=n_cli,
                        flash_bacon=flash_bacon, shown_beacons=shown_beacons,
                    )
                    for col_k, _ in self._COLUMNS
                ]
                table.add_row(*row_cells, key=ap.bssid)
            else:
                self.ap_cache[ap.bssid] = ap

                # Decloak event: already logged here.
                if not prev_state.ssid and ap.ssid:
                    self._write_log(
                        Text.from_markup(
                            f"[bold yellow][*] Decloaked Hidden Network: "
                            f"{escape(ap.bssid)} -> {escape(ap.ssid)}[/bold yellow]",
                            emoji=False,
                        )
                    )

                if (
                    prev_state.is_stale != is_stale
                    or prev_state.is_target != is_target
                    or prev_state.infrastructure_signature != infrastructure_signature
                ):
                    prev_state.is_stale = is_stale
                    prev_state.is_target = is_target
                    prev_state.infrastructure_signature = infrastructure_signature
                    prev_state.signal = ap.signal
                    prev_state.beacons = shown_beacons
                    prev_state.last_seen = int(age)
                    prev_state.clients = n_cli
                    prev_state.flash = flash_bacon
                    prev_state.wps = ap.wps
                    prev_state.wps_locked = ap.wps_locked
                    prev_state.ssid = ap.ssid
                    prev_state.chips_markup = chips_markup
                    prev_state.identity = ident_summary
                    prev_state.manufacturer = mfr
                    prev_state.stations = stations
                    prev_state.channel = ap.channel
                    prev_state.encryption = enc_markup
                    for col_k, _ in self._COLUMNS:
                        cell = self._render_target_cell(
                            ap, col_k, is_stale, n_cli=n_cli,
                            flash_bacon=flash_bacon, shown_beacons=shown_beacons,
                        )
                        table.update_cell(ap.bssid, col_k, cell)
                else:
                    if prev_state.ssid != ap.ssid or prev_state.chips_markup != chips_markup:
                        prev_state.ssid = ap.ssid
                        prev_state.chips_markup = chips_markup
                        table.update_cell(
                            ap.bssid, "ssid", self._render_target_cell(ap, "ssid", is_stale), update_width=True,
                        )

                    if prev_state.channel != ap.channel:
                        prev_state.channel = ap.channel
                        table.update_cell(ap.bssid, "channel", self._render_target_cell(ap, "channel", is_stale))

                    if prev_state.signal != ap.signal:
                        prev_state.signal = ap.signal
                        table.update_cell(ap.bssid, "signal", self._render_target_cell(ap, "signal", is_stale))

                    if prev_state.beacons != shown_beacons or prev_state.flash != flash_bacon:
                        prev_state.beacons = shown_beacons
                        prev_state.flash = flash_bacon
                        table.update_cell(
                            ap.bssid, "beacons",
                            self._render_target_cell(ap, "beacons", is_stale, flash_bacon=flash_bacon, shown_beacons=shown_beacons),
                        )

                    if prev_state.last_seen != int(age):
                        prev_state.last_seen = int(age)
                        table.update_cell(
                            ap.bssid, "last_seen",
                            self._render_target_cell(ap, "last_seen", is_stale, age=age),
                        )

                    if prev_state.clients != n_cli:
                        prev_state.clients = n_cli
                        table.update_cell(
                            ap.bssid, "clients",
                            self._render_target_cell(ap, "clients", is_stale, n_cli=n_cli),
                        )

                    if prev_state.encryption != enc_markup:
                        prev_state.encryption = enc_markup
                        table.update_cell(ap.bssid, "encryption", self._render_target_cell(ap, "encryption", is_stale))

                    if prev_state.wps != ap.wps or prev_state.wps_locked != ap.wps_locked:
                        prev_state.wps = ap.wps
                        prev_state.wps_locked = ap.wps_locked
                        table.update_cell(ap.bssid, "wps", self._render_target_cell(ap, "wps", is_stale))

                    if prev_state.identity != ident_summary:
                        prev_state.identity = ident_summary
                        table.update_cell(ap.bssid, "identity", self._render_target_cell(ap, "identity", is_stale))

                    if prev_state.manufacturer != mfr:
                        prev_state.manufacturer = mfr
                        table.update_cell(ap.bssid, "mfr", self._render_target_cell(ap, "mfr", is_stale))

                    if prev_state.stations != stations:
                        prev_state.stations = stations
                        table.update_cell(ap.bssid, "stations", self._render_target_cell(ap, "stations", is_stale))

        if self._should_sort():
            self._apply_sort(scroll_to_cursor=False)
        else:
            self._sync_infrastructure_levels(table)

    def _grouped_access_points(
        self,
        access_points: list[AccessPoint],
        client_counts: dict[str, int],
    ) -> list[AccessPoint]:
        infrastructures = _ssid_infrastructures(access_points)
        active_keys = {
            f"{_INFRASTRUCTURE_PREFIX}{ssid}" for ssid in infrastructures
        }
        self._expanded_infrastructures.intersection_update(active_keys)
        self._infrastructure_members = {}
        self._expanded_member_ssids = {}
        displayed: list[AccessPoint] = []
        inserted: set[str] = set()

        for ap in access_points:
            ssid_key = ap.ssid.casefold() if ap.ssid else ""
            members = infrastructures.get(ssid_key)
            if members is None:
                displayed.append(ap)
                continue
            group_key = f"{_INFRASTRUCTURE_PREFIX}{ssid_key}"
            self._infrastructure_members[group_key] = tuple(members)
            if group_key in self._expanded_infrastructures:
                self._expanded_member_ssids[ap.bssid] = group_key
                displayed.append(ap)
                continue
            if group_key in inserted:
                continue
            inserted.add(group_key)
            displayed.append(
                self._aggregate_infrastructure(group_key, members, client_counts),
            )
        return displayed

    def _aggregate_infrastructure(
        self,
        group_key: str,
        members: list[AccessPoint],
        client_counts: dict[str, int],
    ) -> AccessPoint:
        strongest = max(members, key=lambda ap: ap.signal)
        aggregate = copy.copy(strongest)
        aggregate.bssid = group_key
        aggregate.beacons = sum(ap.beacons for ap in members)
        aggregate.first_seen = min(ap.first_seen for ap in members)
        aggregate.last_seen = max(ap.last_seen for ap in members)
        aggregate.signal_by_card = {"infrastructure": strongest.signal}
        aggregate.signal_history = {}
        aggregate.siblings = [ap.bssid for ap in members]
        aggregate.wps = any(ap.wps for ap in members)
        aggregate.wps_locked = aggregate.wps and all(
            ap.wps_locked for ap in members if ap.wps
        )
        encryptions = {
            ap.encryption for ap in members if ap.encryption
        }
        aggregate.encryption = (
            next(iter(encryptions)) if len(encryptions) == 1 else "Mixed"
        )
        countries = {ap.country_code for ap in members if ap.country_code}
        aggregate.country_code = next(iter(countries)) if len(countries) == 1 else None
        aggregate.decloak_method = None
        client_counts[group_key] = sum(
            client_counts.get(ap.bssid, 0) for ap in members
        )
        client_manufacturers = sorted({
            label
            for ap in members
            for label in self._station_labels.get(ap.bssid, "").split(" · ")
            if label
        })
        self._station_labels[group_key] = " · ".join(client_manufacturers)
        return aggregate

    def _refresh_client_table(self, array, table: DataTable) -> None:
        visible: set[str] = set()
        forged = array.forged_macs
        now = time.time()
        for client in list(array.clients.values()):
            if client.mac in forged:
                continue
            age = max(0.0, now - client.last_seen)
            if self._ap_has_expired(age):
                array.clients.pop(client.mac, None)
                continue
            ap = array.access_points.get(client.bssid) if client.bssid else None
            if not self._client_matches(client, ap):
                continue
            visible.add(client.mac)
            self._client_cache[client.mac] = client
            manufacturer = vendor_for_mac(client.mac) or ""
            bssid = client.bssid or ""
            ssid = ap.ssid if ap and ap.ssid else ""
            probes = ", ".join(sorted(client.probed_ssids))
            state = _ClientRowState(
                manufacturer=manufacturer,
                bssid=bssid,
                ssid=ssid,
                signal=client.signal,
                packets=client.packets,
                last_seen=int(age),
                probes=probes,
                is_target=self._is_saved_target("client", client.mac),
            )
            cells = self._client_cells(client, state)
            previous = self._client_row_states.get(client.mac)
            if previous is None:
                self._client_row_states[client.mac] = state
                table.add_row(*cells, key=client.mac)
            elif previous != state:
                self._client_row_states[client.mac] = state
                for (key, _label), cell in zip(self._CLIENT_COLUMNS, cells):
                    table.update_cell(client.mac, key, cell, update_width=True)

        for mac in set(self._client_row_states) - visible:
            self._client_row_states.pop(mac, None)
            self._client_cache.pop(mac, None)
            try:
                table.remove_row(mac)
            except Exception:
                pass
        if self._should_sort():
            self._apply_sort(scroll_to_cursor=False)

    def _client_matches(self, client: Client, ap: AccessPoint | None) -> bool:
        if client.signal < self._scan_filter.min_signal:
            return False
        if self._scan_filter.association == "connected" and not client.bssid:
            return False
        if self._scan_filter.association == "unassociated" and client.bssid:
            return False
        if self._scan_filter.encryption is not EncryptionFilter.ALL:
            if ap is None or not self._scan_filter.encryption.matches(ap):
                return False
        if self._scan_filter.wps is not None:
            if ap is None or ap.wps is not self._scan_filter.wps:
                return False
        query = self._scan_filter.text.lower().split()
        if not query:
            return True
        manufacturer = vendor_for_mac(client.mac) or ""
        values = " ".join((
            client.mac,
            manufacturer,
            client.bssid or "",
            ap.ssid if ap and ap.ssid else "",
            vendor_for_mac(ap.bssid) if ap else "",
            ap.country_code if ap and ap.country_code else "",
            *sorted(client.probed_ssids),
        )).lower()
        return all(token in values for token in query)

    def _client_cells(self, client: Client, state: _ClientRowState) -> list[Text]:
        fg = self._theme_fg
        network = Text(justify="right", no_wrap=True)
        if state.bssid:
            network.append(_clip(state.ssid, 20) if state.ssid else "‹hidden›", style=f"{fg} bold")
            network.append(f"  ·  {state.bssid}", style="dim")
        else:
            network.append("‹unassociated›", style="dim italic")
        identity = Text(no_wrap=True)
        if _is_local_mac(client.mac):
            identity.append("~ ", style="yellow bold")
        identity.append(client.mac, style=fg)
        probes = Text(no_wrap=True)
        for index, ssid in enumerate(sorted(client.probed_ssids)):
            if index:
                probes.append("  ·  ", style="dim")
            probes.append(_clip(ssid, 20), style=fg)
            observation = client.probe_observations.get(ssid)
            if observation is not None and observation.historical:
                probes.append(" [history]", style="yellow")
        if not client.probed_ssids:
            probes.append("·", style="dim")
        manufacturer = Text(
            _clip(state.manufacturer, 28) if state.manufacturer else "·",
            style=fg if state.manufacturer else "dim",
        )
        cells = [
            network,
            identity,
            Text(f"{state.signal} dBm", justify="right", style=dbm_style(state.signal)),
            Text(str(state.packets), justify="right", style=fg),
            Text(_format_age(state.last_seen), justify="right", style="dim"),
            manufacturer,
            probes,
        ]
        if state.last_seen > STALE_DURATION_S:
            for cell in cells:
                cell.stylize("dim")
        if state.is_target:
            cells[0] = Text("! ", style="bold red") + cells[0]
            for cell in cells:
                cell.stylize("bold red")
        return cells

    def _is_saved_target(self, kind: str, identifier: str) -> bool:
        store = getattr(self.app, "target_store", None)
        return store is not None and store.find("wifi", kind, identifier) is not None

    def _evict_expired_aps(self) -> None:
        if not self.app.array:
            return
        now = time.time()
        to_drop = [
            bssid for bssid, ap in self.ap_cache.items()
            if self._ap_has_expired(self._ap_row_age(ap, now))
        ]
        for bssid in to_drop:
            self._forget_row(bssid, drop_from_array=True)

    def _ap_row_age(self, ap: AccessPoint, now: float) -> float:
        return max(0.0, now - ap.last_seen)

    def _ap_has_expired(self, age: float) -> bool:
        expiry = Config.scanner_ap_expiry
        return expiry >= 0 and age >= expiry

    def _forget_row(self, bssid: str, *, drop_from_array: bool) -> None:
        """Drop the AP's row and caches; drop_from_array also evicts it and its clients from the registry."""
        if drop_from_array and self.app.array:
            self.app.array.access_points.pop(bssid, None)
            orphans = [
                mac for mac, c in self.app.array.clients.items()
                if c.bssid == bssid
            ]
            for mac in orphans:
                self.app.array.clients.pop(mac, None)
        self.ap_cache.pop(bssid, None)
        self._prev_beacons.pop(bssid, None)
        self._beacon_flash_until.pop(bssid, None)
        self._row_states.pop(bssid, None)
        try:
            self.query_one("#ap-table", DataTable).remove_row(bssid)
        except Exception:
            pass

    # ----- Cell construction -------------------------------------------------

    def _render_target_cell(
        self, ap: AccessPoint, col_key: str, is_stale: bool,
        n_cli: int = 0, flash_bacon: bool = False,
        shown_beacons: Optional[int] = None, age: Optional[float] = None,
    ) -> Text:
        if col_key == "ssid" and self._ap_is_saved_target(ap):
            cell = self._ssid_cell(ap, target=True)
            if is_stale:
                cell.stylize("dim")
            marked_cell = Text("! ", style="bold red", justify="right")
            marked_cell.append_text(cell)
            return marked_cell
        cell = self._render_cell(
            ap,
            col_key,
            is_stale,
            n_cli=n_cli,
            flash_bacon=flash_bacon,
            shown_beacons=shown_beacons,
            age=age,
        )
        return cell

    def _ap_is_saved_target(self, ap: AccessPoint) -> bool:
        members = self._infrastructure_members.get(ap.bssid)
        if members is not None:
            return any(self._is_saved_target("ap", member.bssid) for member in members)
        return self._is_saved_target("ap", ap.bssid)

    def _render_cell(
        self, ap: AccessPoint, col_key: str, is_stale: bool,
        n_cli: int = 0, flash_bacon: bool = False, shown_beacons: Optional[int] = None,
        age: Optional[float] = None,
    ) -> Text:
        """Build the Text renderable for a single column cell."""
        fg = self._theme_fg
        dim = "dim " if is_stale else ""
        infrastructure = self._infrastructure_members.get(ap.bssid)
        if col_key == "ssid":
            cell = self._ssid_cell(ap)
            if is_stale:
                cell.stylize("dim")
            return cell
        if col_key == "channel":
            if infrastructure is not None:
                channels = sorted({member.channel for member in infrastructure})
                return Text(
                    ",".join(str(channel) for channel in channels),
                    justify="right",
                    style=f"{dim}{fg}",
                )
            return Text(str(ap.channel), justify="right", style=f"{dim}{fg}")
        if col_key == "signal":
            return Text(f"{ap.signal} dBm", justify="right", style=dbm_style(ap.signal, dim=is_stale))
        if col_key == "beacons":
            count = ap.beacons if shown_beacons is None else shown_beacons
            style = f"{dim}{fg} bold" if flash_bacon else f"{dim}{fg}"
            return Text(str(count), justify="right", style=style)
        if col_key == "last_seen":
            seconds = int(self._ap_row_age(ap, time.time()) if age is None else age)
            expiry = Config.scanner_ap_expiry
            remaining = "∞" if expiry < 0 else _format_age(max(0, int(expiry - seconds)))
            return Text(
                f"{_format_age(seconds)} / {remaining}",
                justify="right",
                style=f"{dim}{fg}",
            )
        if col_key == "clients":
            return Text(str(n_cli) if n_cli else "", justify="right", style=f"{dim}{fg}")
        if col_key == "encryption":
            if infrastructure is not None and ap.encryption == "Mixed":
                return Text("Mixed", style=f"{dim}yellow")
            cell = Text.from_markup(self._encryption_markup(ap), emoji=False, style=fg)
            if is_stale:
                cell.stylize("dim")
            return cell
        if col_key == "wps":
            if infrastructure is not None:
                count = sum(member.wps for member in infrastructure)
                return Text(
                    f"WPS {count}/{len(infrastructure)}" if count else "",
                    style=f"{dim}{fg}",
                )
            if ap.wps:
                label = "WPS 🔒" if ap.wps_locked else "WPS"
                return Text(label, style=f"{dim}{fg}")
            return Text("", style=f"{dim}{fg}")
        if col_key == "identity":
            if infrastructure is not None:
                return Text(
                    f"Infrastructure · {len(infrastructure)} APs",
                    style=f"{dim}cyan",
                )
            return self._identity_cell(ap, is_stale)
        if col_key == "mfr":
            if infrastructure is not None:
                manufacturers = sorted({
                    vendor_for_mac(member.bssid)
                    for member in infrastructure
                    if vendor_for_mac(member.bssid)
                })
                return Text(
                    _clip(" · ".join(manufacturers), _AP_MFR_MAX),
                    style=f"{dim}{fg}",
                )
            return Text(_clip(vendor_for_mac(ap.bssid) or "", _AP_MFR_MAX), style=f"{dim}{fg}")
        if col_key == "stations":
            label = self._station_labels.get(ap.bssid, "")
            return Text(_clip(label, _CLIENT_MFR_MAX), style=f"{dim}{fg}")
        return Text("")

    def _encryption_markup(self, ap: AccessPoint) -> str:
        markup = format_encryption_markup(ap, muted=self._theme_fg)
        if EncryptionType.from_ap(ap) is EncryptionType.OPEN:
            # Align with weak WPA labels such as "WPA2 (PSK) !WEAK".
            return f"{markup}{' ' * (10 - len('OPEN'))} [bold red]!WEAK[/bold red]"
        members = self._infrastructure_members.get(ap.bssid, (ap,))
        highest = max(
            (
                finding.severity
                for member in members
                for finding in enterprise_findings(member)
            ),
            default=0,
        )
        return f"{markup} [bold red]!WEAK[/bold red]" if highest >= 3 else markup

    def _identity_cell(self, ap: AccessPoint, is_stale: bool = False) -> Text:
        if ap.is_own_fake:
            state = "ACTIVE" if ap.own_fake_active else "STOPPED"
            return Text(f"OUR HONEYPOT AP · {state}", style="bold red")
        fg = self._theme_fg
        dim = "dim " if is_stale else ""
        text = ap.identity.summary
        return Text(text, style=f"{dim}{fg}")

    # Cap the SSID+badges cell so the capture badges never overflow.
    _SSID_CELL_MAX = 32

    def _ssid_cell(self, ap: AccessPoint, target: bool = False) -> Text:
        """Badges plus confirmed, historical, or sibling-guessed SSID."""
        infrastructure = self._infrastructure_members.get(ap.bssid)
        if ap.is_own_fake:
            state = "ACTIVE" if ap.own_fake_active else "STOPPED"
            name = Text(f"◆ FAKE AP [{state}] · {ap.ssid}", style="bold red")
        elif infrastructure is not None:
            name = Text(
                f"▸ {ap.ssid} · {len(infrastructure)} APs",
                style="bold red" if target else "bold cyan",
            )
        elif ap.ssid:
            historical = ap.decloak_method == "history"
            name_style = (
                "bold red" if target
                else "bold yellow" if historical
                else f"{self._theme_fg} bold"
            )
            name = Text(f"{ap.ssid} [history]" if historical else ap.ssid, style=name_style)
            if ap.bssid in self._secondary_member_bssids:
                name = Text("└ ", style="dim cyan") + name
        else:
            sib = self._best_named_sibling_ssid(ap)
            name_style = "red bold" if target else "bold yellow" if sib else f"{self._theme_fg} italic"
            name = Text(f"{sib} [guess]" if sib else "<Hidden>", style=name_style)

        chips_markup = self._ssid_chips_markup(ap)  # ✗S, ✓HS, ✓PMK, ✓WEP, ✓WPS
        chips_text = Text.from_markup(chips_markup, emoji=False) if chips_markup else None
        reserved = 1 + chips_text.cell_len if chips_text else 0   # 1 = separator space
        name.truncate(max(1, self._SSID_CELL_MAX - reserved), overflow="ellipsis")
        if chips_text:
            out = Text(justify="right")
            out.append_text(chips_text)
            out.append(" ")
            out.append_text(name)
        else:
            out = name
            out.justify = "right"
        return out

    def _best_named_sibling_ssid(self, ap: AccessPoint) -> Optional[str]:
        """Guess the sibling SSID to display for a hidden AP."""
        return fm.best_named_sibling_ssid(ap, self.app.array)

    def _guess_child_parents(self) -> dict[str, str]:
        """Map each hidden guess to the visible row of its named sibling."""
        child_parents: dict[str, str] = {}
        array = self.app.array
        for ap in self.ap_cache.values():
            if ap.ssid or not ap.siblings or array is None:
                continue
            named = [
                array.access_points.get(bssid)
                for bssid in ap.siblings
            ]
            named = [
                sibling for sibling in named
                if sibling is not None and sibling.ssid
            ]
            if not named:
                continue
            parent = max(named, key=lambda sibling: sibling.beacons)
            child_parents[ap.bssid] = self._visible_guess_parent(parent)
        return child_parents

    def _visible_guess_parent(self, parent: AccessPoint) -> str:
        """Row key that currently stands for ``parent``.

        A collapsed infrastructure replaces the member BSSIDs with one group
        row. An expanded infrastructure shows the member itself.
        """
        if not parent.ssid:
            return parent.bssid
        group_key = f"{_INFRASTRUCTURE_PREFIX}{parent.ssid.casefold()}"
        if group_key not in self._infrastructure_members:
            return parent.bssid
        if group_key not in self._expanded_infrastructures:
            return group_key
        if parent.bssid in self._expanded_member_ssids:
            return parent.bssid
        for member in self._infrastructure_members.get(group_key, ()):
            if member.bssid in self.ap_cache:
                return member.bssid
        return parent.bssid

    def _sync_infrastructure_levels(self, table: DataTable) -> None:
        """Keep the first expanded member primary and the rest secondary."""
        seen_groups: set[str] = set()
        secondary: set[str] = set()
        for key in table._row_locations:
            group_key = self._expanded_member_ssids.get(key.value)
            if not group_key:
                continue
            if group_key in seen_groups:
                secondary.add(key.value)
            else:
                seen_groups.add(group_key)
        changed = (self._secondary_member_bssids ^ secondary) & set(
            self._expanded_member_ssids
        )
        self._secondary_member_bssids = secondary
        for bssid in changed:
            ap = self.ap_cache.get(bssid)
            state = self._row_states.get(bssid)
            if ap is None or state is None:
                continue
            table.update_cell(
                bssid,
                "ssid",
                self._render_target_cell(ap, "ssid", state.is_stale),
                update_width=True,
            )

    def _ssid_chips_markup(self, ap: AccessPoint) -> str:
        """Badges to the left of SSID for HS, PMK, WEP, WPS, silenced."""
        vault = self.app.vault
        has_hs  = vault.has_handshake(ap) or any(hs.is_complete for hs in ap.handshakes.values())
        has_pmk = vault.has_pmkid(ap) or any(hs.pmkid and pmkid_crackable(hs) for hs in ap.handshakes.values())
        has_wep = vault.has_wep_key(ap) or ap.wep_key is not None
        has_wps = vault.has_wps_psk(ap) or ap.wps_pbc_psk is not None
        silent = Config.is_silenced(ap.bssid)
        badges = [
            (silent, "[red]✗S[/red]"),
            (has_hs, "[green]✓HS[/green]"),
            (has_pmk, "[green]✓PMK[/green]"),
            (has_wep, "[green]✓WEP[/green]"),
            (has_wps, "[green]✓WPS[/green]"),
        ]
        return " ".join(text for cond, text in badges if cond)

    # ----- Capture-event logging ---------------------------------------------

    def _drain_capture_events(self, ap: AccessPoint, forged_macs) -> None:
        if Config.is_silenced(ap.bssid):
            return
        for ev in self._events.poll(ap, forged_macs=forged_macs):
            self._log_capture_event(ev, ap)

    def _log_capture_event(self, ev: CaptureEvent, ap: AccessPoint) -> None:
        ap_label = escape(ev.ssid or ev.bssid)
        client = escape(ev.client_mac)
        save_result = None
        if ev.kind == CaptureKind.HANDSHAKE:
            pair = ev.pair_label or "?"
            msg = (
                f"[bold green]✓ HANDSHAKE[/bold green] ({pair}) on "
                f"[bold cyan]{ap_label}[/bold cyan] from [bold]{client}[/bold]"
            )
            save_result = self.app.vault.save_handshake(ap, ev.client_mac)
        elif ev.kind == CaptureKind.UNCRACKABLE_HANDSHAKE:
            msg = (
                f"[bold yellow]● {escape(ev.value or '?')} 4-way[/bold yellow] on "
                f"[bold cyan]{ap_label}[/bold cyan] [dim](not crackable, -m 22000)[/dim]"
            )
        elif ev.kind == CaptureKind.PMKID:
            msg = (
                f"[bold green]✓ PMKID[/bold green] on "
                f"[bold cyan]{ap_label}[/bold cyan] from [bold]{client}[/bold]"
            )
            save_result = self.app.vault.save_pmkid(ap, ev.client_mac)
        elif ev.kind == CaptureKind.DECLOAK:
            # A ● header (not a ✓ win): a hidden SSID became visible, not a credential.
            method_label = DECLOAK_METHOD_LABELS.get(ev.method or "", ev.method or "?")
            self._write_log(Text.from_markup(treelog.header(
                f"[bold]Decloaked[/bold] [cyan]{escape(ev.bssid)}[/cyan] → "
                f"[green]{escape(ev.ssid or '')}[/green] "
                f"[dim]via {method_label}[/dim]"), emoji=False))
            return
        elif ev.kind == CaptureKind.WEP_KEY:
            msg = (f"[bold green]✓ WEP KEY[/bold green] on "
                   f"[bold cyan]{ap_label}[/bold cyan] = {escape(wep_key_ascii(ev.value or ''))}")
        elif ev.kind == CaptureKind.WPS_PIN:
            msg = (f"[bold green]✓ WPS PIN[/bold green] on "
                   f"[bold cyan]{ap_label}[/bold cyan] = {escape(ev.value or '')}")
        elif ev.kind == CaptureKind.WPS_PSK:
            msg = (f'[bold green]✓ WPS PSK[/bold green] on '
                   f'[bold cyan]{ap_label}[/bold cyan] = "{escape(ev.value or "")}"')
        elif ev.kind == CaptureKind.WPS_PBC:
            msg = (f'[bold green]✓ WPS PSK[/bold green] [dim](via PushButton)[/dim] on '
                   f'[bold cyan]{ap_label}[/bold cyan] = "{escape(ev.value or "")}"')
        else:
            return  # eapol events suppressed in scanner
        # Leading space aligns the ✓ win with the ● / ├─► / └─► tree log above it.
        self._write_log(Text.from_markup(f" {msg}", emoji=False))
        if save_result is not None:
            verb = "saved" if save_result.was_new else "already saved as"
            self._write_log(Text.from_markup(treelog.leaf(
                f"[dim]({verb} {escape(save_result.path.name)})[/dim]"), emoji=False))
        title = CAPTURE_TOAST_TITLES.get(ev.kind)
        if title:
            name = ev.ssid or ev.bssid
            if ev.kind == CaptureKind.WEP_KEY:
                self.notify(f"{name}: {wep_key_ascii(ev.value or '')}", title=title, timeout=6)
            else:
                pair = ev.pair_label or ("M1" if ev.kind == CaptureKind.PMKID else None)
                full_title = f"{title} ({pair})" if pair else title
                body = (f"[bold]{escape(name)}[/bold] on channel [bold]{ap.channel}[/bold] "
                        f"[dim bold](BSSID: {escape(ap.bssid)})[/dim bold]")
                self.notify(body, title=full_title, timeout=6)

    def _write_log(self, text) -> None:
        try:
            log = self.query_one("#system-log", RichLog)
        except Exception:
            return
        # Bypass RichLog's emojis (would turn :ab: / :cd: inside a BSSID into 🆎 / 💿).
        if isinstance(text, str):
            text = Text.from_markup(text, emoji=False)
        log.write(text)

    # ----- Sort --------------------------------------------------------------

    def _should_sort(self) -> bool:
        delay = Config.scanner_sort_delay
        if delay < 0:
            return False
        return (time.time() - self._last_sort_time) >= delay

    def _apply_sort(self, *, scroll_to_cursor: bool = True) -> None:
        """Re-sort while keeping the same selected BSSID/client highlighted."""
        self._last_sort_time = time.time()
        table = self.query_one("#ap-table", _APScanTable)
        if table.row_count == 0:
            return
        try:
            current_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            current_key = None
        if self._view_mode == "clients":
            self._apply_client_sort(table, current_key, scroll_to_cursor)
            return

        sort_key, _ = self._COLUMNS[self._sort_idx]
        reverse = self._sort_reverse

        def _key(bssid: str, val: Any) -> tuple:
            ap = self.ap_cache.get(bssid)
            sig = ap.signal if ap else -100
            sec_sig = sig if reverse else -sig

            if sort_key == "signal":
                state = self._row_states.get(bssid)
                cli = state.clients if state else 0
                sec_cli = cli if reverse else -cli
                sentinel = 1 if reverse else 0
                return (sentinel, sig, sec_cli, bssid)

            if sort_key == "wps":
                wps_rank = 0
                if ap and ap.wps:
                    wps_rank = 1 if ap.wps_locked else 2
                is_empty = (wps_rank == 0)
                sentinel = int(is_empty != reverse)
                return (sentinel, wps_rank, sec_sig, bssid)

            if sort_key == "ssid":
                name = (ap.ssid or "") if ap else ""
                is_empty = not name
                sentinel = int(is_empty != reverse)
                return (sentinel, name.lower(), sec_sig, bssid)

            if sort_key == "channel":
                ch = ap.channel if ap else 0
                sentinel = 1 if reverse else 0
                return (sentinel, ch, sec_sig, bssid)

            if sort_key == "beacons":
                bc = ap.beacons if ap else 0
                sentinel = 1 if reverse else 0
                return (sentinel, bc, sec_sig, bssid)

            if sort_key == "last_seen":
                state = self._row_states.get(bssid)
                age = state.last_seen if state else 0
                return (1 if reverse else 0, age, sec_sig, bssid)

            if sort_key == "clients":
                state = self._row_states.get(bssid)
                cli = state.clients if state else 0
                is_empty = (cli == 0)
                sentinel = int(is_empty != reverse)
                return (sentinel, cli, sec_sig, bssid)

            if sort_key == "encryption":
                enc = (ap.encryption or "") if ap else ""
                is_empty = not enc or enc.lower() == "unknown"
                sentinel = int(is_empty != reverse)
                return (sentinel, enc.lower(), sec_sig, bssid)

            if sort_key == "identity":
                ident = (ap.identity.summary or "") if ap else ""
                is_empty = not ident
                sentinel = int(is_empty != reverse)
                return (sentinel, ident.lower(), sec_sig, bssid)

            if isinstance(val, Text):
                val = val.plain
            s = str(val).strip() if val is not None else ""
            is_empty = not s
            sentinel = int(is_empty != reverse)
            return (sentinel, s.lower(), sec_sig, bssid)

        order_changed = table.sort_aps(
            sort_key, key_func=_key, reverse=reverse,
            child_parents=self._guess_child_parents(),
            keep_together=dict(self._expanded_member_ssids) or None,
        )
        self._restore_selected_key(table, current_key, order_changed, scroll_to_cursor)
        self._sync_infrastructure_levels(table)

    def _apply_client_sort(
        self, table: _APScanTable, current_key: RowKey | None, scroll_to_cursor: bool,
    ) -> None:
        sort_key, _ = self._CLIENT_COLUMNS[self._sort_idx]
        reverse = self._sort_reverse

        def _key(mac: str, val: Any) -> tuple:
            state = self._client_row_states.get(mac)
            if state is None:
                return (0, "", mac)
            values: dict[str, Any] = {
                "client": mac,
                "manufacturer": state.manufacturer,
                "ssid": state.ssid or state.bssid,
                "signal": state.signal,
                "packets": state.packets,
                "last_seen": state.last_seen,
                "probes": state.probes,
            }
            value = values[sort_key]
            is_empty = value == "" or value is None
            sentinel = int(is_empty != reverse)
            normalized = value.lower() if isinstance(value, str) else value
            return (sentinel, normalized, mac)

        order_changed = table.sort_aps(sort_key, key_func=_key, reverse=reverse)
        self._restore_selected_key(table, current_key, order_changed, scroll_to_cursor)

    @staticmethod
    def _restore_selected_key(
        table: _APScanTable,
        current_key: RowKey | None,
        order_changed: bool,
        scroll_to_cursor: bool,
    ) -> None:
        if current_key is None or not (order_changed or scroll_to_cursor):
            return
        try:
            row = table.get_row_index(current_key)
            if scroll_to_cursor:
                table.move_cursor(row=row, animate=False)
            else:
                table.pin_cursor_row(row)
        except Exception:
            pass

    # ----- Actions -----------------------------------------------------------

    def _sync_oui_generation(self) -> None:
        """Copy a freshly loaded oui.txt into AP identities and drop stale client fingerprints."""
        generation = oui_db.generation()
        if generation == self._oui_generation:
            return
        self._oui_generation = generation
        array = self.app.array
        if not array:
            return
        for ap in array.access_points.values():
            vendor = vendor_for_mac(ap.bssid)
            if vendor and ap.identity.get_source_value(IdKey.MANUFACTURER, IdSource.OUI) != vendor:
                ap.identity.set(IdSource.OUI, IdKey.MANUFACTURER, vendor)
        for client in array.clients.values():
            client.__dict__.pop("fingerprint", None)

    def _station_columns(self) -> tuple[dict[str, int], dict[str, str]]:
        """Client counts and manufacturer lists keyed by AP BSSID."""
        array = self.app.array
        counts: dict[str, int] = {}
        grouped: dict[str, list[tuple[str, str]]] = {}
        if not array:
            return counts, {}
        forged = array.forged_macs
        for client in array.clients.values():
            if not client.bssid or client.mac in forged:
                continue
            counts[client.bssid] = counts.get(client.bssid, 0) + 1
            vendor = vendor_for_mac(client.mac)
            if vendor:
                grouped.setdefault(client.bssid, []).append((client.mac, vendor))
        labels = {
            bssid: ", ".join(name for _mac, name in sorted(pairs))
            for bssid, pairs in grouped.items()
        }
        return counts, labels

    def _schedule_oui_load(self, force: bool) -> None:
        self._oui_request += 1
        token = self._oui_request
        self._write_log(treelog.header("IEEE OUI database"))
        if force or not oui_db.cache_is_fresh():
            self._write_log(treelog.branch("downloading oui.txt"))
        self.run_worker(
            self._load_oui(force, token),
            name="oui-db",
            group="oui-db",
            exclusive=True,
            exit_on_error=False,
        )

    async def _load_oui(self, force: bool, token: int) -> None:
        try:
            status = await asyncio.to_thread(oui_db.ensure, force=force)
        except Exception:
            status = None
        if token != self._oui_request:
            return
        if status is None:
            self._write_log(treelog.leaf_fail("could not load oui.txt"))
            return
        line = treelog.leaf_ok if status.ok else treelog.leaf_warn
        self._write_log(line(escape(status.message)))

    def action_toggle_log(self) -> None:
        log_widget = self.query_one("#system-log")
        log_widget.display = not log_widget.display

    def _selected_ap(self) -> Optional[AccessPoint]:
        table = self.query_one("#ap-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None
        return self.ap_cache.get(row_key)

    # ----- WPS PBC opportunistic capture -------------------------------------

    def action_wps_pbc_mode(self) -> None:
        """Toggle automatic WPS PBC capture."""
        if self.app.pbc_enabled:
            self._set_pbc_enabled(False)
            return
        if Config.confirm_active_actions:
            self.app.push_screen(
                ConfirmActiveActionModal(
                    "Automatic WPS PushButton capture",
                    "Any detected AP with an open WPS PBC window",
                    "Automatically associates and requests the network credential.",
                ),
                lambda confirmed: self._set_pbc_enabled(True) if confirmed else None,
            )
            return
        self._set_pbc_enabled(True)

    def _set_pbc_enabled(self, enabled: bool) -> None:
        self.app.pbc_enabled = enabled
        Config.auto_wps_pbc = enabled
        self.app.persist_config()
        self._log_pbc_status()
        if enabled:
            self._arm_open_windows()

    def _arm_open_windows(self) -> None:
        """React to PBC windows that are *already* open at the instant we arm."""
        array = self.app.array
        if not array:
            return
        launched = self._pbc_capturing
        for ap in array.get_access_points():
            if not ap.wps_pbc_active:
                continue
            if self.app.vault.has_psk(ap):
                ssid = escape(ap.ssid or ap.bssid)
                self._write_log(f"  [dim]({ssid} already captured, PSK: [bold]{escape(self.app.vault.known_psk(ap) or '?')}[/bold])[/dim]")
            elif not launched:
                launched = True
                self._on_pbc_window(ap)

    def _log_pbc_status(self) -> None:
        """WPS PBC auto-invade state as a ● header + detail leaf. Shared by
        startup + the 'w' toggle."""
        if self.app.pbc_enabled:
            self._write_log(treelog.header(
                "[bold]WPS PushButton Extraction[/bold] is "
                "[bold green]enabled[/bold green] [dim](press [bold]w[/bold] to toggle)[/dim]",
                color="green"))
            self._write_log(treelog.leaf(
                "[dim](automatically retrieves PSK when [bold italic]any[/bold italic] "
                "WPS button is pressed)[/dim]"))
        else:
            self._write_log(treelog.header(
                "[bold]WPS PushButton Extraction[/bold] is "
                "[orange1]disabled[/orange1] [dim](detect only, press [bold]w[/bold] to toggle)[/dim]",
                color="orange1"))

    def _poll_pbc(self) -> None:
        array = self.app.array
        if not array or self.app.screen is not self:
            return
        for ap in self._pbc_watcher.new_windows(array.get_access_points()):
            self._on_pbc_window(ap)

    def _on_pbc_window(self, ap: AccessPoint) -> None:
        if Config.is_silenced(ap.bssid):
            return
        label = escape(ap.ssid or ap.bssid)
        self._write_log(
            f"[bold cyan]WPS PushButton [italic]auto-invade:[/italic][/bold cyan] "
            f"[bold green]Open Window[/bold green] on [bold]{label}[/bold] "
            f"[dim](CH {ap.channel})[/dim]")
        if not self.app.pbc_enabled:
            self._write_log(treelog.leaf("[dim]auto-invade off: press [bold]w[/bold] to enable[/dim]"))
            return
        if self.app.vault.has_psk(ap):
            wps = self.app.vault.wps_capture(ap)
            where = f" [dim]({escape(Path(wps.path).name)})[/dim]" if wps else ""
            self._write_log(treelog.leaf(f"[italic]already captured[/italic]{where}"))
            return
        if self._pbc_capturing:
            return
        if Campaign.active is not None:
            self._write_log(treelog.leaf("[dim]radio busy: active campaign[/dim]"))
            return
        asyncio.create_task(self._invade_pbc(ap))

    async def _invade_pbc(self, ap: AccessPoint) -> None:
        """Pause hop → tune to the target → run the PBC enrollment → resume."""
        array = self.app.array
        if not array:
            return
        self._pbc_capturing = True
        label = escape(ap.ssid or ap.bssid)
        self._write_log(treelog.branch(
            f"[cyan]invading[/cyan] [bold]{label}[/bold]: pausing hop, "
            f"tuning [cyan]CH {ap.channel}[/cyan]…"))
        try:
            await array.stop_hopping()
            await array.set_channel(ap.channel)
            outcome = await WpsPbcCapture(
                array, ap, log=lambda m: self._write_log(treelog.branch(m))
            ).capture()
            if outcome.result is PinResult.SUCCESS:
                ap.wps_pbc_psk = outcome.psk
                name = escape(outcome.ssid or ap.ssid or ap.bssid)
                self._write_log(treelog.branch_ok(
                    f"[black bold on cyan] PSK for {name}: \"{escape(outcome.psk)}\" [/black bold on cyan]"))
                try:
                    result = self.app.vault.save_wps_pbc(ap, outcome.psk)
                    if result is None:
                        self._write_log(treelog.leaf("[dim](PSK not saved to disk)[/dim]"))
                    else:
                        verb = "saved" if result.was_new else "already saved as"
                        self._write_log(treelog.leaf(
                            f"[cyan]{verb}[/cyan] [dim]{escape(result.path.name)}[/dim]"))
                except Exception:
                    self._write_log(treelog.leaf("[dim](PSK not saved to disk)[/dim]"))
            else:
                self._write_log(treelog.leaf_fail(
                    f"{outcome.result.value} [dim]({escape(outcome.detail)})[/dim]"))
        except Exception as exc:                       # never let an invade kill the scanner
            self._write_log(treelog.leaf_fail(f"capture error: {escape(str(exc))}"))
        finally:
            self._pbc_capturing = False
            if self.app.screen is self:
                # Resume hopping only if we're still the foreground screen (not Focus).
                await array.start_hopping(channels=self._channel_filter, interval=0.25)

    def action_open_vault(self) -> None:
        self.app.action_toggle_vault()

    def action_open_probe_ap(self) -> None:
        running = self._open_probe_campaign
        if running is not None and not running.done:
            running.stopped = True
            self._write_log(treelog.leaf_warn("stopping automated OPEN probe test"))
            return
        if self._view_mode != "clients":
            self.notify("Switch to Clients view and select a client first", severity="warning")
            return
        if Campaign.active is not None or self._pbc_capturing:
            self.notify("The radio is busy with another active operation", severity="warning")
            return
        client = self._selected_client()
        if client is None:
            self.notify("Select a client first", severity="warning")
            return
        if not client.probe_observations:
            self.notify(
                "No channel-tagged directed probe observed; wait for a fresh probe",
                severity="warning",
            )
            return
        self.app.push_screen(
            OpenProbeSsidModal(client),
            lambda selection: (
                self._confirm_open_probe_test(client, *selection)
                if selection else None
            ),
        )

    def _selected_client(self) -> Client | None:
        table = self.query_one("#ap-table", DataTable)
        if not table.row_count:
            return None
        try:
            key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None
        return self._client_cache.get(key)

    def _confirm_open_probe_test(
        self,
        client: Client,
        ssid: str,
        timeout: int,
        encryption: str,
    ) -> None:
        observation = client.probe_observations.get(ssid)
        if observation is None:
            self.notify("That probe observation is no longer available", severity="warning")
            return
        if Config.confirm_active_actions:
            self.app.push_screen(
                ConfirmActiveActionModal(
                    "Automated probe honeypot test",
                    f"{escape(client.mac)} probing for {escape(ssid)}",
                    f"Broadcasts a {encryption} test AP and responds to clients "
                    f"requesting this SSID for up to {timeout // 60} minute(s). "
                    + (
                        "WPA2 sends EAPOL M1 and saves captured M1/M2 "
                        "authentication material to Vault. "
                        if encryption == "WPA2" else ""
                    )
                    + "No DHCP or Internet is served.",
                ),
                lambda confirmed: (
                    self._start_open_probe_test(
                        client, ssid, timeout, encryption,
                    )
                    if confirmed else None
                ),
            )
            return
        self._start_open_probe_test(client, ssid, timeout, encryption)

    def _honeypot_rsn_profile(
        self,
        ssid: str,
        channel: int,
    ) -> tuple[bytes | None, str, bytes]:
        def same_band(candidate: int) -> bool:
            return (candidate <= 14) == (channel <= 14)

        array = self.app.array
        if array is not None:
            live = sorted(
                (
                    ap for ap in array.access_points.values()
                    if ap.ssid == ssid
                    and not ap.is_own_fake
                    and 2 in ap.akm_suites
                    and beacon_rsn_ie(ap.last_beacon_frame) is not None
                ),
                key=lambda ap: (same_band(ap.channel), ap.last_seen),
                reverse=True,
            )
            for ap in live:
                rsn_ie = beacon_rsn_ie(ap.last_beacon_frame)
                compatible = force_psk_akm(
                    rsn_ie or b"",
                    pmf_capable=ap.pmf_capable,
                )
                if compatible is not None:
                    source_ies = (
                        ap.last_beacon_frame[36:]
                        if ap.last_beacon_frame is not None
                        else b""
                    )
                    return (
                        compatible,
                        f"live AP {ap.bssid} · compatible security/capability clone",
                        compatible_wpa2_profile_ies(source_ies, channel),
                    )

        profile_store = getattr(self.app, "wifi_profile_store", None)
        if profile_store is not None:
            stored = sorted(
                (
                    profile for profile in profile_store.profiles_for_ssid(ssid)
                    if 2 in profile.akm_suites
                ),
                key=lambda profile: (
                    same_band(profile.channel),
                    profile.last_seen,
                ),
                reverse=True,
            )
            for profile in stored:
                compatible = force_psk_akm(
                    profile.rsn_ie,
                    pmf_capable=profile.pmf_capable,
                )
                if compatible is not None:
                    return (
                        compatible,
                        f"saved AP profile {profile.bssid} · "
                        "compatible security/capability clone",
                        compatible_wpa2_profile_ies(profile.ies, channel),
                    )

        history = sorted(
            (
                profile for profile in load_scan_rsn_profiles(ssid)
                if 2 in profile.akm_suites
            ),
            key=lambda profile: same_band(profile.channel),
            reverse=True,
        )
        for profile in history:
            compatible = force_psk_akm(
                profile.rsn_ie,
                pmf_capable=profile.pmf_capable,
            )
            if compatible is not None:
                return (
                    compatible,
                    f"scan history {profile.source_file} · "
                    f"{profile.bssid} · PSK-compatible RSN clone",
                    b"",
                )
        return None, "generic WPA2-PSK/CCMP fallback", b""

    def _start_open_probe_test(
        self,
        client: Client,
        ssid: str,
        timeout: int,
        encryption: str,
    ) -> None:
        array = self.app.array
        observation = client.probe_observations.get(ssid)
        if array is None or observation is None:
            self.notify("The client or wireless array is no longer available", severity="warning")
            return
        rsn_ie, rsn_source, profile_ies = (
            self._honeypot_rsn_profile(ssid, observation.channel)
            if encryption == "WPA2"
            else (None, "OPEN", b"")
        )
        campaign = OpenProbeApCampaign(
            array,
            client,
            ssid,
            observation.channel,
            timeout=timeout,
            encryption=encryption,
            rsn_ie=rsn_ie,
            rsn_source=rsn_source,
            profile_ies=profile_ies,
        )
        if campaign.iface is None:
            self.notify(
                f"No spoofable interface can host channel {observation.channel}",
                severity="error",
            )
            return
        if not campaign.run():
            self.notify("The radio is busy with another campaign", severity="warning")
            return
        self._open_probe_campaign = campaign
        self._open_probe_event_index = 0
        self._open_probe_saved_clients.clear()
        warning = self.query_one("#open-probe-active", Static)
        warning.update(Text(
            f"HONEYPOT ACTIVE · {encryption} · {ssid} · CH {observation.channel} · "
            f"{campaign.iface.name} · {int(campaign.timeout)}s"
        ))
        warning.display = True
        self._write_log(treelog.header("Automated probe honeypot test"))
        self.notify(
            f"{encryption} honeypot started for {ssid} on channel "
            f"{observation.channel}",
            title="Probe honeypot",
        )

    def _poll_open_probe_campaign(self) -> None:
        campaign = self._open_probe_campaign
        if campaign is None:
            return
        warning = self.query_one("#open-probe-active", Static)
        if not campaign.done:
            elapsed = (
                time.monotonic() - campaign.started_at
                if campaign.started_at is not None else 0.0
            )
            remaining = max(0, int(campaign.timeout - elapsed))
            warning.update(Text(
                f"HONEYPOT ACTIVE · {campaign.encryption} · {campaign.ssid} · "
                f"CH {campaign.channel} · {campaign.iface.name} · {remaining}s"
            ))
            warning.display = True
        events = campaign.stats.events
        for message in events[self._open_probe_event_index:]:
            self._write_log(treelog.branch(escape(message)))
        self._open_probe_event_index = len(events)
        if campaign.encryption == "WPA2" and self.app.array is not None:
            ap = self.app.array.access_points.get(campaign.bssid_text)
            if ap is not None:
                for client_mac, attempt in campaign.stats.clients.items():
                    if not attempt.m2 or client_mac in self._open_probe_saved_clients:
                        continue
                    saved = self.app.vault.save_handshake(ap, client_mac)
                    if saved is not None:
                        self._open_probe_saved_clients.add(client_mac)
                        self._write_log(treelog.branch(
                            f"WPA2 material saved to Vault · "
                            f"{escape(client_mac)} · {escape(saved.path.name)}"
                        ))
        if not campaign.done:
            return
        warning.display = False
        if campaign.stats.clients:
            self._write_log(treelog.branch("Client MACs observed"))
            attempts = sorted(
                campaign.stats.clients.items(),
                key=lambda item: (not item[1].is_target, item[0]),
            )
            for client_mac, attempt in attempts:
                role = "ORIGIN" if attempt.is_target else "CLIENT"
                try:
                    local = bool(int(client_mac.split(":", 1)[0], 16) & 0x02)
                except (ValueError, IndexError):
                    local = False
                if not attempt.is_target and local:
                    role += " · locally administered/randomized possible"
                self._write_log(treelog.branch(
                    f"[bold]{escape(client_mac)}[/bold] · {role} · "
                    f"{attempt.phase.name.lower()} · probes {attempt.probes} "
                    f"(directed {attempt.directed_probes}, "
                    f"wildcard {attempt.wildcard_probes}) · "
                    f"auth {attempt.auth} · assoc {attempt.assoc} · "
                    f"M2 {attempt.m2} · DHCP {attempt.dhcp}"
                ))
        result = {
            "dhcp": "[bold green]CONFIRMED[/bold green] · client associated and requested DHCP",
            "handshake": (
                "[bold green]WPA2 M2 CAPTURED[/bold green] · saved to Vault"
            ),
            "associated": (
                "[yellow]ASSOCIATION ATTEMPT[/yellow] · WPA2 4-way handshake not performed"
                if campaign.encryption == "WPA2"
                else "[yellow]ASSOCIATED[/yellow] · no DHCP observed before timeout"
            ),
            "authenticated": "[yellow]AUTHENTICATED[/yellow] · association not completed",
            "probe": "[cyan]PROBED[/cyan] · authentication not attempted",
            "timeout": "[dim]TIMEOUT[/dim] · no client response",
            "stopped": "[dim]STOPPED[/dim]",
            "no-interface": "[red]FAILED[/red] · no compatible interface",
        }.get(campaign.result, escape(campaign.result))
        if campaign.encryption == "WPA2" and campaign.stats.m2 == 0:
            result += (
                " · [bold yellow]NO M2 CAPTURED[/bold yellow] · "
                "nothing saved to Vault"
            )
        self._write_log(treelog.leaf(result))
        severity = (
            "information"
            if campaign.result in ("dhcp", "handshake")
            else "warning"
        )
        self.notify(
            (
                "Client requested DHCP from the open test AP"
                if campaign.result == "dhcp"
                else "WPA2 M2 captured and saved to Vault"
                if campaign.result == "handshake"
                else f"Probe honeypot finished: {campaign.result}"
            ),
            title="Probe honeypot",
            severity=severity,
        )
        self._open_probe_campaign = None

    async def stop_open_probe_test(self) -> None:
        campaign = self._open_probe_campaign
        if campaign is not None and not campaign.done:
            await campaign.stop()

    def action_toggle_infrastructure(self) -> None:
        if self._view_mode != "aps":
            self.notify("Infrastructure grouping is available in AP view")
            return
        table = self.query_one("#ap-table", DataTable)
        if not table.row_count:
            return
        try:
            row_key = str(
                table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value,
            )
        except Exception:
            return
        group_key = (
            row_key
            if row_key in self._infrastructure_members
            else self._expanded_member_ssids.get(row_key)
        )
        if group_key is None:
            self.notify("Selected AP is not part of a multi-AP infrastructure")
            return
        members = self._infrastructure_members.get(group_key, ())
        if group_key in self._expanded_infrastructures:
            self._expanded_infrastructures.remove(group_key)
            destination = group_key
        else:
            self._expanded_infrastructures.add(group_key)
            destination = members[0].bssid if members else group_key
        table.clear(columns=False)
        self.ap_cache.clear()
        self._row_states.clear()
        self.refresh_table()
        try:
            table.move_cursor(row=table.get_row_index(destination), animate=False)
        except Exception:
            pass

    def action_new_target(self) -> None:
        selected = self._selected_target_candidate()
        if selected is None:
            self.notify("Select an AP or client first", severity="warning")
            return
        candidate, subject = selected
        existing = self.app.target_store.find(
            candidate.medium, candidate.kind, candidate.identifier
        )
        if existing is not None:
            self.lock_target(existing, candidate, subject)
            return

        def completed(result: NewTargetResult | None) -> None:
            if result is None:
                return
            try:
                target = self.app.target_store.upsert(
                    alias=result.alias,
                    medium=candidate.medium,
                    kind=candidate.kind,
                    identifier=candidate.identifier,
                    details=candidate.details,
                )
            except TargetStoreError as exc:
                self.notify(str(exc), title="Targets", severity="error")
                return
            self.notify(f"Target {target.alias} saved", title="Targets")
            if result.lock:
                self.lock_target(target, candidate, subject)

        self.app.push_screen(NewTargetModal(candidate), completed)

    def _selected_target_candidate(
        self,
    ) -> tuple[TargetCandidate, AccessPoint | Client] | None:
        table = self.query_one("#ap-table", DataTable)
        if not table.row_count:
            return None
        try:
            key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None
        if self._view_mode == "clients":
            client = self._client_cache.get(key)
            if client is None:
                return None
            ap = (
                self.app.array.access_points.get(client.bssid)
                if self.app.array is not None and client.bssid else None
            )
            return client_candidate(client, ap), client
        if key in self._infrastructure_members:
            self.notify(
                "Expand the infrastructure and select one AP first",
                severity="warning",
            )
            return None
        ap = self.ap_cache.get(key)
        if ap is not None and ap.is_own_fake:
            self.notify("Generated test APs cannot be saved as targets", severity="warning")
            return None
        return (ap_candidate(ap), ap) if ap is not None else None

    def _maybe_lock_target(self, array) -> None:
        if self._target_navigation_pending or self.app.screen is not self:
            return
        target_store = getattr(self.app, "target_store", None)
        if target_store is None:
            return
        locked = getattr(self.app, "locked_target", None)
        if locked is not None:
            if locked.medium == "wifi" and locked.kind == "client":
                client = array.clients.get(locked.identifier)
                ap = (
                    array.access_points.get(client.bssid)
                    if client is not None and client.bssid else None
                )
                if client is not None and ap is not None:
                    self.app.target_missing_since = None
                    candidate = client_candidate(client, ap)
                    self.lock_target(locked, candidate, client, announce=False)
                else:
                    self._wait_for_locked_target(locked)
            elif locked.medium == "wifi" and locked.kind == "ap":
                if locked.identifier in array.access_points:
                    self.app.target_missing_since = None
                else:
                    self._wait_for_locked_target(locked)
            return
        if not Config.auto_lock_targets or not getattr(
            self.app, "auto_lock_armed", False,
        ):
            return
        observed: list[tuple[float, SavedTarget, TargetCandidate, AccessPoint | Client]] = []
        for ap in array.get_access_points(include_eviltwin=False):
            target = target_store.find("wifi", "ap", ap.bssid)
            if target is not None and target.enabled:
                observed.append((ap.first_seen, target, ap_candidate(ap), ap))
        for client in array.clients.values():
            target = target_store.find("wifi", "client", client.mac)
            if target is not None and target.enabled:
                ap = array.access_points.get(client.bssid) if client.bssid else None
                observed.append((
                    client.first_seen,
                    target,
                    client_candidate(client, ap),
                    client,
                ))
        if observed:
            _seen, target, candidate, subject = min(observed, key=lambda item: item[0])
            self.lock_target(target, candidate, subject)

    def _wait_for_locked_target(self, target: SavedTarget) -> None:
        now = time.monotonic()
        missing_since = getattr(self.app, "target_missing_since", None)
        if missing_since is None:
            self.app.target_missing_since = now
            return
        if now - missing_since < Config.target_reacquire_timeout:
            return
        self.app.locked_target_id = None
        self.app.target_client = None
        self.app.target_missing_since = None
        self.notify(
            f"Target {target.alias} was not reacquired",
            title="Target lock released",
            severity="warning",
        )

    @work(exclusive=True, group="target-lock")
    async def lock_target(
        self,
        target: SavedTarget,
        candidate: TargetCandidate,
        subject: AccessPoint | Client,
        *,
        announce: bool = True,
    ) -> None:
        self._target_navigation_pending = True
        try:
            self.app.target_store.update_missing(target, candidate.details)
            if announce and not self.app.mark_target_locked(target):
                return
            if not announce:
                self.app.locked_target_id = target.id
            array = self.app.array
            if array is None:
                return
            if isinstance(subject, Client):
                if not subject.bssid or subject.bssid not in array.access_points:
                    self.app.target_client = subject
                    self.notify(
                        f"Target {target.alias} is unassociated; waiting for an association",
                        title="Target lock",
                        severity="warning",
                    )
                    return
                await array.stop_hopping()
                self.app.target_client = subject
                self.app.target_ap = array.access_points[subject.bssid]
                self.app.push_screen("client-focus")
                return
            await array.stop_hopping()
            self.app.target_client = None
            self.app.target_ap = subject
            self.app.push_screen("focus")
        except TargetStoreError as exc:
            self.notify(str(exc), title="Targets", severity="error")
        finally:
            self._target_navigation_pending = False

    def action_go_back(self) -> None:
        self.return_to_device_selection()

    @work(exclusive=True)
    async def return_to_device_selection(self) -> None:
        await self.stop_open_probe_test()
        array = self.app.array
        if array is not None:
            await array.stop_hopping()
            await array.close()
        self.app.array = None
        self.app.target_ap = None
        self.app.target_client = None
        self.app.locked_target_id = None
        self.app.auto_lock_armed = True
        await self.app.switch_screen("splash")
        self.app.get_screen("splash").reset_for_reentry()

    def action_export_scan(self) -> None:
        array = self.app.array
        if array is None:
            self.notify("No scan data to export", severity="warning")
            return
        try:
            json_path, csv_path = export_scan_snapshot(
                array.get_access_points(include_eviltwin=False),
                array.clients.values(),
            )
        except OSError as exc:
            self.notify(str(exc), title="Export failed", severity="error")
            return
        self.notify(
            f"{json_path.name}\n{csv_path.name}",
            title="Scan exported",
            timeout=6,
        )

    def action_focus_filter(self) -> None:
        self.query_one(FilterBar).focus_text()

    def action_focus_encryption(self) -> None:
        self.query_one(FilterBar).focus_encryption()

    def action_toggle_view(self) -> None:
        if self._view_mode == "aps":
            self._ap_sort_state = (self._sort_idx, self._sort_reverse)
            self._view_mode = "clients"
            self._sort_idx, self._sort_reverse = self._client_sort_state
        else:
            self._client_sort_state = (self._sort_idx, self._sort_reverse)
            self._view_mode = "aps"
            self._sort_idx, self._sort_reverse = self._ap_sort_state
        table = self.query_one("#ap-table", DataTable)
        table.clear(columns=True)
        for key, label in self._active_columns():
            width = 13 if self._view_mode == "aps" and key == "last_seen" else None
            table.add_column(label + "  ", key=key, width=width)
        self._row_states.clear()
        self.ap_cache.clear()
        self._client_row_states.clear()
        self._client_cache.clear()
        self.query_one(FilterBar).set_view(self._view_mode)
        self._update_column_headers()
        self.refresh_table()
        self.refresh_bindings()
        table.focus()

    def action_cycle_sort(self) -> None:
        columns = self._active_columns()
        self._sort_idx = (self._sort_idx + 1) % len(columns)
        if self._view_mode == "aps":
            Config.scanner_sort = columns[self._sort_idx][0]
            self.app.persist_config()
        self._update_column_headers()
        self._apply_sort()
        self._announce_sort()

    def action_toggle_sort_dir(self) -> None:
        self._sort_reverse = not self._sort_reverse
        if self._view_mode == "aps":
            Config.scanner_sort_reverse = self._sort_reverse
            self.app.persist_config()
        self._update_column_headers()
        self._apply_sort()
        self._announce_sort()

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.query_one(FilterBar).set_paused(self._paused)
        if self._paused:
            self.notify("Table frozen; radio capture continues", title="Scanner paused")
        else:
            self.notify("Live updates resumed", title="Scanner active")
            self.refresh_table()

    def action_scroll_home(self) -> None:
        table = self.query_one("#ap-table", DataTable)
        if table.row_count > 0:
            table.move_cursor(row=0, animate=True)

    def action_scroll_end(self) -> None:
        table = self.query_one("#ap-table", DataTable)
        if table.row_count > 0:
            table.move_cursor(row=table.row_count - 1, animate=True)

    def action_change_channel(self) -> None:
        log = self.query_one("#system-log", RichLog)
        array = self.app.array
        if not array:
            log.write("[bold red][!] No active interface.[/bold red]")
            return

        supported = array.supported_channels
        if not supported:
            log.write(
                "[bold red][!] Driver did not declare SUPPORTED_CHANNELS.[/bold red]"
            )
            return

        dialog = ChannelFilterDialog(
            supported_channels=list(supported),
            current_filter=self._channel_filter,
        )
        self.app.push_screen(dialog, self._on_channel_filter_result)

    async def _on_channel_filter_result(
        self, result: Optional[List[int]]
    ) -> None:
        if result is None:
            self.query_one("#system-log", RichLog).write("[dim]Channel filter unchanged.[/dim]")
        else:
            await self._apply_channel_filter(result)
        self.query_one(FilterBar).set_channels(self._channel_filter)
        self.query_one("#ap-table", DataTable).focus()

    async def _apply_channel_filter(self, channels: List[int]) -> None:
        """Re-point the hopper; a full-band pick becomes None so hotplug keeps re-spreading it."""
        array = self.app.array
        if not array:
            return
        full_band = set(channels) == set(array.supported_channels)
        self._channel_filter = None if full_band else channels
        await array.stop_hopping()
        dropped = self._prune_aps_outside(channels)
        await array.start_hopping(channels=self._channel_filter, interval=0.25)

        log = self.query_one("#system-log", RichLog)
        pieces = [
            f"[bold cyan]{name}[/bold cyan] [dim]({rngs})[/dim]"
            for name, rngs in band_ranges(channels)
        ]
        summary = " and ".join(pieces) if pieces else "[dim]no channels[/dim]"
        log.write(f" [dim]●[/dim] [bold]Channel hopping[/bold] across {summary}")
        if dropped:
            noun = "AP" if dropped == 1 else "APs"
            log.write(
                treelog.leaf(f"[dim]Cleared [bold]{dropped}[/bold] "
                             f"{noun} outside the filter[/dim]")
            )

    # ----- Filter bar --------------------------------------------------------

    def on_filter_bar_scan_filter_changed(self, message: FilterBar.ScanFilterChanged) -> None:
        self._scan_filter = message.scan_filter
        self.refresh_table()

    def on_filter_bar_edit_channels(self) -> None:
        self.action_change_channel()

    def _prune_aps_outside(self, channels: List[int]) -> int:
        array = self.app.array
        if not array:
            return 0
        keep = set(channels)
        stale = [
            bssid
            for bssid, ap in array.access_points.items()
            if ap.channel not in keep
        ]
        for bssid in stale:
            self._forget_row(bssid, drop_from_array=True)
        return len(stale)

    async def on_data_table_row_selected(
        self, event: DataTable.RowSelected
    ) -> None:
        if self._open_probe_campaign is not None and not self._open_probe_campaign.done:
            self.notify("Stop the active OPEN probe test before leaving", severity="warning")
            return
        row_key = event.row_key.value
        if self._view_mode == "aps" and row_key in self._infrastructure_members:
            self.action_toggle_infrastructure()
            return
        if self._view_mode == "clients":
            client = self._client_cache.get(row_key)
            bssid = client.bssid if client else None
            target_ap = self.app.array.access_points.get(bssid) if self.app.array and bssid else None
        else:
            bssid = row_key
            target_ap = self.ap_cache.get(bssid)
        if target_ap is not None and target_ap.is_own_fake:
            state = "active" if target_ap.own_fake_active else "stopped"
            self.notify(
                f"Our generated honeypot AP is {state}",
                title="Honeypot AP",
            )
            return
        if target_ap:
            if self.app.array:
                await self.app.array.stop_hopping()
            self.app.target_ap = target_ap
            self.app.push_screen("focus")

    def on_data_table_header_selected(
        self, event: DataTable.HeaderSelected
    ) -> None:
        """Click a column header to sort by it; click again to flip direction."""
        key = event.column_key.value
        columns = self._active_columns()
        for idx, (col_key, _) in enumerate(columns):
            if col_key != key:
                continue
            if idx == self._sort_idx:
                self._sort_reverse = not self._sort_reverse
            else:
                self._sort_idx = idx
            if self._view_mode == "aps":
                Config.scanner_sort = columns[self._sort_idx][0]
                Config.scanner_sort_reverse = self._sort_reverse
                self.app.persist_config()
            self._update_column_headers()
            self._apply_sort()
            self._announce_sort()
            return
