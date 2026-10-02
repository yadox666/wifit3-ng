"""``FocusViewV2``: the spatial "router-admin" Focus redesign (landscape v1).

Layout (top to bottom):
- **Top bar** (fixed height): an "action area" on the left (the back button +
  the encryption-conditional attack buttons, all the clickables in one place)
  then the status line, expanding to fill and stay centered.
- **Mid band**: card | packet-dashboard | router. Card and router are fixed-width
  (the art is 20 cells) and vertically centered; the dashboard fills the
  middle. The band's height is capped so the sparklines reach full 2-row height
  and the endpoint columns fit, then extra terminal height goes to the bottom.
- **Bottom band**: LOG (fluid width) | CLIENTS (fixed width). Grows once the mid
  band is satisfied, so tall terminals show more log lines + clients.

Power + signal live above the router ESSID (the live rainbow signal bar), not in
the top bar. Portrait is deferred.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Set

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Offset
from textual.screen import Screen
from textual.widgets import Button, Footer, Static

from wifit3.ui.notification_center import WifiteHeader

from wifit3.campaigns import treelog
from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.pmkid import PmkidHarvestAttack
from wifit3.campaigns.wep import WepCampaign
from wifit3.campaigns.eviltwin import EvilTwinCampaign, EvilTwinInput
from wifit3.campaigns.fake_connect import CONNECTIVITY_URL, FakeConnectCampaign
from wifit3.ui.screens.focus_v2.eviltwin_modal import EvilTwinInputModal
from wifit3.targeting import is_wifi_ap_whitelisted, is_wifi_client_whitelisted
from wifit3.ui.screens.confirm_active import ConfirmActiveActionModal, ConfirmLeaveFocusModal
from wifit3.campaigns.pin import WpsCampaign, load_run_state, run_progress_line
from wifit3.campaigns.deauth import DeauthCampaign
from wifit3.campaigns.pbc import WpsPbcCapture
from wifit3.campaigns.probe import probe_ap
from wifit3.campaigns.enterprise_probe import EnterpriseProbe, EnterpriseProbeResult
from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig, methods_for_ap
from wifit3.campaigns.peap_honeypot import PeapHoneypotCampaign
from wifit3.ui.screens.eap_lab_modal import EapLabModal
from .campaign_controls import CampaignControls
from wifit3.campaigns.wps.registrar import PinResult
from wifit3.crack.handshake import handshake_uncrackable_label
from wifit3.models import AccessPoint, Client, EnterpriseProbeRun, IdSource
from wifit3.safety import deauth_limits
from wifit3.persist.config import Config
from wifit3.persist.common import bssid_to_dashed, safe_ssid
from wifit3.persist.network_metadata import (
    NetworkMetadataStore, NetworkMetadataStoreError,
)
from wifit3.persist.pcap import PcapWriter
from wifit3.ui.network_metadata_panel import (
    NetworkMetadataPanel,
    client_network_details,
)
from wifit3.ui.recording_indicator import pcap_progress, recording_indicator
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.wlan.enterprise_risk import enterprise_findings, is_enterprise_ap
from wifit3.wlan.network_metadata import PassiveNetworkAnalyzer
from wifit3.wlan.channels import channel_spec_for_ap

from ... import focus_model as fm
from ...capture_events import (
    CAPTURE_TOAST_TITLES, DECLOAK_METHOD_LABELS, CaptureEvent, CaptureEventDetector, CaptureKind,
)
from ...capture_log import short_sta
from ...eapol_aggregate import EapolAggregator
from ... import pmkid_log
from ...encryption_format import wep_key_ascii
from .cards_column import CardsColumn
from .tx_picker import TxDevicePicker
from .clients_list import ClientsList, ClientWidget, FingerprintModal
from .packet_dashboard import PacketDashboard
from .log_band import LogBand
from .router_endpoint import RouterEndpoint
from .enterprise_panel import EnterprisePanel
from . import art

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

logger = logging.getLogger(__name__)

_CLIENT_LIVE_SECONDS = 10.0

_ENDPOINT_W = 20  # the .ans art is exactly 20 cells wide
_TOPBAR_H = 3
_CHROME_H = 2  # Buffer for Textual's Header & Footer (1 row each)
_BORDER = "$primary"  # Border/title color for  LOG / CLIENTS panels

# Mid-band height
_CENTER_MAX = 13
_CENTER_MIN = 7
_BOTTOM_MIN = 6
# Horizontal padding on the mid row
_PAD_START = 80
_PAD_RATE = 0.4

_PBC_RETRY_COOLDOWN_S = 3.0

_ATTACK_BUTTONS = [
    ("btn-enterprise", "Enterprise"),
    ("btn-gen-ivs", "ARP Replay"), ("btn-chop", "ChopChop"), ("btn-deauth", "AutoDeauth"),
    ("btn-pmkid", "PMKID"), ("btn-fake-connect", "Fake-Connect"),
    ("btn-wps-info", "WPS Info"), ("btn-wps-pin", "WPS PIN"),
    ("btn-eviltwin", "EvilTwin"),
    ("btn-stop-pbc", "Stop PBC"),
]

# Static button tooltips, keyed by live label so toggled buttons get idle/run-specific tips.
_BUTTON_TIPS = {
    "Enterprise": "Open the accumulated Enterprise assessment",
    "ARP Replay": "Listen for & replay ARP packets",
    "Stop Replay": "Stop the entire WEP campaign.",
    "ChopChop": "Forge a replayable packet",
    "Stop Chop": "Interrupt chopping and return to ARP replay",
    "AutoDeauth": "De-authenticate clients 1-by-1, then de-authenticates broadcast. Loops.",
    "PMKID": "Associate to extract PMKID\n(some APs not applicable)",
    "Fake-Connect": "Associate a fake client; OPEN networks also test Internet access",
    "Disconnect": "Send a client-leaving frame and end the temporary association",
    "WPS Info": "Probe the registrar for WPS manufacturer and model details",
    "Stop Info": "Stop the active WPS information probe",
    "WPS PIN": "PIN attacks: PixieDust, default vendor PINs, then brute-force",
    "EvilTwin": "Punt clients onto a WPA2 twin to capture a crackable handshake",
    "Stop EvilTwin": "Tear down the twin and return clients to the AP",
}


# Pretty-print a capture filename, skipping the <bssid>_<epoch> middle
_FILENAME_MIDDLE = re.compile(r"_[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}_\d+_")


def _save_line(result) -> str:
    """Short, dim 'saved/exists: captures/<essid>_…_<kind>.<ext>' line for a save result."""
    verb = "saved" if result.was_new else "exists"
    name = result.path.name
    m = _FILENAME_MIDDLE.search(name)
    short = f"{name[:m.start()]}_…_{name[m.end():]}" if m else name
    return f"[dim]{verb}: {Config.captures_dir}/{escape(short)}[/dim]"


def _wep_key_chip(key_hex) -> str:
    """Black-bold-on-cyan WEP key chip (bare hex for non-printable keys)."""
    if not key_hex:
        return "[dim]?[/dim]"
    return f"[black bold on cyan] {wep_key_ascii(key_hex)} [/black bold on cyan]"


def _recovered_credential_chip(label: str) -> str:
    """Focus log chip for a saved credential without echoing the secret."""
    return f"[black bold on cyan] {label} recovered [/black bold on cyan]"


def _client_connection_segments(
    source_x: int,
    target_x: int,
    height: int,
) -> tuple[str, str, str]:
    """Return horizontal, vertical, and border-junction connector segments."""
    distance = abs(target_x - source_x)
    if distance < 2 or height < 2:
        return "", "", ""
    if source_x < target_x:
        horizontal = "━" * distance + "┓"
    else:
        horizontal = "┏" + "━" * distance
    vertical = "\n".join("┃" for _ in range(height - 2))
    style = "bold bright_cyan"
    return (
        f"[{style}]{horizontal}[/]",
        f"[{style}]{vertical}[/]" if vertical else "",
        f"[{style}]┴[/]",
    )


class FocusViewV2(Screen):
    app: "WifiteApp"

    HORIZONTAL_BREAKPOINTS = [(0, "-compact"), (100, "-normal"), (140, "-wide")]

    # Attack hotkeys come from the campaign registry
    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("e", "enterprise", "Enterprise", show=True),
        Binding("d", "deauth_all", "Deauth", show=True),
        *[Binding(cls.hotkey[0], f"campaign('{cls.key}')", cls.hotkey[1], show=True)
          for cls in fm.BUTTON_CAMPAIGNS if cls.hotkey],
        Binding("c", "campaign('chop')", "ChopChop", show=True),
        Binding("i", "wps_info", "WPS Info", show=False),
        Binding("x", "capture_packets", "Capture PCAP", show=True),
        Binding("s", "silence", "Silence", show=True),
        Binding("s", "unsilence", "unSilence", show=True),
        Binding("shift+t", "targets_editor", "Targets", show=True),
    ]

    CSS = """
    FocusViewV2 { layout: vertical; background: $surface; }

    #topbar { height: %(top)d; }
    #actions { width: auto; height: 100%%; }
    #topbar Button { height: 3; width: auto; min-width: 0; margin: 0 1 0 0; }
    /* No background override on .attack-btn */
    #status { width: 1fr; height: 3; content-align: center middle; text-align: center; }
    #rspacer { width: 0; height: 1; }
    #pcap-recording { width: 20; height: 3; content-align: center middle; text-align: center; }

    #mid { height: 1fr; }
    #card { width: auto; align: center middle; }
    #router { width: %(ew)d; align: center bottom; }
    #dashboard { width: 1fr; height: 100%%; padding: 0 1; }
    .endpoint-art { width: %(ew)d; background: transparent; }
    .card-static, .ap-static { width: 100%%; height: 1; text-align: center; color: $text-muted; }
    .card-channel { width: 100%%; height: 1; text-align: center; color: $accent; text-style: bold; }
    .card-slot-name { width: 100%%; height: 1; text-align: center; color: $text-muted; }
    .card-dynamic { width: 100%%; height: 1; text-align: center; color: $accent; }
    .ap-essid { width: 100%%; height: 1; text-align: center; text-style: bold; }
    .ap-power { width: 100%%; height: 1; text-align: center; }
    #ap-identity-row { width: 100%%; height: 1; align-horizontal: center; }
    #ap-identity {
        width: 1fr; height: 1; min-width: 0; border: none; margin: 0; padding: 0;
        background: transparent; color: $text-muted; content-align: center middle;
    }
    #ap-identity.identity-known { text-style: underline bold; color: $accent; }
    #ap-identity:focus { text-style: bold reverse; }

    #bottom { height: 1fr; }
    #client-connector-horizontal,
    #client-connector-vertical,
    #client-connector-junction {
        position: absolute; layer: connector;
        height: 1; width: 1; background: transparent;
        text-wrap: nowrap;
        display: none;
    }
    #activity { width: 1fr; height: 100%%; overflow-y: auto; }
    #network-metadata { margin: 0 0 1 0; }
    #log { width: 1fr; height: 1fr; border: round %(border)s;
           border-title-color: %(border)s; border-title-style: bold; padding: 0 1; }
    #log-rich { width: 100%%; height: 1fr; background: transparent; border: none; padding: 0; }
    #clients { width: 54; height: 100%%; border: round %(border)s;
               border-title-color: %(border)s; border-title-style: bold; padding: 0 1; }
    /* Rows scroll inside a fixed-height region; the broadcast button stays pinned. */
    #client-rows { width: 100%%; height: 1fr; }

    .bcast-btn { width: 100%%; height: 1; min-width: 0; border: none; margin: 0 0 1 0;
                 background: $error; color: $text; content-align: center middle; }
    .client-columns { height: 1; width: 100%%; color: $text-muted; text-style: bold; }
    .client-row { height: 1; width: 100%%; }
    .fake-client .cl-bssid, .fake-client .cl-mfr { color: yellow; text-style: bold; }
    .historical-client { color: $text-muted; opacity: 65%%; }
    .historical-client .cl-bssid, .historical-client .cl-mfr,
    .historical-client .cl-pwr, .historical-client .cl-pkts { color: $text-muted; }
    .cl-fp { width: 2; }
    /* A known fingerprint is clickable (pops up the detail popup): underline + accent color on
       the MAC marks it, same as any other actionable text. Not on the emoji itself -- the
       underline renders through the glyph rather than under it, which reads as broken/ugly. */
    .cl-bssid.fp-known { text-style: underline bold; color: $accent; }
    .cl-bssid { width: 17; }
    .cl-mfr {
        width: 15; margin-left: 1; color: $text-muted; text-overflow: ellipsis;
    }
    .cl-pwr { width: 5; text-align: right; }
    .cl-pkts { width: 4; text-align: right; }
    .cl-action { width: 4; }
    .cl-deauth { width: 3; min-width: 3; height: 1; border: none; margin: 0 0 0 1;
                 background: red; color: white; content-align: center middle; }
    """ % {"ew": _ENDPOINT_W, "top": _TOPBAR_H, "border": _BORDER}

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._target_ap = None
        self._last_status: list[str] | None = None   # last-pushed headline; skip no-op repaints
        self._beacon_samples: deque = deque()
        self._events = CaptureEventDetector(granular_eapol=True)
        self._eapol_agg = EapolAggregator(settle_s=3.0)
        self._tick_timer = None
        # The one running campaign (Campaign.active is the radio mutex).
        self._controls = CampaignControls()
        self._pbc_user_stopped = False
        self._pbc_retry_after = 0.0   # monotonic time before which we won't re-arm a PBC retry
        self._probe_task: Optional[asyncio.Task] = None
        self._enterprise_probe_task: Optional[asyncio.Task] = None
        self._eap_lab_campaign: PeapHoneypotCampaign | None = None
        self._eap_lab_event_index = 0
        self._packet_capture: PcapWriter | None = None
        self._packet_capture_array = None
        self._packet_capture_bssid: str | None = None
        self._network_store: NetworkMetadataStore | None = None
        self._network_analyzer: PassiveNetworkAnalyzer | None = None
        self._network_observation_array = None
        self._network_bssid: str | None = None
        self._prev_stats = None
        self._campaign_toggles = {
            "wep": self._toggle_generate_ivs, "pmkid": self._toggle_pmkid,
            "wps": self._toggle_wps_pin, "chop": self._toggle_chop,
            "deauth": self._toggle_deauth, "fake_connect": self._toggle_fake_connect,
        }
        self._binding_sig: Optional[tuple] = None
        self._rspacer_w = -1                          # last-set spacer width; skip no-op relayouts

    # ----- compose -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield WifiteHeader()
        with Horizontal(id="topbar"):
            with Horizontal(id="actions"):
                yield Button("‹ Scanner", id="back")
                # The full attack set is composed once (hidden); refresh_buttons shows the ones that fit the target.
                for bid, label in _ATTACK_BUTTONS:
                    btn = Button(label, id=bid, classes="attack-btn")
                    btn.display = False
                    yield btn
            status = self._status()
            self._last_status = status
            yield Static(self._render_status(status), id="status")
            # Right spacer to accurately align status to sparklines.
            yield Static("", id="rspacer")
            yield Static("", id="pcap-recording")
        with Horizontal(id="mid") as mid:
            mid.ALLOW_SELECT = False
            yield CardsColumn(id="card")
            yield PacketDashboard(self._dashboard_rows(), id="dashboard")
            yield RouterEndpoint(**self._router_values(), id="router")
        with Horizontal(id="bottom"):
            with Vertical(id="activity"):
                panel = NetworkMetadataPanel(id="network-metadata")
                panel.display = False
                yield panel
                yield LogBand([], id="log")
            yield ClientsList(self._client_list(), id="clients")
        yield Static("", id="client-connector-horizontal")
        yield Static("", id="client-connector-vertical")
        yield Static("", id="client-connector-junction")
        yield GlobalJobTracker()
        yield Footer()

    async def on_mount(self) -> None:
        self._tick_timer = self.set_interval(1 / 10, self._tick)
        self._distribute()
        await self._enter_target()

    def on_unmount(self) -> None:
        self.stop_packet_capture(notify=False)
        self._stop_network_analysis()

    async def on_screen_resume(self) -> None:
        # Full re-acquire only on a target change; a same-target return keeps the live view.
        target = getattr(self.app, "target_ap", None)
        if target is not self._target_ap:
            await self._enter_target()
        elif target is not None:
            # Re-pin the pool to the target's channel on re-entry (STACK across channel-capable cards).
            array = self.app.array
            if array is not None:
                ok = await array.set_channel_spec(
                    channel_spec_for_ap(target), scan=False,
                )
                logger.info("[FOCUS] re-pin: bssid=%s ch=%s -> %s",
                            target.bssid, target.channel, ok)

    def on_resize(self) -> None:
        self._distribute()

    # ----- snapshot building -------------------------------------------------

    def _pbc_busy(self) -> bool:
        cur = self._controls.current
        return isinstance(cur, WpsPbcCapture) and not cur.done

    def _is_wps_probing(self) -> bool:
        return self._probe_task is not None and not self._probe_task.done()

    def _is_enterprise_probing(self) -> bool:
        return (
            self._enterprise_probe_task is not None
            and not self._enterprise_probe_task.done()
        )

    def _is_probing(self) -> bool:
        return self._is_wps_probing() or self._is_enterprise_probing()

    def _is_eap_lab_active(self) -> bool:
        return self._eap_lab_campaign is not None and not self._eap_lab_campaign.done

    def _any_campaign_active(self) -> bool:
        return (
            Campaign.active is not None
            or self._controls.current is not None
            or self._is_probing()
            or self._is_eap_lab_active()
        )

    def _campaign_action_label(self, campaign: Campaign) -> str:
        label = campaign.run_label or campaign.idle_label or campaign.key or "Campaign"
        if label.startswith("Stop "):
            return label[5:]
        if label == "Disconnect":
            return "Fake-Connect"
        if label == "pbc":
            return "WPS PushButton capture"
        return label

    def _running_actions_on_leave(self) -> list[str]:
        actions: list[str] = []
        seen: set[str] = set()

        def add(name: str) -> None:
            if name and name not in seen:
                seen.add(name)
                actions.append(name)

        cur = self._controls.current
        if cur is not None and not getattr(cur, "done", False):
            add(self._campaign_action_label(cur))
        elif Campaign.active is not None and not getattr(Campaign.active, "done", False):
            add(self._campaign_action_label(Campaign.active))

        if self._is_wps_probing():
            add("WPS information probe")
        if self._is_enterprise_probing():
            add("Enterprise security probe")
        if self._is_eap_lab_active():
            add("EAP lab honeypot")
        if self._packet_capture is not None:
            add("Focused packet capture")
        return actions

    def _stop_probe(self) -> None:
        if self._probe_task is not None and not self._probe_task.done():
            self._probe_task.cancel()
        self._probe_task = None
        if (
            self._enterprise_probe_task is not None
            and not self._enterprise_probe_task.done()
        ):
            self._enterprise_probe_task.cancel()
        self._enterprise_probe_task = None

    def _router_values(self) -> dict:
        """The AP identity + power primitives the router endpoint renders, read live from
        the target (blanks when there's no target). ``beacon_rate`` mutates the beacon
        deque, so this is its single caller per tick."""
        ap = self.app.target_ap
        if ap is None:
            return dict(essid="", bssid="", channel=0, channel_label="channel unknown",
                        power_dbm=-100, signal=None,
                        uptime_us=None, country_code=None,
                        ssid_note="",
                        identity="", identity_details=None)
        display_ssid, ssid_source = fm.display_ssid(ap, self.app.array)
        essid = fm.truncate_ssid(display_ssid) if display_ssid else "‹hidden›"
        rate, _ = fm.beacon_rate(ap, self._beacon_samples, time.time())
        return dict(essid=essid, bssid=ap.bssid, channel=ap.channel,
                    channel_label=fm.channel_plain_summary(ap),
                    power_dbm=ap.signal, signal=rate, uptime_us=ap.uptime_us,
                    country_code=ap.country_code,
                    ssid_note=(
                        "history" if ssid_source == "history"
                        else "guess" if ssid_source == "sibling" else ""
                    ),
                    identity=ap.identity.summary,
                    identity_details=fm.router_advertised_details(ap))

    def _card_values(self) -> dict:
        """The card endpoint's compose seed: chipset + own MAC from the live pool, plus the
        current dynamic line. Identity then tracks the pool live via ``_sync_card``."""
        chipset, bssid = fm.card_identity(self.app.array)
        return dict(chipset=chipset, bssid=bssid, dynamic=fm.status_under_card())

    def _status(self) -> list[str]:
        """The headline lines for the live target (empty when there's no target)."""
        ap = self.app.target_ap
        if ap is None:
            return []
        return fm.status_headlines(ap, self.app.array, self.app.vault)

    def _dashboard_rows(self) -> list:
        """The packet-dashboard row set for the live target's encryption family (empty when
        there's no target). The widget samples the live counters itself."""
        ap = self.app.target_ap
        return fm.dashboard_rows(ap) if ap is not None else []

    def _live_client_list(self) -> list[Client]:
        """Clients currently heard on the target, including Fake-Connect."""
        ap = self.app.target_ap
        array = self.app.array
        if ap is None or array is None:
            return []
        now = time.time()
        return [
            client
            for client in array.clients.values()
            if client.bssid == ap.bssid
            and (
                client.is_fake
                or now - client.last_seen <= _CLIENT_LIVE_SECONDS
            )
        ]

    def _client_list(self) -> list[Client]:
        """Merge live clients with persisted associations and directed probes."""
        ap = self.app.target_ap
        array = self.app.array
        if ap is None or array is None:
            return []
        rows = {client.mac.casefold(): client for client in self._live_client_list()}
        session_clients = {
            client.mac.casefold(): client for client in array.clients.values()
        }

        for record in self.app.ap_history_store.clients_for_ap(ap.bssid):
            mac = record.client_mac.casefold()
            if mac in rows:
                continue
            source = session_clients.get(mac)
            if source is not None:
                rows[mac] = replace(
                    source,
                    historical=True,
                    history_reasons={"associated"},
                )
            else:
                rows[mac] = Client(
                    mac=record.client_mac,
                    bssid=ap.bssid,
                    first_seen=record.first_seen,
                    last_seen=record.last_seen,
                    historical=True,
                    history_reasons={"associated"},
                )

        if ap.ssid and ap.ssid != "<hidden>":
            ssid = ap.ssid.casefold()
            for record in self.app.hidden_ssid_store.client_probes.values():
                if record.ssid.casefold() != ssid:
                    continue
                mac = record.client_mac.casefold()
                existing = rows.get(mac)
                if existing is not None:
                    if existing.historical:
                        existing.history_reasons.add("probe")
                    continue
                source = session_clients.get(mac)
                if source is not None:
                    observation = source.probe_observations.get(record.ssid)
                    is_historical = (
                        observation is None
                        or observation.historical
                        or time.time() - observation.last_seen > _CLIENT_LIVE_SECONDS
                    )
                    rows[mac] = replace(
                        source,
                        historical=is_historical,
                        history_reasons={"probe"},
                    )
                else:
                    rows[mac] = Client(
                        mac=record.client_mac,
                        first_seen=record.first_seen,
                        last_seen=record.last_seen,
                        historical=True,
                        history_reasons={"probe"},
                    )
        return sorted(
            rows.values(),
            key=lambda client: (client.historical, -client.last_seen, client.mac),
        )

    @staticmethod
    def _render_status(status) -> Text:
        return Text("\n").join(Text.from_markup(s, emoji=False) for s in status)

    def _sync_card(self) -> None:
        """Refresh the card endpoint (picker + art) from the live pool, polled because WlanArray has
        no arrival callback. The shown card is the TX card: the campaign's locked one, else
        select_iface's pick for this target."""
        array = self.app.array
        members = array.members if array else []
        active = Campaign.active
        ap = getattr(self.app, "target_ap", None)
        if active is not None:
            primary = active.iface
        elif ap is not None and array is not None:
            primary = array.select_iface(ap.channel)
        else:
            primary = None
        primary = primary or art.pick_primary(members)   # no capable card: still show something
        card = self.query_one("#card", CardsColumn)
        card.sync(
            members,
            ap.channel if ap is not None else None,
            primary,
            active is not None,
            array,
            active,
        )

    def on_tx_device_picker_selected(self, event: TxDevicePicker.Selected) -> None:
        """User pinned a TX card in the picker: record the preference and sync the endpoint."""
        if self.app.array is not None:
            self.app.array.prefer(event.iface)
        self._sync_card()

    def refresh_buttons(self) -> None:
        """Set each attack button straight from its campaign class + the active campaign.
        No ButtonState in between: read the campaign, write the widget."""
        ap = getattr(self.app, "target_ap", None)
        if ap is None:
            return
        active = Campaign.active
        probing = self._is_probing()
        for cls in fm.BUTTON_CAMPAIGNS:
            btn = self.query_one(f"#{cls.button_id}", Button)
            vault = getattr(self.app, "vault", None)
            visible = (
                cls.visible(ap, vault)
                if cls is FakeConnectCampaign
                else cls.visible(ap)
            )
            btn.display = visible
            running = active is not None and active.key == cls.key and cls.stoppable
            if running:
                btn.label, btn.variant, btn.disabled, reason = cls.run_label, cls.run_variant, False, ""
            else:
                reason = fm.campaign_blocked(
                    cls, ap, vault if cls is FakeConnectCampaign else None,
                )
                btn.label, btn.variant = cls.idle_label, cls.idle_variant
                btn.disabled = reason is not None
            if probing and not running:
                btn.disabled, reason = True, "Disabled while probing"
            btn.tooltip = reason or _BUTTON_TIPS.get(str(btn.label))
        enterprise = self.query_one("#btn-enterprise", Button)
        enterprise.display = is_enterprise_ap(ap)
        enterprise.disabled = False
        enterprise.tooltip = _BUTTON_TIPS["Enterprise"]
        self._refresh_chop_button(ap, active, probing)
        self._refresh_wps_info_button(ap)
        self._refresh_stop_pbc_button(probing)

    def _refresh_chop_button(self, ap, active, probing: bool) -> None:
        """ChopChop: a WEP sub-action, enabled only while the WEP campaign runs."""
        btn = self.query_one("#btn-chop", Button)
        wep_running = active is not None and active.key == "wep"
        chopping = wep_running and getattr(active, "chop_active", False)
        btn.display = WepCampaign.visible(ap)
        btn.disabled = not wep_running or Config.is_silenced(ap.bssid) or probing
        btn.label = "Stop Chop" if chopping else "ChopChop"
        btn.variant = "warning" if chopping else "primary"
        btn.tooltip = _BUTTON_TIPS.get(str(btn.label))

    def _refresh_stop_pbc_button(self, probing: bool) -> None:
        """The transient 'Stop PBC' button (PBC has no start button; it auto-invades)."""
        stop_pbc = self.query_one("#btn-stop-pbc", Button)
        if self._pbc_busy():
            stopping = getattr(self._controls.current, "stopped", False)
            stop_pbc.display = True
            stop_pbc.disabled = stopping or probing         # already draining → no double-stop
            stop_pbc.variant = "error"
            stop_pbc.label = "Stopping…" if stopping else "Stop PBC"
        else:
            stop_pbc.display = False

    def _refresh_wps_info_button(self, ap: AccessPoint) -> None:
        button = self.query_one("#btn-wps-info", Button)
        probing = self._is_wps_probing()
        identity = getattr(ap, "identity", None)
        has_m1_identity = (
            identity is not None and identity.has_source(IdSource.WSC_M1)
        )
        button.display = bool(ap.wps and (
            probing or not has_m1_identity
        ))
        button.label = "Stop Info" if probing else "WPS Info"
        button.variant = "error" if probing else "primary"
        button.disabled = (
            self._is_enterprise_probing()
            or (not probing and self._any_campaign_active())
        )
        button.tooltip = _BUTTON_TIPS[str(button.label)]

    # ----- target (re)acquisition --------------------------------------------

    async def _enter_target(self) -> None:
        """Bind to ``app.target_ap``: stop campaigns, reset state, update panels/radio/log."""
        self.stop_packet_capture(notify=False)
        self._stop_network_analysis()
        self._controls.stop()
        self._stop_probe()

        ap = getattr(self.app, "target_ap", None)
        self._target_ap = ap
        self._refresh_client_connector()
        if ap is None:
            return
        array = self.app.array
        logger.info("[FOCUS] enter: ssid=%r bssid=%s ch=%s", ap.ssid, ap.bssid, ap.channel)

        self._beacon_samples.clear()
        self._events.reset()
        self._eapol_agg.reset()
        self._prev_stats = None        # drop the old target's counters
        self.query_one("#log", LogBand).clear()
        self._load_network_metadata(ap)
        self._start_network_analysis(ap, array)

        status = self._status()
        self._last_status = status
        self.query_one("#status", Static).update(self._render_status(status))
        self.query_one("#dashboard", PacketDashboard).reconfigure(self._dashboard_rows(), array, ap.bssid)
        self.query_one("#card", CardsColumn).update(dynamic=fm.status_under_card())
        self._sync_card()
        self.query_one("#router", RouterEndpoint).update(**self._router_values())
        self.query_one("#clients", ClientsList).sync(self._client_list())
        self._refresh_network_metadata()
        self.refresh_buttons()
        self._balance_status()
        self._refresh_status_footer()  # dashboard footer (cleared by reconfigure)

        # Log initial "target acquired"
        enc = fm.encryption_chip(ap)
        display_ssid, ssid_source = fm.display_ssid(ap, self.app.array)
        if display_ssid:
            if ssid_source in ("history", "sibling"):
                label = "HISTORY" if ssid_source == "history" else "SIBLING GUESS"
                chip = f"[black bold on yellow] {escape(display_ssid)} [/black bold on yellow]"
                self._log(
                    f"[bold]Target acquired:[/bold] {chip} "
                    f"[black bold on yellow] {label} [/black bold on yellow]"
                )
            else:
                chip = f"[black bold on cyan] {escape(display_ssid)} [/black bold on cyan]"
                self._log(f"[bold]Target acquired:[/bold] {chip}")
        else:
            self._log("[bold]Target acquired:[/bold] "
                      "[dim italic]cloaked network (hidden SSID)[/dim italic]")
        self._log(treelog.branch(f"[dim]Encryption:[/dim] {enc}"))
        self._log(treelog.branch(f"[dim]BSSID:[/dim] {ap.bssid}"))
        if array:
            try:
                ok = await array.set_channel_spec(
                    channel_spec_for_ap(ap), scan=False,
                )
            except Exception:
                logger.exception("Focus v2 channel tune failed")
                ok = False
            if ok:
                self._log(treelog.leaf(f"Tuned to [cyan]channel {ap.channel}[/cyan]"))
            else:
                self._log(treelog.leaf(
                    f"[yellow]Tried to tune to channel {ap.channel}[/yellow]"))
        else:
            self._log(treelog.leaf("[yellow]no interface: passive view only[/yellow]"))

        if ap.pmf_required:
            self._log("[bold yellow]PMF Required:[/] "
                      "AP requires [bold]Protected Management Frames[/]")
            self._log(treelog.leaf("[italic]Deauth[/] attacks have been disabled"))

        self._log_band_twins(ap)
        self._log_persisted_history(ap)
        try:
            self.app.ap_history_store.enrich(ap)
        except Exception:
            logger.warning("Could not enrich AP identity from history", exc_info=True)
        self._log_stored_wps_identity(ap)

        locked = self.app.locked_target
        if (
            locked is not None
            and locked.medium == "wifi"
            and locked.kind == "ap"
            and locked.identifier.casefold() == ap.bssid.casefold()
        ):
            self._log(f"[bold cyan]Target lock:[/] {escape(locked.alias)}")
            self.action_capture_packets()

        if Config.is_silenced(ap.bssid):
            self._log_silenced()
            return

        enc = (ap.encryption or "").upper()
        if enc == "WEP":
            self._log("[bold italic]Passively listening[/bold italic] for [bold]WEP IVs[/bold]")
        elif enc not in ("OPEN", "", "WPA3 "):
            # 'Crackable' because the pipeline filters SAE-only out.
            self._log("[bold italic]Passively listening[/bold italic] for")
            self._log(treelog.branch("Crackable 4-Way [bold]Handshakes[/bold]"))
            self._log(treelog.leaf("Crackable [bold]PMKIDs[/bold]"))

    def _log_band_twins(self, ap) -> None:
        """Note if the focused network also exists on another band.

        A band-steered client can keep this link in power-save (Null/keepalive frames only)
        while its real traffic rides the other-band radio, so a data/website capture may need
        the twin BSSID instead of this one."""
        twins = fm.band_twins(ap, self.app.array)
        if not twins:
            return
        for twin in twins[:2]:
            band = "5 GHz" if twin.channel > 14 else "2.4 GHz"
            label = escape(twin.ssid or ap.ssid or "<same SSID>")
            self._log(treelog.branch(
                f"[yellow]Alternate {band} BSSID detected[/yellow]: [cyan]{label}[/cyan] "
                f"[dim]ch {twin.channel} · {twin.bssid}[/dim]"))
        self._log(treelog.leaf(
            f"[dim]current capture remains on ch {ap.channel}; switch targets only if the "
            "client is confirmed on the alternate BSSID[/dim]"))

    def _log_persisted_history(self, ap) -> None:
        """On focus init, print captures/ artifacts for this AP to the log."""
        wps_state = load_run_state(Config.captures_dir, ap.bssid)
        wps_progress = run_progress_line(wps_state) if wps_state else None
        rows = list(self.app.vault.detailed_summary(ap).items())
        if not rows and not wps_progress:
            return
        if rows:
            self._log("[bold]Existing captures[/bold] in [cyan]captures/[/cyan]:")
        # Pad the label column so the dates line up.
        label_w = max((len(f"{label} ({n})") for label, (_cap, n) in rows), default=0)
        for i, (label, (cap, n)) in enumerate(rows):
            # The WPS progress leaf, if present, takes the └, so a saved row is the last leaf only when nothing follows.
            last = i == len(rows) - 1 and wps_progress is None
            line = treelog.leaf if last else treelog.branch
            pad = " " * (label_w - len(f"{label} ({n})"))
            head = f"[bold cyan]{label}[/bold cyan] [dim]({n})[/dim]{pad}"
            dt = datetime.fromtimestamp(cap.timestamp)
            if label == "WEP Key":
                self._log(line(
                    f"{head}  {_recovered_credential_chip('WEP key')} "
                    f"[dim]{dt:%Y-%m-%d %H:%M}[/dim]",
                ))
            elif label in ("WPS PIN", "WPS PBC"):
                creds = [_recovered_credential_chip("PSK")]
                if cap.pin:
                    creds.append("[dim]PIN recovered[/dim]")
                joined = "  ".join(creds) + "  "
                self._log(line(f"{head}  {joined}[dim]{dt:%Y-%m-%d %H:%M}[/dim]"))
            elif label == "WPA PSK":
                self._log(line(
                    f"{head}  {_recovered_credential_chip('PSK')} "
                    f"[dim]{dt:%Y-%m-%d %H:%M}[/dim]",
                ))
            else:
                self._log(line(f"{head}  {dt:%Y-%m-%d} "
                               f"[dim]{dt:%H:%M}[/dim]"))
        if wps_progress is not None:
            self._log(treelog.leaf(wps_progress) if rows else wps_progress)

    # ----- per-tick paint ----------------------------------------------------

    def _tick(self) -> None:
        if self._target_ap is None or not self.is_current:
            return
        self._poll_eap_lab_campaign()
        ap = self._target_ap
        locked = getattr(self.app, "locked_target", None)
        if (
            locked is not None
            and locked.medium == "wifi"
            and locked.kind == "ap"
            and locked.identifier.casefold() == ap.bssid.casefold()
            and time.time() - ap.last_seen > Config.target_reacquire_timeout
        ):
            self.stop_packet_capture(notify=True)
            self.app.locked_target_id = None
            self.notify(
                f"Target {locked.alias} was not reacquired",
                title="Target lock released",
                severity="warning",
            )

        # WEP recovers its key while still running; WPS reaches a terminal phase while its
        # task drains. Ask them to stop so they reap (below) on a following tick.
        cur = self._controls.current
        if isinstance(cur, FakeConnectCampaign):
            self._record_fake_connect_offer(cur)
        if cur is not None and cur.check_auto_stop():
            self._controls.request_stop()

        # Reap a finished campaign: log/save its result, free the slot.
        finished = self._controls.reap()
        if finished is not None:
            handler = getattr(self, f"_finish_{finished.key}", None)
            if handler:
                handler(finished)
        # Clear the manual-stop suppression when the window closes; a fresh one re-arms.
        if not ap.wps_pbc_active:
            self._pbc_user_stopped = False
        if self._should_auto_invade_pbc(ap):
            self._start_pbc_capture(ap)

        status = self._status()
        if status != self._last_status:
            self._last_status = status
            self.query_one("#status", Static).update(self._render_status(status))
        self.query_one("#card", CardsColumn).update(dynamic=fm.status_under_card())
        self._sync_card()
        self.query_one("#router", RouterEndpoint).update(**self._router_values())
        clients = self.query_one("#clients", ClientsList)
        clients.sync(self._client_list())
        clients.set_deauth_enabled(not fm.deauth_blocked(ap))
        self._refresh_client_connector()
        self.refresh_buttons()
        self._balance_status()
        self._sync_bindings()
        self._refresh_status_footer()
        self.query_one("#pcap-recording", Static).update(
            recording_indicator(
                "PCAP RECORDING",
                self._packet_capture is not None,
                detail=pcap_progress(self._packet_capture) if self._packet_capture else None,
            ),
        )
        if self._network_store is not None:
            try:
                self._network_store.flush_if_due()
            except NetworkMetadataStoreError as exc:
                logger.warning("%s", exc)
        self._refresh_network_metadata()
        array = self.app.array
        self._drive_leds(ap, array)
        self._drain_capture_events(ap, array.forged_macs if array else set(), time.time())

    def _should_auto_invade_pbc(self, ap) -> bool:
        if not (ap.wps_pbc_active and self.app.pbc_enabled):
            return False
        if Config.is_silenced(ap.bssid) or ap.is_hidden:
            return False
        if self.app.vault.has_psk(ap) or self._pbc_user_stopped:
            return False
        if time.monotonic() < self._pbc_retry_after or self._pbc_busy():
            return False
        return self._controls.current is None   # no other attack owns the radio

    def _distribute(self) -> None:
        """Fill the mid band to full 2-row sparklines."""
        avail = max(1, self.size.height - _TOPBAR_H - _CHROME_H)
        center = min(_CENTER_MAX, max(_CENTER_MIN, avail - _BOTTOM_MIN))
        center = max(1, min(center, avail - 1))
        mid = self.query_one("#mid")
        mid.styles.height = center
        self.query_one("#bottom").styles.height = avail - center
        pad = max(0, round((self.size.width - _PAD_START) * _PAD_RATE))
        mid.styles.padding = (0, pad, 0, pad)
        self._balance_status()
        self._refresh_client_connector()

    def _refresh_client_connector(self) -> None:
        """Show a thin AP-to-panel link while connected clients are present."""
        horizontal = self.query_one("#client-connector-horizontal", Static)
        vertical = self.query_one("#client-connector-vertical", Static)
        junction = self.query_one("#client-connector-junction", Static)
        pieces = (horizontal, vertical, junction)
        if (
            not self.is_mounted
            or self._target_ap is None
            or not self._live_client_list()
        ):
            for piece in pieces:
                piece.display = False
            return
        router_art = self.query_one("#router-art").region
        clients = self.query_one("#clients").region
        # The art canvas has two transparent cells to the right of the visible
        # router body. Start immediately beside the body, one row below its
        # former top-edge alignment.
        source_x = router_art.right - 2
        source_y = router_art.y + router_art.height // 2 + 1
        target_x = clients.x + clients.width // 2
        target_y = clients.y
        height = target_y - source_y + 1
        horizontal_markup, vertical_markup, junction_markup = _client_connection_segments(
            source_x,
            target_x,
            height,
        )
        if height < 2 or abs(target_x - source_x) < 2:
            for piece in pieces:
                piece.display = False
            return
        left = min(source_x, target_x)
        horizontal.styles.offset = Offset(left, source_y)
        horizontal.styles.width = abs(target_x - source_x) + 1
        horizontal.update(horizontal_markup)
        horizontal.display = True

        vertical_height = height - 2
        if vertical_height:
            vertical.styles.offset = Offset(target_x, source_y + 1)
            vertical.styles.height = vertical_height
            vertical.update(vertical_markup)
            vertical.display = True
        else:
            vertical.display = False

        junction.styles.offset = Offset(target_x, target_y)
        junction.update(junction_markup)
        junction.display = True

    def _balance_status(self) -> None:
        """Center the status label over the sparklines despite the button row on its left."""
        topbar_w = self.query_one("#topbar").content_size.width
        actions_w = self.query_one("#actions").outer_size.width
        widest = max((Text.from_markup(s, emoji=False).cell_len
                      for s in (self._last_status or [])), default=0)
        spacer = min(actions_w, max(0, topbar_w - actions_w - widest))
        if spacer != self._rspacer_w:
            self._rspacer_w = spacer
            self.query_one("#rspacer", Static).styles.width = spacer

    def _refresh_status_footer(self) -> None:
        """Refresh status footer under sparklines."""
        ap = self._target_ap
        if ap is None:
            return
        array = self.app.array
        lines = [Text.from_markup(m, emoji=False)
                 for m in fm.status_under_dash(ap, array, time.time())]
        locked = getattr(self.app, "locked_target", None)
        if (
            locked is not None
            and locked.medium == "wifi"
            and locked.kind == "ap"
            and locked.identifier.casefold() == ap.bssid.casefold()
        ):
            lines.append(Text.from_markup(
                f"[bold cyan]TARGET LOCKED · {escape(locked.alias)}[/bold cyan]",
                emoji=False,
            ))
        findings = enterprise_findings(ap)
        if findings and findings[0].severity >= 3:
            lines.append(Text.from_markup(
                f"[bold red]SECURITY RISK · {escape(findings[0].label)}[/bold red]",
                emoji=False,
            ))
        self.query_one("#dashboard", PacketDashboard).set_footer(lines)

    # ----- endpoint LED flicker (instrumentation) ----------------------------

    # Router LED = RX from the target; card LED = TX we send.
    _RX_KEYS = ("beacon", "data", "eapol", "wep_iv")
    _TX_KEYS = ("inject", "deauth")

    def _drive_leds(self, ap, array) -> None:
        """Flicker the endpoint LEDs on real traffic."""
        if array is None:
            return
        snap = array.packet_stats.snapshot(ap.bssid)
        prev, self._prev_stats = self._prev_stats, snap
        if prev is None:   # first frame after (re)acquire, no delta yet
            return
        if any(snap.get(k, 0) > prev.get(k, 0) for k in self._RX_KEYS):
            self.query_one("#router", RouterEndpoint).flicker()
        if any(snap.get(k, 0) > prev.get(k, 0) for k in self._TX_KEYS):
            self.query_one("#card", CardsColumn).flicker()

    # ----- event log (capture pipeline) --------------------------------------

    def _drain_capture_events(self, ap, forged_macs: Set[str], now: float) -> None:
        # EAPOL + handshake completions go through the aggregator (one tree per client); PMKID / decloak are immediate.
        if Config.is_silenced(ap.bssid):
            return
        for ev in self._events.poll(ap, forged_macs=forged_macs):
            if ev.kind == CaptureKind.EAPOL:
                self._eapol_agg.on_eapol(ev, now)
            elif ev.kind == CaptureKind.HANDSHAKE:
                # Save instantly
                result = self.app.vault.save_handshake(ap, ev.client_mac)
                hint = _save_line(result) if result is not None else None
                self._emit_lines(self._eapol_agg.on_handshake(ev, now, save_hint=hint))
            else:
                self._log_capture_event(ev, ap)
        # Flush any per-client bursts that have gone quiet; label real-but-uncrackable ones.
        for lines in self._eapol_agg.tick(now, label_for=lambda mac: self._uncrackable_reason(ap, mac)):
            self._emit_lines(lines)

    def _emit_lines(self, lines) -> None:
        for ln in lines:
            self._log(ln)

    def _uncrackable_reason(self, ap, mac: str) -> str | None:
        """The uncrackable-AKM badge (SAE/FT/EAP/OWE) for a client's handshake, else None."""
        hs = ap.handshakes.get(mac)
        return handshake_uncrackable_label(hs) if hs is not None else None

    def _log_capture_event(self, ev: CaptureEvent, ap) -> None:
        if ev.kind == CaptureKind.PMKID:
            self._log(
                f"[black bold on green] ✓ PMKID captured [/black bold on green] "
                f"from [bold]{short_sta(ev.client_mac)}[/bold]"
            )
            result = self.app.vault.save_pmkid(ap, ev.client_mac)
            if result is not None:
                self._log(treelog.leaf(_save_line(result)))
        elif ev.kind == CaptureKind.DECLOAK:
            method_label = DECLOAK_METHOD_LABELS.get(ev.method or "", ev.method or "?")
            self._log(
                f"[bold]Decloaked[/bold] [cyan]{escape(ev.bssid)}[/cyan] → "
                f"[green]{escape(ev.ssid or '')}[/green] "
                f"[dim]via {method_label}[/dim]"
            )

    def _log(self, markup: str) -> None:
        ts = time.strftime("%H:%M:%S")
        try:
            log = self.query_one("#log", LogBand)
        except Exception:
            return
        log.write(Text.from_markup(f"[dim]{ts}[/dim]  {markup}", emoji=False))

    # ----- button dispatch ---------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "back":
            await self.action_go_back()
        elif bid == "btn-enterprise":
            self.action_enterprise()
        elif bid == "deauth-all":
            self._request_deauth_broadcast()
        elif bid == "btn-deauth":
            self._request_campaign("deauth")
        elif bid == "btn-pmkid":
            self._request_campaign("pmkid")
        elif bid == "btn-fake-connect":
            self._request_campaign("fake_connect")
        elif bid == "btn-wps-info":
            self.action_wps_info()
        elif bid == "btn-wps-pin":
            self._request_campaign("wps")
        elif bid == "btn-eviltwin":
            self._request_evil_twin()
        elif bid == "btn-gen-ivs":
            self._request_campaign("wep")
        elif bid == "btn-chop":
            self._request_campaign("chop")
        elif bid == "btn-stop-pbc":
            self._user_stop_pbc()

    def on_client_widget_deauth_requested(self, event: ClientWidget.DeauthRequested) -> None:
        self._request_client_deauth(event.mac)

    def on_client_widget_fingerprint_clicked(self, event: ClientWidget.FingerprintClicked) -> None:
        metadata = (
            self._network_store.metadata
            if self._network_store is not None
            else None
        )
        details = (
            event.details
            + "\n"
            + client_network_details(metadata, event.mac)
        )
        self.app.push_screen(FingerprintModal(
            event.mac, event.fingerprint, details=details, offset=event.offset,
        ))

    def on_router_endpoint_identity_requested(self, event: RouterEndpoint.IdentityRequested) -> None:
        self._log_identity_details_text(event.details)

    def _start_wps_probe(self) -> None:
        ap = self._target_ap
        if ap is None or not ap.wps:
            return
        if self._is_probing():
            return
        if self._any_campaign_active():
            self._log(treelog.leaf_fail("cannot probe while attacks are active"))
            return
        self._probe_task = asyncio.create_task(self._run_probe(ap))
        self.refresh_buttons()
        self._sync_bindings()
        self.query_one("#router", RouterEndpoint).update(**self._router_values())

    async def _run_probe(self, ap: AccessPoint) -> None:
        array = self.app.array
        if not array:
            self._log(treelog.leaf_fail("no active interface"))
            return
        iface = array.select_iface(ap.channel)
        if iface is None:
            self._log(treelog.leaf_fail(f"no interface can probe CH {ap.channel}"))
            return
        label = escape(ap.ssid or ap.bssid)
        self._log(treelog.header(
            f"[bold]Identity probe[/bold] on [cyan]{label}[/cyan] [dim](CH {ap.channel})[/dim]"
        ))
        try:
            async with array.claim(iface):
                result = await probe_ap(iface, ap)
                if result.ok:
                    self._log_wps_identity_matched_body(ap)
                else:
                    self._log(treelog.leaf_fail(
                        f"identity probe failed [dim]({escape(result.detail or 'no detail')})[/dim]"
                    ))
        except asyncio.CancelledError:
            self._log(treelog.leaf_fail("identity probe cancelled"))
            raise
        except Exception as exc:
            logger.exception("Active probe failed")
            self._log(treelog.leaf_fail(f"identity probe error: {escape(str(exc))}"))
        finally:
            self._probe_task = None
            try:
                self.refresh_buttons()
                self._sync_bindings()
                self.query_one("#router", RouterEndpoint).update(**self._router_values())
            except Exception:
                pass

    def _log_stored_wps_identity(self, ap: AccessPoint) -> None:
        if not fm.has_stored_wps_identity(ap):
            return
        label = escape(ap.ssid or ap.bssid)
        self._log(treelog.header(
            f"[bold]Identity probe[/bold] on [cyan]{label}[/cyan] "
            f"[dim](CH {ap.channel})[/dim] · [dim]stored[/dim]"
        ))
        self._log_wps_identity_matched_body(ap)

    def _log_wps_identity_matched_body(self, ap: AccessPoint) -> None:
        ident = ap.identity
        summary = (
            ident.summary
            if ident is not None and ident.summary
            else (ap.ssid or ap.bssid)
        )
        self._log(treelog.leaf_ok(
            f"probe matched: [bold]{escape(summary)}[/bold]",
        ))
        self._log_identity_details(ap)

    def _log_identity_details(self, ap: AccessPoint) -> None:
        details = fm.router_advertised_details(ap)
        if details:
            self._log_identity_details_text(details)

    def _log_identity_details_text(self, details: str) -> None:
        self._log("[bold]Router identity[/bold]")
        lines = [line for line in details.splitlines() if line]
        for i, line in enumerate(lines):
            connector = treelog.leaf if i == len(lines) - 1 else treelog.branch
            self._log(connector(line))

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Drive the footer keys off the same state as the buttons."""
        if self._is_probing():
            if action in ("campaign", "deauth_all", "wps_pbc_mode"):
                return False
        ap = self._target_ap
        if action == "campaign":
            if ap is None:
                return False
            key = parameters[0]
            if key == "chop":                      # WEP sub-action: enabled only while WEP runs (and not silenced)
                if not WepCampaign.visible(ap):
                    return False
                cur = self._controls.current
                running = cur is not None and cur.key == "wep"
                return None if (not running or Config.is_silenced(ap.bssid)) else True
            cls = fm.CAMPAIGN_BY_KEY.get(key)
            vault = self.app.vault
            visible = (
                cls.visible(ap, vault)
                if cls is FakeConnectCampaign
                else cls.visible(ap)
            )
            if cls is None or not visible:
                return False
            active = Campaign.active
            if active is not None and active.key == key and cls.stoppable:
                return True
            blocked = fm.campaign_blocked(
                cls, ap, vault if cls is FakeConnectCampaign else None,
            )
            return None if blocked is not None else True
        if action == "enterprise":
            return ap is not None and is_enterprise_ap(ap)
        if action == "deauth_all":
            if ap is None:
                return False
            return None if fm.deauth_blocked(ap) else True
        if action == "wps_info":
            if ap is None or not ap.wps or ap.identity.has_source(IdSource.WSC_M1):
                return None
            if self._is_enterprise_probing():
                return False
            return True if self._is_wps_probing() else not self._any_campaign_active()
        if action == "capture_packets":
            return self._packet_capture is not None or (ap is not None and self.app.array is not None)
        if action == "silence":
            return False if (ap is not None and Config.is_silenced(ap.bssid)) else True
        if action == "unsilence":
            return True if (ap is not None and Config.is_silenced(ap.bssid)) else False
        return True

    def _sync_bindings(self) -> None:
        """Repaint the footer only when a key's shown/greyed state changes."""
        ap = self._target_ap
        if ap is None:
            sig: Optional[tuple] = None
        else:
            active = Campaign.active
            probing = self._is_probing()

            vault = self.app.vault

            def _disabled(cls) -> bool:
                if active is not None and active.key == cls.key and cls.stoppable:
                    return False
                return fm.campaign_blocked(
                    cls, ap, vault if cls is FakeConnectCampaign else None,
                ) is not None

            def _visible(cls) -> bool:
                if cls is FakeConnectCampaign:
                    return cls.visible(ap, vault)
                return cls.visible(ap)

            btn_sig = tuple((cls.key, _visible(cls), True if probing else _disabled(cls))
                            for cls in fm.BUTTON_CAMPAIGNS)
            sig = (btn_sig,
                   is_enterprise_ap(ap),
                   True if probing else fm.deauth_blocked(ap),
                   Config.is_silenced(ap.bssid),
                   bool(ap.wps),
                   ap.identity.has_source(IdSource.WSC_M1),
                   probing,
                   bool(
                       self._controls.current is not None
                       and self._controls.current.key == "fake_connect"
                   ))
        if sig != self._binding_sig:
            self._binding_sig = sig
            self.refresh_bindings()

    def action_campaign(self, camp_key: str) -> None:
        """Toggle a hotkey's campaign."""
        self._request_campaign(camp_key)
        self._sync_bindings()

    def action_enterprise(self) -> None:
        ap = self._target_ap
        if ap is None or not is_enterprise_ap(ap):
            return
        self.app.push_screen(
            EnterprisePanel(
                self._enterprise_systems(ap),
                probing=self._is_enterprise_probing(),
            ),
            self._on_enterprise_panel_action,
        )

    def _on_enterprise_panel_action(self, action: str | None) -> None:
        if action == "probe":
            self._request_enterprise_probe()
        elif action == "cancel_probe":
            self._cancel_enterprise_probe()
        elif action == "save_report":
            self._save_enterprise_report()
        elif action == "eap_lab":
            self._request_eap_lab_honeypot()

    def _request_eap_lab_honeypot(self) -> None:
        ap = self._target_ap
        if ap is None or not is_enterprise_ap(ap):
            return
        if self._is_eap_lab_active():
            self.notify("PEAP EAP lab is already running", severity="warning")
            return
        if self._any_campaign_active():
            self.notify("Another active operation owns the radio", severity="warning")
            return
        self.app.push_screen(
            EapLabModal(
                ap.ssid or "<hidden>",
                ap.channel,
                default_methods=methods_for_ap(ap),
            ),
            self._start_eap_lab_honeypot,
        )

    def _start_eap_lab_honeypot(self, launch: EapLabLaunchConfig | None) -> None:
        if launch is None:
            return
        ap = self._target_ap
        array = self.app.array
        if ap is None or array is None:
            return
        try:
            campaign = PeapHoneypotCampaign(array, ap, launch=launch)
        except RuntimeError as exc:
            self.notify(str(exc), title="EAP lab unavailable", severity="error")
            return
        if campaign.iface is None:
            self.notify(
                f"No spoofable interface can host channel {ap.channel}",
                severity="error",
            )
            return
        if not campaign.run():
            self.notify("The radio is busy with another campaign", severity="warning")
            return
        self._eap_lab_campaign = campaign
        self._eap_lab_event_index = 0
        self._write_log(treelog.header("PEAP EAP lab honeypot"))
        self.notify(
            f"EAP lab active on {ap.ssid} · CH {ap.channel} · twin {campaign.bssid_text}",
            title="EAP lab",
        )

    def _poll_eap_lab_campaign(self) -> None:
        campaign = self._eap_lab_campaign
        if campaign is None:
            return
        events = campaign.stats.events
        for message in events[self._eap_lab_event_index:]:
            self._write_log(treelog.branch(escape(message)))
        self._eap_lab_event_index = len(events)
        ap = self._target_ap
        while campaign.pending_captures and ap is not None:
            capture = campaign.pending_captures.pop(0)
            try:
                saved = self.app.vault.save_mschapv2(
                    ap,
                    capture,
                    lab_bssid=campaign.bssid_text,
                )
            except Exception as exc:
                logger.exception("Could not save MS-CHAPv2 capture")
                self.notify(str(exc), title="Vault save failed", severity="error")
                break
            if saved is not None:
                self._write_log(treelog.branch(
                    f"MS-CHAPv2 saved to Vault · {escape(capture.username)} · "
                    f"{escape(saved.mschapv2.path.name)} + "
                    f"{escape(saved.netntlmv2.path.name)} (Hashcat 5500/5600)"
                ))
        if not campaign.done:
            return
        result = {
            "captured": "[bold green]MS-CHAPv2 CAPTURED[/bold green] · saved to Vault",
            "misconfigured": "[bold yellow]CLIENT MISCONFIGURATION[/bold yellow] · see Vault report",
            "timeout": "[dim]TIMEOUT[/dim] · no MS-CHAPv2 response",
            "stopped": "[dim]STOPPED[/dim]",
            "no-interface": "[red]FAILED[/red] · no compatible interface",
        }.get(campaign.result, escape(campaign.result))
        self._write_log(treelog.leaf(result))
        if ap is not None and campaign.client_assessments:
            try:
                saved = self.app.vault.save_eap_lab_report(
                    ap,
                    lab_bssid=campaign.bssid_text,
                    launch=campaign.launch,
                    clients=campaign.client_assessments,
                    campaign_result=campaign.result,
                )
            except Exception as exc:
                logger.exception("Could not save EAP lab assessment report")
                self.notify(str(exc), title="Vault save failed", severity="error")
                saved = None
            if saved is not None:
                self._write_log(treelog.branch(
                    f"EAP lab assessment saved to Vault · {escape(saved.path.name)}"
                ))
        severity = (
            "warning"
            if campaign.result in ("misconfigured", "timeout", "stopped")
            else "information"
        )
        self.notify(
            "MS-CHAPv2 hash saved to Vault"
            if campaign.result == "captured"
            else f"EAP lab finished: {campaign.result}",
            title="EAP lab",
            severity=severity,
        )
        self._eap_lab_campaign = None

    async def stop_eap_lab_honeypot(self) -> None:
        campaign = self._eap_lab_campaign
        if campaign is not None and not campaign.done:
            await campaign.stop()

    def _save_enterprise_report(self) -> None:
        ap = self._target_ap
        if ap is None or not is_enterprise_ap(ap):
            return
        try:
            result = self.app.vault.save_enterprise_report(ap)
        except Exception as exc:
            logger.exception("Could not save Enterprise report")
            self.notify(str(exc), title="Enterprise report failed", severity="error")
            return
        if result is None:
            self.notify("No Enterprise evidence to save", severity="warning")
            return
        self.notify(
            f"Saved {result.path.name}",
            title="Enterprise report added to Vault",
            severity="information",
        )

    def _cancel_enterprise_probe(self) -> None:
        task = self._enterprise_probe_task
        if task is not None and not task.done():
            task.cancel()
            self.notify("Cancelling Enterprise probe…", severity="warning")

    def _enterprise_systems(self, target: AccessPoint) -> tuple[AccessPoint, ...]:
        array = self.app.array
        if array is None:
            return (target,)
        target_certificates = set(target.enterprise.certificates)
        systems = [
            ap for ap in array.access_points.values()
            if is_enterprise_ap(ap) and (
                ap is target
                or (
                    target.ssid
                    and target.ssid != "<hidden>"
                    and ap.ssid == target.ssid
                )
                or bool(target_certificates & set(ap.enterprise.certificates))
            )
        ]
        systems.sort(key=lambda ap: (ap is not target, ap.bssid))
        return tuple(systems) or (target,)

    def _request_enterprise_probe(self) -> None:
        ap = self._target_ap
        if ap is None or not is_enterprise_ap(ap):
            return
        if self._is_enterprise_probing():
            self.notify("Enterprise probe is already running", severity="warning")
            return
        if self._any_campaign_active():
            self.notify("Another active operation owns the radio", severity="warning")
            return
        self._confirm_active(
            "Enterprise outer-EAP probe",
            (
                "Associates an anonymous temporary client, enumerates EAP methods and "
                "negotiates outer TLS. It stops before inner authentication and sends no secret."
            ),
            self._start_enterprise_probe,
        )

    def _start_enterprise_probe(self) -> None:
        ap = self._target_ap
        if ap is None or self._is_enterprise_probing():
            return
        self._enterprise_probe_task = asyncio.create_task(self._run_enterprise_probe(ap))
        self.refresh_buttons()
        self._sync_bindings()

    async def _run_enterprise_probe(self, ap: AccessPoint) -> None:
        array = self.app.array
        if array is None:
            self.notify("No active interface", severity="error")
            self._enterprise_probe_task = None
            self.refresh_buttons()
            self._sync_bindings()
            return
        iface = array.select_iface(ap.channel)
        if iface is None:
            self.notify(f"No interface can probe channel {ap.channel}", severity="error")
            self._enterprise_probe_task = None
            self.refresh_buttons()
            self._sync_bindings()
            return
        label = escape(ap.ssid or ap.bssid)
        self._log(treelog.header(
            f"[bold]Enterprise probe[/bold] on [cyan]{label}[/cyan] "
            f"[dim](CH {ap.channel})[/dim]"
        ))
        probe: EnterpriseProbe | None = None
        try:
            async with array.claim(iface):
                probe = EnterpriseProbe(
                    iface,
                    ap,
                    tx_observer=array.record_injected_eapol,
                )
                result = await probe.run()
            self._record_enterprise_probe_result(ap, result)
            marker = treelog.leaf_ok if result.ok else treelog.leaf_fail
            self._log(marker(escape(result.detail)))
            self.notify(
                result.detail,
                title=f"Enterprise probe: {result.status}",
                severity="information" if result.ok else "warning",
                timeout=8,
            )
        except asyncio.CancelledError:
            result = (
                probe.cancelled_result()
                if probe is not None else
                EnterpriseProbeResult(False, "cancelled", "probe cancelled by operator")
            )
            self._record_enterprise_probe_result(ap, result)
            self._log(treelog.leaf_fail("Enterprise probe cancelled"))
            self.notify("Enterprise probe cancelled", severity="warning")
        except Exception as exc:
            logger.exception("Enterprise probe failed")
            result = EnterpriseProbeResult(False, "failed", str(exc))
            self._record_enterprise_probe_result(ap, result)
            self._log(treelog.leaf_fail(f"Enterprise probe error: {escape(str(exc))}"))
            self.notify(str(exc), title="Enterprise probe failed", severity="error")
        finally:
            self._enterprise_probe_task = None
            try:
                self.refresh_buttons()
                self._sync_bindings()
            except Exception:
                pass

    def _record_enterprise_probe_result(
        self,
        ap: AccessPoint,
        result: EnterpriseProbeResult,
    ) -> None:
        profile = ap.enterprise
        profile.probe_attempts += 1
        profile.probe_last_status = result.status
        profile.probe_last_detail = result.detail
        profile.probe_last_seen = time.time()
        profile.probe_history.append(EnterpriseProbeRun(
            started_at=result.started_at,
            ended_at=result.ended_at,
            status=result.status,
            detail=result.detail,
            association_ok=result.association_ok,
            eap_method=result.eap_method,
            events=list(result.events),
        ))
        if len(profile.probe_history) > 32:
            del profile.probe_history[:-32]
        profile.server_eap_types.update(result.server_methods)
        profile.tls_versions.update(result.tls.versions)
        profile.tls_client_versions.update(result.tls.client_versions)
        profile.tls_cipher_suites.update(result.tls.cipher_suites)
        profile.tls_client_cipher_suites.update(result.tls.client_cipher_suites)
        profile.tls_server_names.update(result.tls.server_names)
        profile.tls_supported_groups.update(result.tls.supported_groups)
        profile.tls_signature_algorithms.update(result.tls.signature_algorithms)
        for certificate in result.tls.certificates:
            if len(profile.certificates) < 16:
                profile.certificates[certificate.fingerprint] = certificate
        store = self.app.enterprise_session_store
        if result.client_mac:
            client_id = store.client_id(ap.bssid, result.client_mac)
            for session in reversed(profile.sessions):
                if session.client_id != client_id:
                    continue
                session.source = "active_probe"
                session.outcome = "probe_complete" if result.ok else "probe_partial"
                break
        try:
            store.remember(ap, force=True)
        except Exception:
            logger.warning("Could not persist Enterprise probe result", exc_info=True)
        try:
            self.app.vault.save_enterprise_report(ap)
        except Exception:
            logger.warning("Could not save Enterprise report snapshot", exc_info=True)

    def action_wps_info(self) -> None:
        if self._is_wps_probing():
            self._stop_probe()
            self.refresh_buttons()
            self._sync_bindings()
            self.query_one("#router", RouterEndpoint).update(**self._router_values())
            return
        self._start_wps_probe()

    def action_capture_packets(self) -> None:
        if self._packet_capture is not None:
            self.stop_packet_capture()
            return
        ap = self._target_ap
        array = self.app.array
        if ap is None or array is None:
            self.notify("No focused access point", severity="warning")
            return
        directory = Path(Config.captures_dir)
        epoch = int(time.time())
        while True:
            path = directory / (
                f"{safe_ssid(ap.ssid)}_{bssid_to_dashed(ap.bssid)}_"
                f"{epoch}_packet_capture.pcap"
            )
            if not path.exists():
                break
            epoch += 1
        try:
            writer = PcapWriter(
                path,
                max_bytes=Config.target_capture_max_mb * 1024 * 1024,
                max_parts=Config.target_capture_max_parts,
            )
        except OSError as exc:
            self.notify(str(exc), title="Capture failed", severity="error")
            return
        self._packet_capture = writer
        self._packet_capture_array = array
        self._packet_capture_bssid = ap.bssid.lower()
        array.register_packet_callback(self._capture_packet)
        self._log(
            f"[bold cyan]PCAP capture started[/bold cyan] for [bold]{escape(ap.bssid)}[/bold]"
        )
        self._log(f"[dim]{escape(str(path))} · press x to stop[/dim]")

    def _capture_packet(self, packet) -> None:
        writer = self._packet_capture
        target = self._packet_capture_bssid
        if writer is None or target is None or (packet.bssid or "").lower() != target:
            return
        writer.write(packet.raw, time.time())

    def stop_packet_capture(self, *, notify: bool = True) -> None:
        writer = self._packet_capture
        if writer is None:
            return
        array = self._packet_capture_array
        if array is not None:
            array.unregister_packet_callback(self._capture_packet)
        writer.close()
        if self._network_store is not None:
            try:
                self._network_store.save()
            except NetworkMetadataStoreError as exc:
                logger.warning("%s", exc)
                if notify:
                    self.notify(str(exc), title="Metadata save failed", severity="warning")
        self.app.vault.refresh()
        self._packet_capture = None
        self._packet_capture_array = None
        self._packet_capture_bssid = None
        self._log(f"[bold green]PCAP saved[/bold green] · {writer.count} packets")
        self._log(f"[dim]{escape(str(writer.path))}[/dim]")
        if notify:
            self.notify(
                f"{writer.count} packets\n{writer.path.name}",
                title="PCAP capture saved",
                timeout=6,
            )

    @staticmethod
    def _is_open_ap(ap) -> bool:
        """True only for clear-text OPEN, never OWE/Enhanced Open."""
        return (ap.encryption or "").casefold() == "open" and not ap.akm_suites

    def _load_network_metadata(self, ap) -> None:
        panel = self.query_one("#network-metadata", NetworkMetadataPanel)
        clients = self.query_one("#clients", ClientsList)
        open_ap = self._is_open_ap(ap)
        self._network_store = NetworkMetadataStore(
            self.app.ap_history_store, ap.bssid, ap.ssid,
        )
        panel.display = open_ap
        clients.set_open_network_metadata(
            self._network_store.metadata,
            enabled=open_ap,
        )
        for error in self._network_store.errors:
            logger.warning("%s", error)
        if not open_ap:
            self._network_analyzer = None

    def _start_network_analysis(self, ap, array) -> None:
        """Observe open-AP metadata for the Focus lifetime, independently of PCAP recording."""
        if not self._is_open_ap(ap) or self._network_store is None or array is None:
            return
        self._network_analyzer = PassiveNetworkAnalyzer(self._network_store.metadata)
        self._network_observation_array = array
        self._network_bssid = ap.bssid.casefold()
        array.register_packet_callback(self._observe_network_packet)

    def _observe_network_packet(self, packet) -> None:
        analyzer = self._network_analyzer
        target = self._network_bssid
        if (
            analyzer is not None
            and target is not None
            and (getattr(packet, "bssid", "") or "").casefold() == target
        ):
            analyzer.observe(packet)

    def _stop_network_analysis(self) -> None:
        array, self._network_observation_array = self._network_observation_array, None
        if array is not None:
            array.unregister_packet_callback(self._observe_network_packet)
        if self._network_store is not None:
            try:
                self._network_store.save()
            except NetworkMetadataStoreError as exc:
                logger.warning("%s", exc)
        self._network_analyzer = None
        self._network_bssid = None
        self._network_store = None

    def _refresh_network_metadata(self) -> None:
        panel = self.query_one("#network-metadata", NetworkMetadataPanel)
        store = self._network_store
        ap = self._target_ap
        open_ap = ap is not None and self._is_open_ap(ap)
        panel.set_metadata(
            store.metadata if store is not None else None,
            live=self._network_analyzer is not None,
        )
        self.query_one("#clients", ClientsList).set_open_network_metadata(
            store.metadata if store is not None else None,
            enabled=open_ap,
        )

    def _request_campaign(self, camp_key: str) -> None:
        toggle = self._campaign_toggles.get(camp_key)
        if toggle is None:
            return
        active = Campaign.active
        if camp_key == "chop" or (active is not None and active.key == camp_key):
            toggle()
            return
        impacts = {
            "deauth": "Transmits repeated deauthentication frames and may disconnect clients.",
            "wep": "Transmits replay traffic to generate IVs on the target network.",
            "pmkid": "Actively associates with the access point to request authentication data.",
            "fake_connect": (
                "Authenticates and associates a randomized temporary client with the open AP, "
                "claims and releases a DHCP lease, then contacts "
                f"{CONNECTIVITY_URL} to test Internet/captive-portal access."
            ),
            "wps": "Actively attempts WPS enrollment and PIN recovery.",
        }
        ap = self._target_ap
        vault = self.app.vault
        if camp_key == "fake_connect" and ap is not None:
            enc = (ap.encryption or "").casefold()
            cred = FakeConnectCampaign.resolve_credential(ap, vault)
            if enc == "wep" and cred is None:
                impacts[camp_key] = (
                    "Authenticates and associates a randomized temporary client with the WEP AP. "
                    "It does not send encrypted data, request DHCP, or test Internet access."
                )
            elif enc.startswith("wpa2") and cred is not None:
                impacts[camp_key] = (
                    "Runs a WPA2-PSK 4-way handshake with the captured passphrase, "
                    "associates a randomized temporary client, claims and releases a DHCP "
                    f"lease, then contacts {CONNECTIVITY_URL} to test Internet/captive-portal access."
                )
        self._confirm_active(fm.CAMPAIGN_BY_KEY[camp_key].idle_label, impacts[camp_key], toggle)

    def _request_evil_twin(self) -> None:
        active = Campaign.active
        if active is not None and active.key == "eviltwin":
            self._toggle_eviltwin()
            return
        self._confirm_active(
            "Evil Twin",
            "Creates a look-alike access point and may disconnect clients from the original.",
            self._toggle_eviltwin,
        )

    def _request_deauth_broadcast(self) -> None:
        ap = self._target_ap
        if ap is not None and is_wifi_ap_whitelisted(self.app.target_store, ap.bssid):
            self.notify(
                f"{ap.bssid} is on the whitelist",
                severity="warning",
                title="Whitelist",
            )
            return
        self._confirm_active(
            "Broadcast deauthentication",
            "Transmits deauthentication frames that may disconnect every associated client.",
            lambda: self.run_worker(self._run_deauth_broadcast(), exclusive=True),
        )

    def _request_client_deauth(self, mac: str) -> None:
        if is_wifi_client_whitelisted(self.app.target_store, mac):
            self.notify(
                f"{mac} is on the whitelist",
                severity="warning",
                title="Whitelist",
            )
            return
        self._confirm_active(
            "Client deauthentication",
            f"Transmits deauthentication frames to client {mac}.",
            lambda: self.run_worker(self._run_deauth_selected(mac), exclusive=True),
        )

    def _confirm_active(self, action_name: str, impact: str, callback) -> None:
        ap = self._target_ap
        if ap is None:
            return
        if not Config.confirm_active_actions:
            callback()
            return
        target = f"{ap.ssid or '<hidden>'} ({ap.bssid})"
        self.app.push_screen(
            ConfirmActiveActionModal(action_name, target, impact),
            lambda confirmed: callback() if confirmed else None,
        )

    def action_deauth_all(self) -> None:
        """'d': one-shot broadcast deauth, matching the client-panel button."""
        self._request_deauth_broadcast()

    def action_wps_pbc_mode(self) -> None:
        """'w': toggle the shared WPS PBC auto-invade."""
        enabled = not getattr(self.app, "pbc_enabled", False)
        if enabled and Config.confirm_active_actions:
            ap = self._target_ap
            target = f"{ap.ssid or '<hidden>'} ({ap.bssid})" if ap else "detected access points"
            self.app.push_screen(
                ConfirmActiveActionModal(
                    "Automatic WPS PushButton capture",
                    target,
                    "Automatically associates when an open WPS PBC window is detected.",
                ),
                lambda confirmed: self._set_pbc_enabled(True) if confirmed else None,
            )
            return
        self._set_pbc_enabled(enabled)

    def _set_pbc_enabled(self, enabled: bool) -> None:
        self.app.pbc_enabled = enabled
        Config.auto_wps_pbc = enabled
        self.app.persist_config()
        self._log_pbc_status()

    def _log_pbc_status(self) -> None:
        if getattr(self.app, "pbc_enabled", True):
            self._log("[bold]WPS PushButton Extraction[/bold] "
                      "[bold green]enabled[/bold green] [dim](press w to toggle)[/dim]")
        else:
            self._log("[bold]WPS PushButton Extraction[/bold] "
                      "[yellow]disabled[/yellow] [dim](detect only, press w to toggle)[/dim]")

    def action_silence(self) -> None:
        self._toggle_silence()

    def action_unsilence(self) -> None:
        self._toggle_silence()

    def _toggle_silence(self) -> None:
        """Flip the focused AP's silenced state (campaigns off, handshakes/PMKIDs ignored)."""
        if self._target_ap is None:
            return
        bssid = self._target_ap.bssid.lower()
        if bssid in Config.silenced_bssids:
            Config.silenced_bssids.remove(bssid)
            self._log("[green bold] ● AP [italic]Un[/italic]Silenced ✓[/]")
            self._log("[dim green]" + treelog.leaf("campaigns enabled, listening for handshakes") + "[/]")
        else:
            Config.silenced_bssids.append(bssid)
            self._log_silenced()
        self.app.persist_config()
        self.refresh_buttons()
        self._sync_bindings()

    def _log_silenced(self) -> None:
        self._log("[yellow bold] ● AP Silenced[/] [red]✗S[/]")
        self._log("[yellow dim]" + treelog.branch("campaigns disabled, handshakes ignored.") + "[/]")
        self._log("[yellow dim]" + treelog.leaf("press [bold]s[/bold] to unsilence.") + "[/]")

    # ----- deauth ------------------------------------------------------------

    async def _run_deauth_broadcast(self) -> None:
        """Worker: broadcast-deauth every station associated with the focused AP."""
        ap = self._target_ap
        array = self.app.array
        card = array.select_iface(ap.channel) if (ap and array) else None
        if not ap or card is None:
            self._log("[red]✗ No target / no card on this channel. Aborting Broadcast.[/red]")
            return
        self._log("[bold]Broadcast de-auth: all clients[/bold]")
        try:
            _rounds, broadcast_count = deauth_limits()
            sent = await card.deauth_broadcast(ap.bssid, count=broadcast_count)
        except Exception as exc:
            logger.exception("Broadcast deauth crashed")
            self._log(treelog.leaf_fail(f"Broadcast failed: {escape(str(exc))}"))
            return
        # Broadcast frames are never ACKed: a neutral leaf (no green ✓).
        self._log(treelog.leaf(f"sent {sent} de-auth frames [dim](AP→broadcast)[/dim]"))

    async def _run_deauth_selected(self, mac: str) -> None:
        """Worker: deauth a specific client (the inline ✕ that was clicked)."""
        ap = self._target_ap
        array = self.app.array
        card = array.select_iface(ap.channel) if (ap and array) else None
        if not ap or card is None:
            self._log("[red]✗ No target / no card on this channel. Aborting Deauth.[/red]")
            return
        self._log(f"[bold]De-authenticating Client {escape(mac)}[/bold]")
        try:
            client_rounds, _broadcast_count = deauth_limits()
            res = await card.deauth_client(ap.bssid, mac, rounds=client_rounds)
        except Exception as exc:
            logger.exception("Deauth %s crashed", mac)
            self._log(treelog.leaf_fail(f"Deauth failed: {escape(str(exc))}"))
            return
        self._log(treelog.branch(
            f"sent {res.total_sent} de-auth frames "
            f"[dim](AP↔Client ×{res.client_sent})[/dim]"))
        if not res.measured:  # card lacks TX-ACK detection, nothing to confirm
            self._log(treelog.leaf("[dim]delivery not measured (no TX-ACK on this card)[/dim]"))
            return
        detail = f"[dim](client {res.client_acks}/{res.client_sent} · AP {res.ap_acks}/{res.ap_sent})[/dim]"
        if res.total_acked:
            self._log(treelog.leaf(
                f"[bold][cyan]{res.total_acked}[/cyan]/{res.total_sent} de-auths ACK'd[/bold] {detail}"))
        else:
            self._log(treelog.leaf(
                f"[bold][red]0[/red]/{res.total_sent} de-auths ACK'd[/bold] [dim](silent AP & client)[/dim]"))

    # ----- PMKID -------------------------------------------------------------

    def _toggle_pmkid(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "pmkid":
            self._controls.request_stop()
        else:
            self._start_pmkid()
        self.refresh_buttons()

    def _start_pmkid(self) -> None:
        ap = self._target_ap
        array = self.app.array
        if not ap or not array:
            self._log("[red]✗ No target / interface. Aborting PMKID harvest.[/red]")
            return
        self._log(pmkid_log.header(escape(ap.ssid or ap.bssid)))
        self._controls.start(PmkidHarvestAttack, array, ap,
                             log=lambda m: self._log(treelog.branch(m)))

    def _finish_pmkid(self, camp) -> None:
        """Handle a completed harvest."""
        if camp.pmkid:
            result = self.app.vault.save_pmkid(camp.target, camp.client_mac)
            hint = _save_line(result) if result is not None else None
            self._emit_lines(pmkid_log.verdict_success(hint))
            # Detector skips forged MACs, so toast the active-harvest win here too.
            name = camp.target.ssid or camp.target.bssid
            body = (f"[bold]{escape(name)}[/bold] on channel [bold]{camp.target.channel}[/bold] "
                    f"[dim bold](BSSID: {escape(camp.target.bssid)})[/dim bold]")
            self.notify(body, title=f"{CAPTURE_TOAST_TITLES[CaptureKind.PMKID]} (M1)", timeout=6)
        elif getattr(camp, "stopped", False):
            self._log(treelog.leaf_fail("[bright_red bold]Stopped harvest[/]"))
        else:
            self._emit_lines(pmkid_log.verdict_failure(camp.fail_reason))

    # ----- Fake-Connect ------------------------------------------------------

    def _toggle_fake_connect(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "fake_connect":
            self._controls.request_stop()
        else:
            ap = self._target_ap
            array = self.app.array
            if not ap or not array:
                self._log("[red]✗ No target / interface. Aborting Fake-Connect.[/red]")
                return
            self._log(
                f"[bold cyan]Fake-Connect[/bold cyan] → "
                f"[bold]{escape(ap.ssid or ap.bssid)}[/bold]"
            )
            credential = FakeConnectCampaign.resolve_credential(ap, self.app.vault)
            self._controls.start(
                FakeConnectCampaign, array, ap,
                log=lambda message: self._log(treelog.branch(message)),
                credential=credential,
            )
        self.refresh_buttons()

    def _finish_fake_connect(self, camp) -> None:
        self._record_fake_connect_offer(camp)
        if camp.fail_reason and not camp.stopped:
            self._log(treelog.leaf_fail(f"Fake-Connect failed: {escape(camp.fail_reason)}"))
        else:
            self._log(treelog.leaf("[dim]Fake client disconnected[/dim]"))

    def _record_fake_connect_offer(self, camp: FakeConnectCampaign) -> None:
        """Publish Fake-Connect network evidence to the panel and durable JSON."""
        store = self._network_store
        if store is None:
            return
        changed = False
        now = time.time()
        if camp.dhcp_offer is not None and not camp.metadata_recorded:
            changed |= store.metadata.observe_dhcp_offer(
                camp.dhcp_offer,
                client_mac=camp.client_mac,
                now=now,
            )
            camp.metadata_recorded = True
        lease = getattr(camp, "dhcp_lease", None)
        if lease is not None and not getattr(camp, "lease_recorded", False):
            changed |= store.metadata.observe_dhcp_offer(
                lease,
                client_mac=camp.client_mac,
                now=now,
                source="dhcp_ack_active",
            )
            camp.lease_recorded = True
        connectivity = getattr(camp, "connectivity_result", None)
        if connectivity is not None and not getattr(camp, "connectivity_recorded", False):
            expires_at = (
                now + lease.lease_seconds
                if lease is not None and lease.lease_seconds is not None
                else None
            )
            changed |= store.metadata.observe_connectivity(
                connectivity,
                client_mac=camp.client_mac,
                now=now,
                expires_at=expires_at,
            )
            camp.connectivity_recorded = True
        arp_neighbors = getattr(camp, "arp_neighbors", None)
        if arp_neighbors and not getattr(camp, "arp_neighbors_recorded", False):
            changed |= store.metadata.observe_arp_neighbors(
                arp_neighbors, now=now,
            )
            camp.arp_neighbors_recorded = True
        if not changed:
            return
        try:
            store.save()
        except NetworkMetadataStoreError as exc:
            logger.warning("%s", exc)
        self._refresh_network_metadata()

    # ----- Deauth ------------------------------------------------------------

    def _toggle_deauth(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "deauth":
            self._controls.request_stop()
        else:
            self._start_deauth()
        self.refresh_buttons()

    def _start_deauth(self) -> None:
        ap = self._target_ap
        array = self.app.array
        if not ap or not array:
            self._log("[red]✗ No target / interface. Aborting Deauth.[/red]")
            return
        self._log(f"[bold]Deauth[/bold] of [bold]{escape(ap.ssid or ap.bssid)}[/bold]: "
                  "forcing a re-handshake")
        self._controls.start(DeauthCampaign, array, ap, log=self._log)

    def _finish_deauth(self, camp) -> None:
        """Reap a completed deauth run. A captured handshake is saved+toasted by the
        always-on capture path (CaptureKind.HANDSHAKE); we only log the campaign's end."""
        if camp.captured:
            self._log("[bold green]✓ Deauth provoked a crackable handshake[/bold green]")
        else:
            self._log("[bright_red bold]Deauth stopped[/]")

    # ----- EvilTwin ----------------------------------------------------------

    def _toggle_eviltwin(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "eviltwin":
            self._controls.request_stop()
        else:
            self._start_eviltwin()
        self.refresh_buttons()

    def _start_eviltwin(self) -> None:
        ap = self._target_ap
        array = self.app.array
        if not ap or not array or not array.members:
            self._log("[red]✗ No target / interface. Cannot start EvilTwin.[/red]")
            return
        self.app.push_screen(EvilTwinInputModal(ap, array.members), self._on_eviltwin_input)

    def _on_eviltwin_input(self, evil_input: Optional[EvilTwinInput]) -> None:
        """The modal's callback: build + run EvilTwin from its input (the one campaign
        with a pre-construction step, so it can't go through a plain toggle)."""
        if evil_input is None:
            return
        ap, array = self._target_ap, self.app.array
        if not ap or not array:
            return
        try:
            started = self._controls.start(EvilTwinCampaign, array, ap, evil_input=evil_input)
        except Exception as exc:
            logger.exception("EvilTwin start failed")
            self._log(f"[bold red]✗ EvilTwin failed to start:[/bold red] {escape(str(exc))}")
            return
        if started is None:
            return
        self._log(f"[bold cyan]EvilTwin[/bold cyan] of [bold cyan]"
                  f"{escape(ap.ssid or ap.bssid)}[/bold cyan] active on ch {evil_input.twin_channel}"
                  f" [dim]({evil_input.twin_bssid})[/dim]")
        self._log(treelog.branch(f"[italic]punting clients[/italic] [dim]on[/dim] ch {ap.channel}"))
        self._log(treelog.leaf("[dim]waiting for clients to auth…[/dim]"))
        self.refresh_buttons()

    def _finish_eviltwin(self, camp) -> None:
        """Reap a finished EvilTwin (user-stopped, or captured and released the radio itself)."""
        if camp.captured:
            self._log("[bold green]✓ EvilTwin captured a crackable handshake[/bold green]")
        else:
            self._log("[bold red]EvilTwin stopped[/bold red]")

    # ----- WEP: Generate IVs (Replay) + Chop ---------------------------------

    def _toggle_generate_ivs(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "wep":
            if cur.recovered_key is None:
                self._controls.request_stop()
            else:
                self._controls.stop()          # finished campaign lingering; clear then restart
                self._start_generate_ivs()
        else:
            self._start_generate_ivs()
        self.refresh_buttons()

    def _start_generate_ivs(self) -> None:
        ap = self._target_ap
        array = self.app.array
        if not ap or not array:
            self._log("[red]✗ No target / interface. Cannot Generate IVs.[/red]")
            return
        try:
            self._controls.start(WepCampaign, array, ap, log=self._log)
        except Exception as exc:
            logger.exception("Generate IVs start failed")
            self._log(f"[bold red]✗ Generate IVs failed to start:[/bold red] {escape(str(exc))}")

    def _finish_wep(self, camp) -> None:
        if camp.recovered_key is not None:
            result = self.app.vault.save_wep_key(camp.target, camp.recovered_key)
            if result is not None:
                self._log(treelog.leaf(_save_line(result)))

    def _toggle_chop(self) -> None:
        camp = self._controls.current
        if camp is None or camp.key != "wep":
            self._log("[yellow]Start Replay first[/yellow] [dim](ChopChop "
                      "manufactures an ARP seed for the replay engine)[/dim]")
            return
        if camp.chop_active:
            camp.stop_chop()
            self._log("[cyan]→ Chop stopped[/cyan] [dim](back to ARP replay)[/dim]")
        else:
            camp.start_chop()
        self.refresh_buttons()

    # ----- WPS PIN -----------------------------------------------------------

    def _toggle_wps_pin(self) -> None:
        cur = self._controls.current
        if cur is not None and cur.key == "wps":
            self._controls.request_stop()
        else:
            self._start_wps_pin()
        self.refresh_buttons()

    def _start_wps_pin(self) -> None:
        ap = self._target_ap
        array = self.app.array
        if not ap or not array:
            self._log("[red]✗ No target / pool. Cannot start WPS PIN.[/red]")
            return
        # Warn when the elected card can't HW-ACK a spoofed MAC (still runs PIN fine, just spammy).
        card = array.select_iface(ap.channel)
        if card is not None:
            warning = card.active_monitor_warning()
            if isinstance(warning, str):
                self._log(warning)
        self._launch_wps_pin(ap, array)

    def _launch_wps_pin(self, ap, array) -> None:
        try:
            name = escape(ap.ssid or ap.bssid)
            self._log(f"[bold]WPS PIN brute[/bold] started on [bold cyan]{name}[/bold cyan]")
            self._controls.start(WpsCampaign, array, ap,
                                 log=lambda m: self._log(treelog.branch(m)))
        except Exception as exc:
            logger.exception("WPS PIN start failed")
            self._log(f"[bold red]✗ WPS PIN failed to start:[/bold red] {escape(str(exc))}")

    def _finish_wps(self, camp) -> None:
        """Reap a finished WPS PIN sweep: log/save the found PIN, else the give-up reason."""
        ssid = escape(camp.target.ssid or camp.bssid)
        if camp.state.found_pin:
            camp.target.wps_pin = camp.state.found_pin
            camp.target.wps_pin_psk = camp.state.found_psk
            self._log(treelog.branch_ok(
                f"[black bold on cyan]  WPS PIN for {ssid}: "
                f"{escape(camp.state.found_pin)}  [/black bold on cyan]"))
            self._log(treelog.branch(
                f"[black bold on green] Password for {ssid}: "
                f"\"{escape(camp.state.found_psk or '')}\" [/black bold on green]"))
            try:
                result = self.app.vault.save_wps_pin(
                    camp.target, camp.state.found_pin, camp.state.found_psk or "")
                if result is None:
                    self._log(treelog.leaf("[dim](save failed)[/dim]"))
                else:
                    self._log(treelog.leaf(_save_line(result)))
            except Exception:
                self._log(treelog.leaf("[dim](save failed)[/dim]"))
        elif getattr(camp, "fail_reason", None):
            self._log(treelog.leaf_fail(
                f"[bold red]giving up:[/bold red] [yellow]{escape(camp.fail_reason)}[/yellow]"))
        else:
            self._log(treelog.leaf(
                f"[yellow]WPS PIN stopped[/yellow] "
                f"[dim]({camp.state.tested} tested, phase {camp.state.phase})[/dim]"))

    # ----- WPS PBC auto-capture ----------------------------------------------

    def _start_pbc_capture(self, ap) -> None:
        array = self.app.array
        if not array:
            return
        self._log("[bold cyan]WPS PushButton:[/bold cyan] [bold green]Window Open[/bold green] "
                  "(auto-capturing PSK)")
        self._controls.start(WpsPbcCapture, array, ap,
                             log=lambda m: self._log(treelog.branch(m)))

    def _finish_pbc(self, camp) -> None:
        """Handle a completed PBC attempt."""
        ap = camp.target
        if getattr(camp, "stopped", False):
            self._log(treelog.leaf(
                "[yellow]stopped[/yellow] [dim](radio freed; auto-invade resumes on "
                "the next window)[/dim]"))
            return
        if camp.error is not None:
            self._log(treelog.leaf_fail(f"capture error: {escape(str(camp.error))}"))
            return
        outcome = camp.outcome
        if outcome is None:
            return
        if outcome.result is PinResult.SUCCESS:
            ap.wps_pbc_psk = outcome.psk
            name = escape(outcome.ssid or ap.ssid or ap.bssid)
            self._log(treelog.branch(
                f"[black bold on green] Password for {name}: "
                f"\"{escape(outcome.psk)}\" [/black bold on green]"))
            try:
                result = self.app.vault.save_wps_pbc(ap, outcome.psk)
                if result is None:
                    self._log(treelog.leaf("[dim](save failed)[/dim]"))
                else:
                    self._log(treelog.leaf(_save_line(result)))
            except Exception:
                self._log(treelog.leaf("[dim](save failed)[/dim]"))
        else:
            self._pbc_retry_after = time.monotonic() + _PBC_RETRY_COOLDOWN_S
            self._log(treelog.leaf_warn(
                f"{outcome.result.value} [dim]({escape(outcome.detail)})[/dim], "
                f"retrying in {_PBC_RETRY_COOLDOWN_S:.0f}s while the window's open"))

    def _user_stop_pbc(self) -> None:
        """The transient 'Stop PBC' button."""
        cur = self._controls.current
        if cur is None or cur.key != "pbc":
            return
        self._pbc_user_stopped = True
        self._controls.request_stop()
        self.refresh_buttons()

    # ----- navigation --------------------------------------------------------

    def action_targets_editor(self) -> None:
        self.app.open_targets_editor()

    async def action_go_back(self) -> None:
        running = self._running_actions_on_leave()
        if running:
            self.app.push_screen(
                ConfirmLeaveFocusModal(running, destination="the scanner"),
                self._on_leave_focus_confirmed,
            )
            return
        await self._do_go_back()

    async def _on_leave_focus_confirmed(self, confirmed: bool) -> None:
        if confirmed:
            await self._do_go_back()

    async def _do_go_back(self) -> None:
        # Tear down any running attack: Scanner doesn't own the AP's channel, and a forged daemon would keep injecting.
        self.stop_packet_capture(notify=False)
        self._stop_network_analysis()
        self._controls.stop()
        self._stop_probe()
        ap = self._target_ap
        logger.info("[FOCUS] leave: ssid=%r bssid=%s",
                    getattr(ap, "ssid", None), getattr(ap, "bssid", None))
        self.app.pop_screen()
