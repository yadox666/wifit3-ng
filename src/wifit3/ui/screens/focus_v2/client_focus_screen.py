"""Client Focus: spatial layout mirroring AP Focus for a station target."""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Static

from wifit3.ui.notification_center import WifiteHeader

from wifit3.campaigns import treelog
from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.open_probe_ap import OpenProbeApCampaign
from wifit3.id import fingerprint, vendor_for_mac
from wifit3.models import AccessPoint, Client
from wifit3.persist.common import bssid_to_dashed, safe_ssid
from wifit3.persist.config import Config
from wifit3.persist.network_metadata import NetworkMetadataStore, NetworkMetadataStoreError
from wifit3.persist.pcap import PcapWriter
from wifit3.safety import deauth_limits
from wifit3.ui.network_metadata_panel import NetworkMetadataPanel, client_network_details
from wifit3.ui.open_probe_honeypot import start_open_probe_test
from wifit3.ui.recording_indicator import pcap_progress, recording_indicator
from wifit3.targeting import is_wifi_ap_whitelisted, is_wifi_client_whitelisted
from wifit3.ui.screens.confirm_active import ConfirmActiveActionModal, ConfirmLeaveFocusModal
from wifit3.ui.screens.open_probe_modal import OpenProbeSsidModal
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.wlan.channels import ChannelSpec, channel_spec_for_ap
from wifit3.wlan.network_metadata import PassiveNetworkAnalyzer

from ... import focus_model as fm
from . import art
from .card_endpoint import CardEndpoint
from .client_endpoint import ClientEndpoint
from .clients_list import ClientsList, ClientWidget, FingerprintModal
from .log_band import LogBand
from .packet_dashboard import PacketDashboard
from .tx_picker import TxDevicePicker

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

logger = logging.getLogger(__name__)

_CLIENT_LIVE_SECONDS = 10.0
_ENDPOINT_W = 20
_TOPBAR_H = 3
_CHROME_H = 2
_BORDER = "$primary"
_CENTER_MAX = 13
_CENTER_MIN = 7
_BOTTOM_MIN = 6
_PAD_START = 80
_PAD_RATE = 0.4
_RX_KEYS = ("beacon", "data", "eapol", "wep_iv")
_TX_KEYS = ("inject", "deauth")


class ClientFocusView(Screen):
    """Focus screen for a Wi‑Fi client (station) target."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("d", "deauth_client", "Deauth client", show=True),
        Binding("D", "deauth_ap", "Deauth AP", show=True),
        Binding("a", "toggle_probe_honeypot", "Probe honeypot", show=True),
        Binding("x", "toggle_capture", "Capture PCAP", show=True),
        Binding("shift+t", "targets_editor", "Targets", show=True),
    ]

    CSS = """
    ClientFocusView { layout: vertical; background: $surface; }
    #topbar { height: %(top)d; }
    #actions { width: auto; height: 100%%; }
    #topbar Button { height: 3; width: auto; min-width: 0; margin: 0 1 0 0; }
    #status { width: 1fr; height: 3; content-align: center middle; text-align: center; }
    #rspacer { width: 0; height: 1; }
    #pcap-recording { width: 20; height: 3; content-align: center middle; text-align: center; }
    #mid { height: 1fr; }
    #card, #client-endpoint { width: %(ew)d; align: center middle; }
    #client-endpoint { align: center bottom; }
    #dashboard { width: 1fr; height: 100%%; padding: 0 1; }
    .endpoint-art { width: %(ew)d; background: transparent; }
    .ap-static, .ap-essid, .ap-power { width: 100%%; }
    #bottom { height: 1fr; }
    #activity { width: 1fr; height: 100%%; overflow-y: auto; }
    #network-metadata { margin: 0 0 1 0; }
    #log { width: 1fr; height: 1fr; border: round %(border)s;
           border-title-color: %(border)s; border-title-style: bold; padding: 0 1; }
    #clients { width: 54; height: 100%%; border: round %(border)s;
               border-title-color: %(border)s; border-title-style: bold; padding: 0 1; }
    #client-rows { width: 100%%; height: 1fr; }
    .associated-ap-banner {
        width: 100%%; height: 1; margin: 0 0 1 0; color: cyan; text-style: bold;
    }
    .bcast-btn { width: 100%%; height: 1; min-width: 0; border: none; margin: 0 0 1 0;
                 background: $error; color: $text; content-align: center middle; }
    .client-columns { height: 1; width: 100%%; color: $text-muted; text-style: bold; }
    .client-row { height: 1; width: 100%%; }
    .fake-client .cl-bssid, .fake-client .cl-mfr { color: yellow; text-style: bold; }
    .historical-client { color: $text-muted; opacity: 65%%; }
    .historical-client .cl-bssid, .historical-client .cl-mfr,
    .historical-client .cl-pwr, .historical-client .cl-pkts { color: $text-muted; }
    .cl-fp { width: 2; }
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
    #client-identity.identity-known { text-style: underline bold; color: $accent; }
    """ % {"ew": _ENDPOINT_W, "top": _TOPBAR_H, "border": _BORDER}

    def __init__(self) -> None:
        super().__init__()
        self._target_client: Client | None = None
        self._target_ap: AccessPoint | None = None
        self._last_status: list[str] | None = None
        self._prev_stats = None
        self._signal_samples: deque = deque(maxlen=20)
        self._writer: PcapWriter | None = None
        self._array = None
        self._client_mac: str | None = None
        self._network_bssid: str | None = None
        self._network_store: NetworkMetadataStore | None = None
        self._network_analyzer: PassiveNetworkAnalyzer | None = None
        self._network_observer_registered = False
        self._last_network_packet = None
        self._last_network_touched: set[str] = set()
        self._open_probe_campaign: OpenProbeApCampaign | None = None
        self._open_probe_event_index = 0
        self._open_probe_saved_clients: set[str] = set()
        self._rspacer_w = -1

    def compose(self) -> ComposeResult:
        yield WifiteHeader()
        with Horizontal(id="topbar"):
            with Horizontal(id="actions"):
                yield Button("‹ Clients", id="back")
                probe = Button("Probe Honeypot", id="btn-probe-honeypot", variant="primary")
                probe.display = False
                yield probe
                yield Button("Deauth client", id="btn-deauth-client", variant="error")
                yield Button("Deauth AP", id="btn-deauth-ap", variant="error")
            yield Static("", id="status")
            yield Static("", id="rspacer")
            yield Static("", id="pcap-recording")
        with Horizontal(id="mid") as mid:
            mid.ALLOW_SELECT = False
            yield CardEndpoint(**self._card_values(), id="card")
            yield PacketDashboard(fm.client_dashboard_rows(None, None), id="dashboard")
            yield ClientEndpoint(**self._client_endpoint_values(), id="client-endpoint")
        with Horizontal(id="bottom"):
            with Vertical(id="activity"):
                panel = NetworkMetadataPanel(id="network-metadata")
                panel.display = False
                yield panel
                yield LogBand([], id="log")
            yield ClientsList([], id="clients")
        yield GlobalJobTracker()
        yield Footer()

    async def on_mount(self) -> None:
        self.set_interval(0.1, self._tick)
        self._distribute()
        await self._enter_target()

    def on_unmount(self) -> None:
        self.stop_capture(notify=False)
        self._stop_network_analysis()

    async def on_screen_resume(self) -> None:
        client = getattr(self.app, "target_client", None)
        if client is not self._target_client:
            await self._enter_target()

    def on_resize(self) -> None:
        self._distribute()

    async def _enter_target(self) -> None:
        client = getattr(self.app, "target_client", None)
        self._target_client = client
        self._target_ap = getattr(self.app, "target_ap", None)
        if client is None:
            self.app.pop_screen()
            return
        array = self.app.array
        self.query_one("#log", LogBand).clear()
        self._load_network_metadata(client, self._target_ap)
        if self._target_ap is not None and array is not None:
            self._start_network_analysis(client, self._target_ap)
            await array.set_channel_spec(channel_spec_for_ap(self._target_ap), scan=False)
        elif array is not None:
            channel = self._probe_channel(client)
            if channel is not None:
                await array.set_channel_spec(ChannelSpec(channel), scan=False)
        self._log_client_acquired(client)
        self._refresh_all()

    def _probe_channel(self, client: Client) -> int | None:
        best = None
        for observation in client.probe_observations.values():
            if best is None or observation.last_seen > best.last_seen:
                best = observation
        return best.channel if best is not None else None

    def _log_client_acquired(self, client: Client) -> None:
        fp = fingerprint(client.mac)
        badge = fp.emoji if fp else "💻"
        vendor = vendor_for_mac(client.mac) or "Unknown"
        self._log(
            f"[bold]Client acquired:[/bold] {badge} "
            f"[black bold on cyan] {escape(client.mac)} [/black bold on cyan] "
            f"[dim]· {escape(vendor)}[/dim]"
        )
        ap = self._target_ap
        if ap is not None:
            ssid = ap.ssid or "‹hidden›"
            self._log(treelog.branch(
                f"[dim]Associated AP:[/dim] [bold]{escape(ssid)}[/bold] · {escape(ap.bssid)}"
            ))
        probes = sorted(client.probed_ssids)
        if probes:
            self._log(treelog.branch(
                f"[dim]Probe SSIDs ({len(probes)}):[/dim] "
                + ", ".join(escape(s) for s in probes[:6])
                + (" …" if len(probes) > 6 else "")
            ))
        self._log_probe_details(client)

    def _log_probe_details(self, client: Client) -> None:
        for ssid in sorted(client.probed_ssids):
            obs = client.probe_observations.get(ssid)
            if obs is None:
                continue
            age = max(0, int(time.time() - obs.last_seen))
            hist = " · history" if obs.historical else ""
            self._log(treelog.leaf(
                f"{escape(ssid)} · CH {obs.channel} · {obs.count} probes · {age}s ago{hist}"
            ))

    def _tick(self) -> None:
        client = self._live_client()
        if client is None:
            return
        self._target_client = client
        if client.bssid and self.app.array:
            ap = self.app.array.access_points.get(client.bssid)
            if ap is not None:
                self._target_ap = ap
        self._poll_open_probe()
        status = self._status()
        if status != self._last_status:
            self._last_status = status
            self.query_one("#status", Static).update(self._render_status(status))
        self._sync_card()
        self.query_one("#client-endpoint", ClientEndpoint).update(
            **self._client_endpoint_values()
        )
        dashboard_bssid = fm.client_dashboard_bssid(
            client, self._target_ap, self._open_probe_campaign,
        )
        rows = fm.client_dashboard_rows(client, self._target_ap)
        dash = self.query_one("#dashboard", PacketDashboard)
        if dash._bssid != dashboard_bssid or dash._rows != rows:
            dash.reconfigure(rows, self.app.array, dashboard_bssid)
        clients = self.query_one("#clients", ClientsList)
        clients.sync(self._client_panel_list())
        clients.set_associated_ap(self._target_ap)
        clients.set_deauth_enabled(self._deauth_allowed())
        self._refresh_probe_button()
        self._refresh_deauth_buttons()
        self._refresh_network_panel(client)
        self._drive_leds(dashboard_bssid)
        self.query_one("#pcap-recording", Static).update(
            recording_indicator(
                "PCAP RECORDING",
                self._writer is not None,
                detail=pcap_progress(self._writer) if self._writer else None,
            ),
        )

    def _live_client(self) -> Client | None:
        seed = self._target_client or getattr(self.app, "target_client", None)
        if seed is None:
            return None
        array = self.app.array
        if array is None:
            return seed
        live = array.clients.get(seed.mac)
        return live if live is not None else seed

    def _refresh_all(self) -> None:
        client = self._live_client()
        if client is None:
            return
        status = self._status()
        self._last_status = status
        self.query_one("#status", Static).update(self._render_status(status))
        bssid = fm.client_dashboard_bssid(
            client, self._target_ap, self._open_probe_campaign,
        )
        self.query_one("#dashboard", PacketDashboard).reconfigure(
            fm.client_dashboard_rows(client, self._target_ap),
            self.app.array,
            bssid,
        )
        self.query_one("#client-endpoint", ClientEndpoint).update(
            **self._client_endpoint_values()
        )
        self._sync_card()
        panel = self.query_one("#clients", ClientsList)
        panel.sync(self._client_panel_list())
        panel.set_associated_ap(self._target_ap)
        panel.set_deauth_enabled(self._deauth_allowed())
        self._refresh_probe_button()
        self._balance_status()

    def _status(self) -> list[str]:
        client = self._live_client()
        if client is None:
            return []
        active = (
            self._open_probe_campaign is not None
            and not self._open_probe_campaign.done
        )
        return fm.client_status_headlines(
            client, self._target_ap, honeypot_active=active,
        )

    @staticmethod
    def _render_status(status: list[str]) -> Text:
        return Text("\n").join(Text.from_markup(s, emoji=False) for s in status)

    def _card_values(self) -> dict:
        chipset, bssid = fm.card_identity(self.app.array)
        return dict(chipset=chipset, bssid=bssid, dynamic=fm.status_under_card())

    def _client_endpoint_values(self) -> dict:
        client = self._live_client()
        if client is None:
            return dict(
                mac="", label="", power_dbm=-100, signal=None, identity_details=None,
            )
        fp = fingerprint(client.mac)
        label = fp.label if fp else (vendor_for_mac(client.mac) or "Client")
        rate = self._client_signal_rate(client)
        return dict(
            mac=client.mac,
            label=label,
            power_dbm=client.signal,
            signal=rate,
            identity_details=fm.client_advertised_details(client),
        )

    def _client_signal_rate(self, client: Client) -> float | None:
        now = time.time()
        self._signal_samples.append((now, client.packets))
        if len(self._signal_samples) < 2:
            return None
        t0, p0 = self._signal_samples[0]
        t1, p1 = self._signal_samples[-1]
        dt = max(0.4, t1 - t0)
        return max(0.0, (p1 - p0) / dt)

    def _sync_card(self) -> None:
        array = self.app.array
        members = array.members if array else []
        ap = self._target_ap
        live = self._live_client()
        channel = ap.channel if ap is not None else (self._probe_channel(live) if live else None)
        primary = art.pick_primary(members)
        card = self.query_one("#card", CardEndpoint)
        card.set_art(art.art_path_for(primary) if primary is not None else art.pool_art(members))
        card.sync_picker(members, channel, primary, Campaign.active is not None)
        card.update_bssid(members[0].mac_address if len(members) == 1 else None)
        card.update(dynamic=fm.status_under_card())

    def _client_panel_list(self) -> list[Client]:
        client = self._live_client()
        array = self.app.array
        if client is None:
            return []
        rows: dict[str, Client] = {}
        campaign = self._open_probe_campaign
        if campaign is not None and not campaign.done and array is not None:
            honeypot_bssids = {ep.bssid_text for ep in campaign.endpoints}
            for sta in array.clients.values():
                if sta.bssid in honeypot_bssids or sta.mac.casefold() == client.mac.casefold():
                    rows[sta.mac.casefold()] = sta
            for endpoint in campaign.endpoints:
                for mac, attempt in endpoint.stats.clients.items():
                    if mac.casefold() in rows:
                        continue
                    rows[mac.casefold()] = Client(
                        mac=mac,
                        bssid=endpoint.bssid_text,
                        packets=attempt.probes + attempt.auth + attempt.assoc,
                        is_fake=not attempt.is_target,
                    )
            if client.mac.casefold() not in rows:
                rows[client.mac.casefold()] = replace(
                    client, bssid=campaign.endpoints[0].bssid_text, is_fake=False,
                )
            return sorted(rows.values(), key=lambda c: (c.mac != client.mac, -c.packets, c.mac))
        if self._target_ap is not None and array is not None:
            now = time.time()
            for sta in array.clients.values():
                if sta.bssid == self._target_ap.bssid and (
                    sta.is_fake or now - sta.last_seen <= _CLIENT_LIVE_SECONDS
                ):
                    rows[sta.mac.casefold()] = sta
            if client.mac.casefold() not in rows:
                rows[client.mac.casefold()] = client
            return sorted(
                rows.values(),
                key=lambda c: (c.mac.casefold() != client.mac.casefold(), -c.packets, c.mac),
            )
        return [client]

    def _deauth_allowed(self) -> bool:
        ap = self._target_ap
        if ap is None:
            return False
        return not fm.deauth_blocked(ap) and not (
            self._open_probe_campaign is not None and not self._open_probe_campaign.done
        )

    def _refresh_deauth_buttons(self) -> None:
        allowed = self._deauth_allowed()
        for bid in ("btn-deauth-client", "btn-deauth-ap"):
            btn = self.query_one(f"#{bid}", Button)
            btn.disabled = not allowed

    def _refresh_probe_button(self) -> None:
        client = self._live_client()
        btn = self.query_one("#btn-probe-honeypot", Button)
        if client is None or not client.probe_observations:
            btn.display = False
            return
        btn.display = True
        running = self._open_probe_campaign is not None and not self._open_probe_campaign.done
        btn.label = "Stop Honeypot" if running else "Probe Honeypot"
        btn.variant = "warning" if running else "primary"
        btn.disabled = (
            not running
            and (Campaign.active is not None or not client.probe_observations)
        )

    def _drive_leds(self, bssid: str | None) -> None:
        array = self.app.array
        if array is None or not bssid:
            return
        snap = array.packet_stats.snapshot(bssid)
        prev, self._prev_stats = self._prev_stats, snap
        if prev is None:
            return
        if any(snap.get(k, 0) > prev.get(k, 0) for k in _RX_KEYS):
            self.query_one("#client-endpoint", ClientEndpoint).flicker()
        if any(snap.get(k, 0) > prev.get(k, 0) for k in _TX_KEYS):
            self.query_one("#card", CardEndpoint).flicker()

    def _distribute(self) -> None:
        avail = max(1, self.size.height - _TOPBAR_H - _CHROME_H)
        center = min(_CENTER_MAX, max(_CENTER_MIN, avail - _BOTTOM_MIN))
        center = max(1, min(center, avail - 1))
        self.query_one("#mid").styles.height = center
        self.query_one("#bottom").styles.height = avail - center
        pad = max(0, round((self.size.width - _PAD_START) * _PAD_RATE))
        self.query_one("#mid").styles.padding = (0, pad, 0, pad)
        self._balance_status()

    def _balance_status(self) -> None:
        actions = self.query_one("#actions")
        rspacer = self.query_one("#rspacer", Static)
        width = max(0, actions.size.width)
        if width != self._rspacer_w:
            self._rspacer_w = width
            rspacer.styles.width = width

    def _log(self, markup: str) -> None:
        ts = time.strftime("%H:%M:%S")
        try:
            self.query_one("#log", LogBand).write(
                Text.from_markup(f"[dim]{ts}[/dim]  {markup}", emoji=False)
            )
        except Exception:
            pass

    def _running_actions_on_leave(self) -> list[str]:
        actions: list[str] = []
        campaign = self._open_probe_campaign
        if campaign is not None and not campaign.done:
            actions.append("Probe honeypot")
        if self._writer is not None:
            actions.append("Client packet capture")
        if self._network_analyzer is not None:
            actions.append("Passive network metadata")
        return actions

    def action_targets_editor(self) -> None:
        self.app.open_targets_editor()

    async def action_go_back(self) -> None:
        running = self._running_actions_on_leave()
        if running:
            self.app.push_screen(
                ConfirmLeaveFocusModal(running, destination="the client list"),
                self._on_leave_focus_confirmed,
            )
            return
        await self._do_go_back()

    async def _on_leave_focus_confirmed(self, confirmed: bool) -> None:
        if confirmed:
            await self._do_go_back()

    async def _do_go_back(self) -> None:
        await self.stop_honeypot()
        self.stop_capture()
        self._stop_network_analysis()
        self.app.resume_clients_view = True
        self.app.pop_screen()

    async def stop_honeypot(self) -> None:
        campaign = self._open_probe_campaign
        if campaign is not None and not campaign.done:
            await campaign.stop()
        self._open_probe_campaign = None

    def action_toggle_capture(self) -> None:
        if self._writer is not None:
            self.stop_capture()
            return
        client = self._live_client()
        ap = self._target_ap
        if client is not None and ap is not None:
            self._start_capture(client, ap)

    def action_deauth_client(self) -> None:
        client = self._live_client()
        if client is None:
            return
        self._request_client_deauth(client.mac)

    def action_deauth_ap(self) -> None:
        self._request_deauth_broadcast()

    def action_toggle_probe_honeypot(self) -> None:
        running = self._open_probe_campaign
        if running is not None and not running.done:
            running.stopped = True
            self._log(treelog.leaf_warn("Stopping probe honeypot"))
            return
        client = self._live_client()
        if client is None or not client.probe_observations:
            self.notify("No probe observations for this client", severity="warning")
            return
        if Campaign.active is not None:
            self.notify("The radio is busy with another campaign", severity="warning")
            return
        self.app.push_screen(
            OpenProbeSsidModal(client),
            lambda selection: self._confirm_probe(client, selection) if selection else None,
        )

    def _confirm_probe(self, client: Client, selection: tuple[str, int, str]) -> None:
        ssid, timeout, encryption = selection
        if Config.confirm_active_actions:
            self.app.push_screen(
                ConfirmActiveActionModal(
                    "Automated probe honeypot test",
                    f"{escape(client.mac)} probing for {escape(ssid)}",
                    f"Broadcasts a {encryption} test AP for up to {timeout // 60} minute(s).",
                ),
                lambda ok: self._start_probe(client, ssid, timeout, encryption) if ok else None,
            )
            return
        self._start_probe(client, ssid, timeout, encryption)

    def _start_probe(self, client: Client, ssid: str, timeout: int, encryption: str) -> None:
        campaign = start_open_probe_test(self.app, client, ssid, timeout, encryption)
        if campaign is None:
            self.notify("Could not start probe honeypot (radio busy or no interface)", severity="error")
            return
        self._open_probe_campaign = campaign
        self._open_probe_event_index = 0
        self._open_probe_saved_clients.clear()
        self._log(treelog.header(f"Probe honeypot · {encryption} · {escape(ssid)}"))
        self.notify(f"Honeypot started for {ssid}", title="Probe honeypot")
        self._refresh_probe_button()

    def _poll_open_probe(self) -> None:
        campaign = self._open_probe_campaign
        if campaign is None:
            return
        for message in campaign.stats.events[self._open_probe_event_index:]:
            self._log(treelog.branch(escape(message)))
        self._open_probe_event_index = len(campaign.stats.events)
        if campaign.done:
            self._log(treelog.leaf(f"Honeypot finished: {escape(campaign.result or 'done')}"))
            self._open_probe_campaign = None
            self._refresh_probe_button()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "back":
            await self.action_go_back()
        elif bid == "btn-probe-honeypot":
            self.action_toggle_probe_honeypot()
        elif bid == "btn-deauth-client":
            self.action_deauth_client()
        elif bid == "btn-deauth-ap":
            self.action_deauth_ap()
        elif bid == "deauth-all":
            self._request_deauth_broadcast()

    def on_client_widget_deauth_requested(self, event: ClientWidget.DeauthRequested) -> None:
        self._request_client_deauth(event.mac)

    def on_client_widget_fingerprint_clicked(self, event: ClientWidget.FingerprintClicked) -> None:
        metadata = (
            self._network_store.metadata if self._network_store is not None else None
        )
        details = event.details + "\n" + client_network_details(metadata, event.mac)
        self.app.push_screen(
            FingerprintModal(event.mac, event.fingerprint, details=details, offset=event.offset),
        )

    def on_client_endpoint_identity_requested(self, event: ClientEndpoint.IdentityRequested) -> None:
        self._log("[bold]Client details[/bold]")
        for line in event.details.splitlines():
            self._log(treelog.leaf(line))

    def on_tx_device_picker_selected(self, event: TxDevicePicker.Selected) -> None:
        if self.app.array is not None:
            self.app.array.prefer(event.iface)
        self._sync_card()

    def _request_deauth_broadcast(self) -> None:
        ap = self._target_ap
        if ap is None:
            self.notify("Client is not associated with a live AP", severity="warning")
            return
        if is_wifi_ap_whitelisted(self.app.target_store, ap.bssid):
            self.notify(
                f"{ap.bssid} is on the whitelist",
                severity="warning",
                title="Whitelist",
            )
            return
        self._confirm_active(
            "Broadcast deauthentication",
            "May disconnect every client on the associated AP.",
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
        client = self._live_client()
        if client is None:
            return
        if not Config.confirm_active_actions:
            callback()
            return
        target = client.mac
        if self._target_ap is not None:
            target = f"{self._target_ap.ssid or '<hidden>'} ({self._target_ap.bssid}) · client {client.mac}"
        self.app.push_screen(
            ConfirmActiveActionModal(action_name, target, impact),
            lambda confirmed: callback() if confirmed else None,
        )

    async def _run_deauth_broadcast(self) -> None:
        ap = self._target_ap
        array = self.app.array
        card = array.select_iface(ap.channel) if (ap and array) else None
        if not ap or card is None:
            self._log("[red]✗ No associated AP on this channel.[/red]")
            return
        self._log("[bold]Broadcast de-auth on associated AP[/bold]")
        try:
            _rounds, broadcast_count = deauth_limits()
            sent = await card.deauth_broadcast(ap.bssid, count=broadcast_count)
        except Exception as exc:
            self._log(treelog.leaf_fail(f"Broadcast failed: {escape(str(exc))}"))
            return
        self._log(treelog.leaf(f"sent {sent} de-auth frames [dim](AP→broadcast)[/dim]"))

    async def _run_deauth_selected(self, mac: str) -> None:
        ap = self._target_ap
        array = self.app.array
        card = array.select_iface(ap.channel) if (ap and array) else None
        if not ap or card is None:
            self._log("[red]✗ No associated AP on this channel.[/red]")
            return
        self._log(f"[bold]De-authenticating {escape(mac)}[/bold]")
        try:
            client_rounds, _ = deauth_limits()
            res = await card.deauth_client(ap.bssid, mac, rounds=client_rounds)
        except Exception as exc:
            self._log(treelog.leaf_fail(f"Deauth failed: {escape(str(exc))}"))
            return
        self._log(treelog.leaf(
            f"sent {res.total_sent} de-auth frames "
            f"[dim](AP↔Client ×{res.client_sent})[/dim]"
        ))

    def check_action(self, action: str, parameters: tuple):
        if action == "toggle_probe_honeypot":
            client = self._live_client()
            if client is None or not client.probe_observations:
                return False
            return True
        if action in ("deauth_client", "deauth_ap"):
            return None if self._deauth_allowed() else False
        return super().check_action(action, parameters)

    @staticmethod
    def _is_open_ap(ap) -> bool:
        return (ap.encryption or "").casefold() == "open" and not ap.akm_suites

    def _load_network_metadata(self, client: Client, ap: AccessPoint | None) -> None:
        panel = self.query_one("#network-metadata", NetworkMetadataPanel)
        if ap is None or not self._is_open_ap(ap):
            self._network_store = None
            panel.display = False
            return
        self._network_store = NetworkMetadataStore(
            self.app.ap_history_store, ap.bssid, ap.ssid,
        )
        panel.display = True

    def _refresh_network_panel(self, client: Client) -> None:
        panel = self.query_one("#network-metadata", NetworkMetadataPanel)
        panel.set_metadata(
            self._network_store.metadata if self._network_store is not None else None,
            live=self._network_analyzer is not None,
            client_mac=client.mac,
        )

    def _start_network_analysis(self, client, ap) -> None:
        self._array = self.app.array
        self._client_mac = client.mac
        self._network_bssid = ap.bssid.casefold()
        if not self._is_open_ap(ap) or self._array is None:
            return
        self._network_analyzer = PassiveNetworkAnalyzer(self._network_store.metadata)
        self._array.register_packet_callback(self._observe_network_packet)
        self._network_observer_registered = True

    def _observe_network_packet(self, packet) -> None:
        self._last_network_packet = packet
        self._last_network_touched = set()
        if (
            self._network_analyzer is not None
            and (getattr(packet, "bssid", "") or "").casefold() == self._network_bssid
        ):
            self._last_network_touched = self._network_analyzer.observe(packet)

    def _stop_network_analysis(self) -> None:
        if self._network_observer_registered and self._array is not None:
            self._array.unregister_packet_callback(self._observe_network_packet)
        self._network_observer_registered = False
        if self._network_store is not None:
            try:
                self._network_store.save()
            except NetworkMetadataStoreError as exc:
                logger.warning("%s", exc)
        self._network_store = None
        self._network_analyzer = None

    def _start_capture(self, client, ap) -> None:
        if self._writer is not None or self.app.array is None:
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
            self._writer = PcapWriter(
                path,
                max_bytes=Config.target_capture_max_mb * 1024 * 1024,
                max_parts=Config.target_capture_max_parts,
            )
        except OSError as exc:
            self.notify(str(exc), title="Capture failed", severity="error")
            return
        self._array = self.app.array
        self._client_mac = client.mac
        self._network_bssid = ap.bssid.casefold()
        self._array.register_packet_callback(self._capture_packet)

    def _capture_packet(self, packet) -> None:
        writer = self._writer
        if writer is None or self._client_mac is None:
            return
        packet_client = getattr(packet, "client_mac", None)
        already_observed = packet is self._last_network_packet
        touched = self._last_network_touched if already_observed else set()
        if (
            not already_observed
            and self._network_analyzer is not None
            and (getattr(packet, "bssid", "") or "").casefold() == self._network_bssid
        ):
            touched = self._network_analyzer.observe(packet)
        direct = (
            packet_client is not None
            and packet_client.casefold() == self._client_mac.casefold()
        )
        if not direct and self._client_mac.casefold() not in touched:
            return
        writer.write(packet.raw, time.time())

    def stop_capture(self, *, notify: bool = True) -> None:
        writer, self._writer = self._writer, None
        if writer is None:
            return
        if self._array is not None:
            self._array.unregister_packet_callback(self._capture_packet)
        writer.close()
        if self._network_store is not None:
            try:
                self._network_store.save()
            except NetworkMetadataStoreError as exc:
                logger.warning("%s", exc)
        self.app.vault.refresh()
        if notify:
            self.notify(
                f"{writer.count} packets\n{writer.path.name}",
                title="Client PCAP saved",
                timeout=6,
            )
