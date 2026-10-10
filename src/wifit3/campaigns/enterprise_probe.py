from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import struct
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from wifit3.campaigns.auth_assoc import Association, WlanTransport, build_client_leaving
from wifit3.campaigns.eap_lab_config import read_eap_lab_user, resolve_lab_identities
from wifit3.crack.mschapv2 import (
    EAP_TYPE_MSCHAPV2,
    parse_mschapv2_challenge_payload,
)
from wifit3.dot11 import str_to_mac
from wifit3.dot11.eap import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_RESPONSE,
    EAP_SUCCESS,
    EAP_TLS_TYPES,
    EAP_TYPE_GTC,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_MD5,
    EAP_TYPE_NAK,
    EAP_TYPE_PAP,
    EAP_TYPE_PEAP,
    EAP_TYPE_TLS,
    EAP_TYPE_TTLS,
    eap_identity_response_frame,
    eap_nak_response_frame,
    eap_tls_response_frame,
    eapol_start_frame,
)
from wifit3.dot11.enterprise import (
    TlsMetadata,
    eap_tls_fragment,
    parse_der_certificate,
    parse_tls_records,
)
from wifit3.dot11.ie import force_psk_akm
from wifit3.dot11.packet import EapPacket
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models import EnterpriseProbeEvent

EnterpriseProbeEventCallback = Callable[[EnterpriseProbeEvent], None]


_SUPPORTED_AKMS = (1, 5)
_MAX_TLS_BYTES = 1_048_576
_TLS_FRAGMENT_BYTES = 900
_MAX_INNER_EAP = 1024
_EAP_CODES = {EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE}
_HT_CIPHERS = {"CCMP", "GCMP", "GCMP-256", "CCMP-256"}
_DEFAULT_LAB_INNER = b"labuser"
_RADIUS_USER_NAME = 1
_RADIUS_EAP_MESSAGE = 79
_RADIUS_VENDOR = 26
_MS_VENDOR_ID = 311
_MS_CHAP_CHALLENGE = 11
_PHASE_REATTACH_REASONS = frozenset({
    "failure",
    "timeout",
    "timeout_tls",
    "timeout_inner",
    "tls_error",
})
logger = logging.getLogger(__name__)


def _inner_eap_header_status(buffer: bytes) -> str:
    """Return complete, incomplete, or condensed for PEAP phase-2 bytes."""
    if not buffer:
        return "incomplete"
    if len(buffer) < 4:
        if len(buffer) == 1 and buffer[0] == EAP_TYPE_IDENTITY:
            return "condensed"
        return "condensed" if buffer[0] not in _EAP_CODES else "incomplete"
    code = buffer[0]
    length = struct.unpack(">H", buffer[2:4])[0]
    if code not in _EAP_CODES or length < 4 or length > _MAX_INNER_EAP:
        return "condensed"
    if len(buffer) < length:
        return "incomplete"
    return "complete"


def _synthesize_peap_inner(buffer: bytes) -> tuple[bytes, int] | None:
    """Rebuild a full EAP Request from PEAP's type+payload tunnel format."""
    if not buffer:
        return None
    eap_type = buffer[0]
    if eap_type == EAP_TYPE_IDENTITY:
        return struct.pack(">BBH", EAP_REQUEST, 0, 5) + bytes([EAP_TYPE_IDENTITY]), 1
    if eap_type == EAP_TYPE_MSCHAPV2:
        payload = bytes(buffer[1:])
        if len(payload) < 4:
            return None
        identifier = payload[1]
        body = bytes([EAP_TYPE_MSCHAPV2]) + payload
        return struct.pack(">BBH", EAP_REQUEST, identifier, 4 + len(body)) + body, len(buffer)
    if eap_type == EAP_TYPE_NAK:
        payload = bytes(buffer[1:])
        body = bytes([EAP_TYPE_NAK]) + payload
        return struct.pack(">BBH", EAP_REQUEST, 0, 4 + len(body)) + body, len(buffer)
    return None


def _iter_radius_avps(data: bytes):
    offset = 0
    while offset + 2 <= len(data):
        length = data[offset + 1]
        if length < 2 or offset + length > len(data):
            break
        yield data[offset], data[offset + 2: offset + length]
        offset += length


def _ms_chap_challenge_from_vsa(value: bytes) -> bytes | None:
    if len(value) < 6:
        return None
    if int.from_bytes(value[:4], "big") != _MS_VENDOR_ID:
        return None
    vendor_type, vendor_length = value[4], value[5]
    if vendor_length < 2 or 4 + vendor_length > len(value):
        return None
    payload = value[6: 4 + vendor_length]
    if vendor_type == _MS_CHAP_CHALLENGE and payload:
        return payload
    return None


class _PcapIface:
    """Write injected frames while delegating the live radio."""

    def __init__(self, iface, write) -> None:
        self._iface = iface
        self._write = write

    def __getattr__(self, name):
        return getattr(self._iface, name)

    async def send_no_wait(self, frame, **kwargs):
        if frame:
            self._write(bytes(frame))
        return await self._iface.send_no_wait(frame, **kwargs)

    async def send_until_ack(self, frame, **kwargs):
        if frame:
            self._write(bytes(frame))
        return await self._iface.send_until_ack(frame, **kwargs)


def _ap_allows_ht(ap) -> bool:
    pairwise = getattr(ap, "pairwise_ciphers", None) or []
    if not pairwise:
        return True
    return any(cipher in _HT_CIPHERS for cipher in pairwise)


def _assoc_fail_detail(ap, fail_reason: str | None) -> str:
    detail = fail_reason or "association rejected"
    ouis = {
        str(oui).casefold()
        for oui in getattr(getattr(ap, "capabilities", None), "vendor_ouis", set()) or set()
    }
    if "caps-unsupported" in detail and "00:0c:42" in ouis:
        return (
            f"{detail}; AirOS airMAX is advertised - disable airMAX "
            "so standard 802.11 clients can associate"
        )
    return detail


@dataclass(slots=True)
class EnterpriseProbeResult:
    ok: bool
    status: str
    detail: str
    association_ok: bool = False
    eap_method: int | None = None
    client_mac: str | None = None
    server_methods: set[int] = field(default_factory=set)
    tls: TlsMetadata = field(default_factory=TlsMetadata)
    started_at: float = field(default_factory=time.time)
    ended_at: float = field(default_factory=time.time)
    events: list[EnterpriseProbeEvent] = field(default_factory=list)
    pcap_path: str | None = None
    report_path: str | None = None
    inner_eap_types: set[int] = field(default_factory=set)
    compatibility_notes: list[str] = field(default_factory=list)
    mschap_username: str | None = None
    mschap_challenge_hex: str | None = None
    mschap_challenge_path: str | None = None
    dump_path: str | None = None
    lab_correlation: dict | None = None


class _TlsClient:
    def __init__(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self.ssl = context.wrap_bio(self._incoming, self._outgoing, server_side=False)
        self.complete = False
        self.error: str | None = None

    def feed(self, incoming: bytes = b"") -> tuple[bytes, bytes]:
        if incoming:
            self._incoming.write(incoming)
        if not self.complete:
            try:
                self.ssl.do_handshake()
                self.complete = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as exc:
                self.error = str(exc)
        app = b""
        if self.complete:
            for _ in range(32):
                chunk = self.read_app()
                if chunk:
                    app += chunk
                pending = self.ssl.pending()
                if not chunk and pending == 0:
                    break
        return self._drain_outgoing(), app

    def drain_app(self) -> bytes:
        if not self.complete:
            return b""
        chunks: list[bytes] = []
        for _ in range(32):
            chunk = self.read_app()
            if chunk:
                chunks.append(chunk)
            if not chunk and self.ssl.pending() == 0:
                break
        return b"".join(chunks)

    def read_app(self) -> bytes:
        try:
            return self.ssl.read(8192)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return b""
        except ssl.SSLError as exc:
            self.error = str(exc)
            return b""

    def write_app(self, payload: bytes) -> bytes:
        try:
            self.ssl.write(payload)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        except ssl.SSLError as exc:
            self.error = str(exc)
        return self._drain_outgoing()

    def _drain_outgoing(self) -> bytes:
        chunks = []
        while self._outgoing.pending:
            chunks.append(self._outgoing.read())
        return b"".join(chunks)

    def negotiated_metadata(self) -> TlsMetadata:
        metadata = TlsMetadata()
        version = self.ssl.version()
        if version:
            metadata.versions.add(version.replace("v", " "))
        try:
            der = self.ssl.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            der = None
        if der:
            certificate = parse_der_certificate(der)
            if certificate is not None:
                metadata.certificates.append(certificate)
        return metadata


class EnterpriseProbe:
    def __init__(
        self,
        iface,
        ap,
        *,
        tx_observer=None,
        on_event: EnterpriseProbeEventCallback | None = None,
        deep_lab: bool = True,
        lab_identities: tuple[str, ...] | None = None,
        record_pcap: bool = True,
        channel: int | None = None,
    ) -> None:
        self.iface = iface
        self.ap = ap
        self._record_pcap = record_pcap
        self.radio_channel = int(channel) if channel else int(ap.channel)
        self.tx_observer = tx_observer
        self.on_event = on_event
        self._deep_lab = deep_lab
        self.bssid = str_to_mac(ap.bssid.casefold())
        self.our_mac: bytes | None = None
        self._tls: _TlsClient | None = None
        self._method: int | None = None
        self._method_version_flags = 0
        self._incoming_tls = bytearray()
        self._incoming_expected: int | None = None
        self._outgoing_tls: deque[bytes] = deque()
        self._outgoing_total = 0
        self._metadata = TlsMetadata()
        self._started_at = time.time()
        self._events: list[EnterpriseProbeEvent] = []
        self._server_methods: set[int] = set()
        self._associated = False
        self._response_cache: dict[tuple[int, int | None, bytes], bytes] = {}
        self._current_request_key: tuple[int, int | None, bytes] | None = None
        self._pcap = None
        self._pcap_path: str | None = None
        self._inner_buffer = bytearray()
        self._inner_eap_types: set[int] = set()
        self._compatibility_notes: list[str] = []
        self._mschap_username: str | None = None
        self._mschap_challenge_hex: str | None = None
        self._mschap_challenge_path: str | None = None
        self._capture_done = False
        self._finish_detail: str | None = None
        self._legacy_survey_done = False
        self._outer_identity = b"anonymous"
        self._lab_identities = resolve_lab_identities(
            ", ".join(lab_identities) if lab_identities else None
        )
        self._inner_identity = self._lab_identities[0].encode()
        self._ttls_identity_sent = False
        self._inner_mschap_survey = False
        self._phase_outcomes: list[str] = []
        self._pending_inner_app: tuple[bytes, int] | None = None

    async def run(self, timeout: float = 52.0) -> EnterpriseProbeResult:
        self._event("preflight", "Selecting a compatible 802.1X AKM", direction="local")
        selected_akm = self._selected_akm()
        if selected_akm is None:
            return self._result(False, "unsupported", "no supported 802.1X AKM", set())
        if not self.ap.rsn_ie:
            return self._result(False, "unsupported", "RSN information is unavailable", set())
        rsn_ie = force_psk_akm(
            self.ap.rsn_ie,
            selected_akm,
            pmf_capable=self.ap.pmf_capable or self.ap.pmf_required,
        )
        if rsn_ie is None:
            return self._result(
                False,
                "unsupported",
                "could not build Enterprise RSN IE",
                set(),
            )

        await self.iface.set_channel(self.radio_channel)
        fake_mac = await self.iface.set_fake_mac(None, self.bssid)
        our_mac_text = fake_mac or (
            self.iface.mac_address if isinstance(self.iface.mac_address, str) else None
        )
        if our_mac_text is None:
            return self._result(False, "failed", "active monitor unavailable", set())
        self.our_mac = str_to_mac(our_mac_text)
        if self._record_pcap:
            self._open_pcap()
        radio = _PcapIface(self.iface, self._write_pcap) if self._pcap else self.iface
        association = Association(
            radio,
            self.ap.bssid,
            self.ap.ssid or "",
            self.radio_channel,
            our_mac=self.our_mac,
            assoc_trailer_ies=rsn_ie,
            auth_timeout=1.5,
            assoc_timeout=1.5,
            require_auth=True,
            capability_flags=getattr(self.ap.capabilities, "capability_flags", None),
            ht_capable=_ap_allows_ht(self.ap),
            wmm=bool(getattr(getattr(self.ap, "capabilities", None), "wmm", False)),
        )
        transport = WlanTransport(
            radio,
            self.bssid,
            self.our_mac,
            tx_observer=self.tx_observer,
        )
        association.start()
        transport.start()
        associated = False
        try:
            self._event("association", "Sending Open Authentication and Association", direction="tx")
            associated = await association.associate(attempts=4)
            if not associated:
                return self._result(
                    False,
                    "failed",
                    _assoc_fail_detail(self.ap, association.fail_reason),
                    set(),
                )
            self._associated = True
            self._event("association", "Association accepted", direction="rx")
            last_reason = ""
            if self._deep_lab:
                self._event(
                    "preflight",
                    "Deep lab battery: multi-pass outer/inner EAP and downgrade surveys",
                    direction="local",
                )
                phases = self._identity_phases()
                phase_budget = timeout * 0.19
                last_reason = ""
                for title, outer, inner, reset, inner_nak in phases:
                    if self._capture_done:
                        self._phase_outcomes.append(f"{title}: skipped (MS-CHAPv2 captured)")
                        break
                    if reset and last_reason in _PHASE_REATTACH_REASONS:
                        if not await self._reattach_association(association, transport):
                            self._phase_outcomes.append(f"{title}: skipped (re-association failed)")
                            break
                    self._event("survey", title, direction="local")
                    if reset:
                        self._reset_eap_phase_state()
                    self._outer_identity = outer
                    self._inner_identity = inner
                    self._inner_mschap_survey = inner_nak
                    reason = await self._exchange_phase(transport, phase_budget)
                    last_reason = reason
                    self._phase_outcomes.append(f"{title}: {reason}")
                    if reason in {"captured", "success"}:
                        break
                self._inner_mschap_survey = False
            else:
                self._event("eap", "Starting EAP exchange", direction="local")
                await self._exchange_phase(transport, timeout * 0.7)

            if self._associated and not self._capture_done:
                if last_reason in _PHASE_REATTACH_REASONS:
                    await self._reattach_association(association, transport)
                    self._reset_eap_phase_state()
                survey_budget = min(14.0, timeout * 0.18)
                self._event(
                    "survey",
                    "Outer downgrade survey (NAK tunnel → EAP-MD5 probe)",
                    direction="local",
                )
                extra = await self._survey_legacy_outer(transport, survey_budget)
                if extra:
                    self._server_methods.update(extra)
                    self._compatibility_notes.append(
                        "Downgrade survey saw additional outer EAP types: "
                        + ", ".join(str(code) for code in sorted(extra))
                    )
                if self._deep_lab:
                    self._event(
                        "survey",
                        "Outer tunnel preference survey (PEAP/TTLS/TLS NAK)",
                        direction="local",
                    )
                    await self._survey_tunnel_preferences(
                        transport,
                        min(12.0, timeout * 0.16),
                    )
            return self._finalize_battery()
        finally:
            transport.stop()
            association.stop()
            if self.our_mac is not None:
                try:
                    await self.iface.send_no_wait(build_client_leaving(self.bssid, self.our_mac))
                except Exception:
                    pass
            await self.iface.clear_fake_mac()
            self._close_pcap()

    def _selected_akm(self) -> int | None:
        for suite in _SUPPORTED_AKMS:
            if suite in self.ap.akm_suites:
                return suite
        if not self.ap.akm_suites and any("EAP" in name for name in self.ap.akms):
            return 1
        return None

    def _eap_failure_detail(self) -> str:
        if self._mschap_challenge_hex:
            return "MS-CHAPv2 challenge captured; server rejected probe client"
        if self._inner_eap_types:
            inner = ", ".join(str(code) for code in sorted(self._inner_eap_types))
            if self._inner_eap_types == {EAP_TYPE_IDENTITY}:
                return (
                    f"RADIUS rejected inner Identity [{self._inner_identity.decode('utf-8', errors='replace')}] "
                    "before MS-CHAPv2 (unknown user or policy)"
                )
            return f"RADIUS rejected after inner EAP types [{inner}]"
        if self._metadata.versions or self._metadata.certificates:
            return "outer TLS completed; no inner EAP observed before Failure"
        return "EAP negotiation failed before TLS"

    async def _reattach_association(
        self,
        association: Association,
        transport: WlanTransport,
    ) -> bool:
        assert self.our_mac is not None
        transport.drain()
        self._event("association", "Re-associating for next lab phase", direction="local")
        try:
            await self.iface.send_no_wait(build_client_leaving(self.bssid, self.our_mac))
        except Exception:
            pass
        await asyncio.sleep(0.35)
        transport.drain()
        associated = await association.associate(attempts=4)
        if associated:
            self._event("association", "Re-association accepted", direction="rx")
        else:
            self._event("association", "Re-association failed", direction="local")
        return associated

    def _reset_eap_phase_state(self) -> None:
        self._tls = None
        self._method = None
        self._incoming_tls.clear()
        self._incoming_expected = None
        self._outgoing_tls.clear()
        self._inner_buffer.clear()
        self._response_cache.clear()
        self._current_request_key = None
        self._pending_inner_app = None
        self._ttls_identity_sent = False

    def _identity_phases(self) -> list[tuple[str, bytes, bytes, bool, bool]]:
        identities = self._lab_identities or (self._inner_identity.decode("utf-8", errors="replace"),)
        phases: list[tuple[str, bytes, bytes, bool, bool]] = []
        for ident in identities:
            raw = ident.encode("utf-8")
            phases.append((
                f"anon outer + {ident} inner → MS-CHAPv2",
                b"anonymous",
                raw,
                True,
                False,
            ))
            if raw != b"anonymous":
                phases.append((
                    f"matched {ident} outer+inner → MS-CHAPv2",
                    raw,
                    raw,
                    True,
                    False,
                ))
        first = identities[0].encode("utf-8")
        phases.append((
            "inner method survey (NAK MS-CHAPv2 for PAP/GTC)",
            b"anonymous",
            first,
            True,
            True,
        ))
        if phases:
            title, outer, inner, _reset, nak = phases[0]
            phases[0] = (title, outer, inner, False, nak)
        total = len(phases)
        return [
            (f"Phase {index}/{total}: {title}", outer, inner, reset, nak)
            for index, (title, outer, inner, reset, nak) in enumerate(phases, start=1)
        ]

    def _vault_username(self) -> str:
        if self._mschap_username:
            return self._mschap_username
        if self._inner_identity:
            text = self._inner_identity.decode("utf-8", errors="replace").strip()
            if text:
                return text
        return read_eap_lab_user() or _DEFAULT_LAB_INNER.decode()

    async def _flush_pending_inner(
        self,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> None:
        if self._outgoing_tls or self._pending_inner_app is None:
            return
        data, outer_id = self._pending_inner_app
        self._pending_inner_app = None
        await self._consume_inner(data, transport, outer_id or outer_identifier)

    async def _schedule_inner_app(
        self,
        app: bytes,
        transport: WlanTransport,
        outer_identifier: int,
        *,
        defer_if_outgoing: bool,
    ) -> None:
        if not app:
            return
        if defer_if_outgoing or self._outgoing_tls:
            self._pending_inner_app = (app, outer_identifier)
            return
        await self._consume_inner(app, transport, outer_identifier)

    def _outer_identity_label(self) -> str:
        text = self._outer_identity.decode("utf-8", errors="replace").strip()
        return text or "anonymous"

    def _finalize_battery(self) -> EnterpriseProbeResult:
        methods = set(self._server_methods)
        if self._mschap_challenge_hex:
            ok, status, detail = (
                True,
                "complete",
                self._finish_detail or "MS-CHAPv2 server challenge captured",
            )
        elif self._inner_eap_types and (self._metadata.certificates or self._metadata.versions):
            inner = ", ".join(str(code) for code in sorted(self._inner_eap_types))
            ok, status, detail = (
                True,
                "partial",
                f"Deep lab complete: PEAP inner observed [{inner}]; MS-CHAPv2 challenge not captured",
            )
            if EAP_TYPE_MSCHAPV2 not in self._inner_eap_types:
                self._compatibility_notes.append(
                    "MS-CHAPv2 was not offered: add inner user "
                    f"{self._vault_username()} to FreeRADIUS users, or put that "
                    "identity in the Enterprise lab dialog."
                )
        elif self._metadata.certificates or self._metadata.versions:
            ok, status, detail = (
                True,
                "partial",
                "Deep lab complete: outer PEAP/TLS mapped; inner MS-CHAPv2 not captured",
            )
        elif methods:
            ok, status, detail = (
                False,
                "failed",
                "Deep lab finished without TLS-bearing EAP completion",
            )
        else:
            ok, status, detail = False, "timeout", "Deep lab found no EAP responses"
        if self._deep_lab and self._phase_outcomes:
            self._compatibility_notes.insert(
                0,
                "Lab phases: " + " | ".join(self._phase_outcomes[:8]),
            )
        return self._finalize_result(ok, status, detail, methods)

    async def _exchange_phase(
        self,
        transport: WlanTransport,
        timeout: float,
    ) -> str:
        assert self.our_mac is not None
        start = eapol_start_frame(self.bssid, self.our_mac)
        self._event("eap", "EAPOL-Start", direction="tx")
        await transport.send_no_wait(start)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        last_start = loop.time()
        nak_count = 0

        while loop.time() < deadline:
            frame = await transport.recv(max(0.01, min(0.8, deadline - loop.time())))
            if frame is None:
                if not self._server_methods and loop.time() - last_start >= 1.0:
                    await transport.send_no_wait(start)
                    last_start = loop.time()
                continue
            packet = WlanFrameParser.parse_80211_frame(frame, 0)
            if not isinstance(packet, EapPacket):
                continue
            if packet.eap_code == EAP_SUCCESS:
                self._event("eap", "EAP Success", direction="rx", packet=packet)
                return "success"
            if packet.eap_code == EAP_FAILURE:
                detail = self._eap_failure_detail()
                self._event("eap", f"EAP Failure ({detail})", direction="rx", packet=packet)
                self._compatibility_notes.append(f"Phase ended: {detail}")
                return "failure"
            if packet.eap_code != EAP_REQUEST or packet.eap_type is None:
                continue
            request_key = self._request_key(packet)
            cached = self._response_cache.get(request_key)
            if cached is not None:
                self._event(
                    "retransmission",
                    "Repeated EAP Request; replaying cached response",
                    direction="rx",
                    packet=packet,
                )
                await transport.send_no_wait(cached)
                continue
            self._current_request_key = request_key
            self._server_methods.add(packet.eap_type)
            self._event(
                "eap",
                f"EAP Request type {packet.eap_type}",
                direction="rx",
                packet=packet,
            )
            if packet.eap_type == EAP_TYPE_IDENTITY:
                response = eap_identity_response_frame(
                    self.bssid,
                    self.our_mac,
                    packet.eap_identifier,
                    identity=self._outer_identity,
                )
                await self._send_response(
                    transport,
                    response,
                    f"Outer identity ({self._outer_identity_label()})",
                    packet,
                )
                continue
            if packet.eap_type not in EAP_TLS_TYPES:
                nak_count += 1
                if nak_count > 4:
                    return "unsupported"
                response = eap_nak_response_frame(
                    self.bssid,
                    self.our_mac,
                    packet.eap_identifier,
                    tuple(sorted(EAP_TLS_TYPES)),
                )
                await self._send_response(
                    transport,
                    response,
                    "Legacy NAK with supported TLS methods",
                    packet,
                )
                continue
            try:
                await self._handle_tls_request(transport, packet)
            except ValueError as exc:
                self._compatibility_notes.append(f"Phase TLS error: {exc}")
                return "error"
            if self._capture_done:
                return "captured"
            if self._tls is not None and self._tls.error:
                self._compatibility_notes.append(f"Phase TLS stack: {self._tls.error}")
                if self._deep_lab:
                    return "tls_error"
                return "tls_error"
        if self._finish_detail:
            return "timeout"
        if self._tls is not None and self._tls.complete and self._inner_eap_types:
            return "timeout_inner"
        if self._metadata.versions or self._metadata.certificates:
            return "timeout_tls"
        return "timeout"

    async def _handle_tls_request(
        self,
        transport: WlanTransport,
        packet: EapPacket,
    ) -> None:
        assert self.our_mac is not None
        if self._method != packet.eap_type:
            self._method = packet.eap_type
            self._tls = _TlsClient()
            self._incoming_tls.clear()
            self._incoming_expected = None
            self._outgoing_tls.clear()
            self._pending_inner_app = None
        if packet.eap_data:
            self._method_version_flags = packet.eap_data[0] & 0x1F
        more, start, total_length, fragment = eap_tls_fragment(packet.eap_data)
        if start and not fragment:
            outgoing, app = self._tls.feed() if self._tls is not None else (b"", b"")
            if outgoing:
                await self._queue_tls(transport, packet.eap_identifier, outgoing)
            await self._schedule_inner_app(
                app,
                transport,
                packet.eap_identifier,
                defer_if_outgoing=bool(outgoing),
            )
            return
        if self._outgoing_tls and not fragment:
            await self._send_next_tls_fragment(transport, packet.eap_identifier)
            await self._flush_pending_inner(transport, packet.eap_identifier)
            return
        if start or total_length is not None:
            self._incoming_tls.clear()
        if total_length is not None and total_length > _MAX_TLS_BYTES:
            raise ValueError("EAP-TLS payload exceeds safety limit")
        if total_length is not None:
            self._incoming_expected = total_length
        if len(self._incoming_tls) + len(fragment) > _MAX_TLS_BYTES:
            raise ValueError("EAP-TLS reassembly exceeds safety limit")
        self._incoming_tls.extend(fragment)
        if (
            self._incoming_expected is not None
            and len(self._incoming_tls) > self._incoming_expected
        ):
            raise ValueError("EAP-TLS fragment data exceeds declared length")
        if more:
            ack = eap_tls_response_frame(
                self.bssid,
                self.our_mac,
                packet.eap_identifier,
                packet.eap_type,
                version_flags=self._method_version_flags,
            )
            await self._send_response(
                transport,
                ack,
                "EAP-TLS fragment acknowledgement",
                packet,
            )
            return
        incoming = bytes(self._incoming_tls)
        self._incoming_tls.clear()
        if self._incoming_expected is not None and len(incoming) != self._incoming_expected:
            expected = self._incoming_expected
            self._incoming_expected = None
            raise ValueError(
                f"EAP-TLS length mismatch: expected {expected}, received {len(incoming)}"
            )
        self._incoming_expected = None
        was_complete = bool(self._tls is not None and self._tls.complete)
        if incoming[:1] == b"\x16":
            self._merge_metadata(parse_tls_records(incoming))
        outgoing, app = self._tls.feed(incoming) if self._tls is not None else (b"", b"")
        if self._tls is not None and self._tls.complete:
            self._merge_metadata(self._tls.negotiated_metadata())
            self._note_tls_downgrade()
        if self._tls is not None and self._tls.complete:
            extra = self._tls.drain_app()
            if extra:
                app = app + extra if app else extra
        if outgoing:
            await self._queue_tls(transport, packet.eap_identifier, outgoing)
        await self._schedule_inner_app(
            app,
            transport,
            packet.eap_identifier,
            defer_if_outgoing=bool(outgoing),
        )
        sent_ttls_identity = False
        if (
            self._method == EAP_TYPE_TTLS
            and self._tls is not None
            and self._tls.complete
            and not self._ttls_identity_sent
            and not self._outgoing_tls
            and not outgoing
        ):
            await self._send_ttls_username(transport, packet.eap_identifier)
            sent_ttls_identity = True
        if (
            self._tls is not None
            and self._tls.complete
            and not app
            and not outgoing
            and not self._outgoing_tls
            and not sent_ttls_identity
        ):
            detail = "PEAP post-handshake ack"
            if not was_complete:
                detail = "PEAP handshake complete (ack)"
            ack = eap_tls_response_frame(
                self.bssid,
                self.our_mac,
                packet.eap_identifier,
                packet.eap_type,
                version_flags=self._method_version_flags,
            )
            await self._send_response(
                transport,
                ack,
                detail,
                packet,
            )

    async def _queue_tls(
        self,
        transport: WlanTransport,
        identifier: int,
        payload: bytes,
    ) -> None:
        if not payload:
            return
        self._outgoing_total = len(payload)
        self._outgoing_tls = deque(
            payload[offset: offset + _TLS_FRAGMENT_BYTES]
            for offset in range(0, len(payload), _TLS_FRAGMENT_BYTES)
        )
        await self._send_next_tls_fragment(transport, identifier)

    async def _send_next_tls_fragment(
        self,
        transport: WlanTransport,
        identifier: int,
    ) -> None:
        assert self.our_mac is not None and self._method is not None
        fragment = self._outgoing_tls.popleft()
        more = bool(self._outgoing_tls)
        first = self._outgoing_total > len(fragment) and more and (
            self._outgoing_total - sum(map(len, self._outgoing_tls)) == len(fragment)
        )
        frame = eap_tls_response_frame(
            self.bssid,
            self.our_mac,
            identifier,
            self._method,
            fragment,
            more=more,
            total_length=self._outgoing_total if first else None,
            version_flags=self._method_version_flags,
        )
        await self._send_response(
            transport,
            frame,
            "EAP-TLS response fragment",
        )
        if not self._outgoing_tls:
            await self._flush_pending_inner(transport, identifier)

    def _merge_metadata(self, metadata: TlsMetadata) -> None:
        self._metadata.versions.update(metadata.versions)
        self._metadata.client_versions.update(metadata.client_versions)
        self._metadata.cipher_suites.update(metadata.cipher_suites)
        self._metadata.client_cipher_suites.update(metadata.client_cipher_suites)
        self._metadata.server_names.update(metadata.server_names)
        self._metadata.supported_groups.update(metadata.supported_groups)
        self._metadata.signature_algorithms.update(metadata.signature_algorithms)
        if metadata.certificate_requested and not self._metadata.certificate_requested:
            self._metadata.certificate_requested = True
            authority = next(iter(metadata.certificate_authorities), None)
            subject = next(
                (certificate.subject for certificate in metadata.certificates if certificate.subject),
                None,
            )
            detail = "Server requested a client certificate"
            if authority:
                detail += f" (CA {authority})"
            elif subject:
                detail += f" (server {subject})"
            self._event("tls", detail, direction="rx")
            self._compatibility_notes.append(detail)
        if metadata.certificate_authorities:
            for name in metadata.certificate_authorities:
                if name not in self._metadata.certificate_authorities:
                    self._metadata.certificate_authorities.append(name)
        known = {certificate.fingerprint for certificate in self._metadata.certificates}
        self._metadata.certificates.extend(
            certificate
            for certificate in metadata.certificates
            if certificate.fingerprint not in known
        )
        if (
            metadata.versions
            or metadata.cipher_suites
            or metadata.certificates
            or metadata.certificate_requested
        ):
            self._event("tls", "Observed outer TLS metadata", direction="local")

    def _note_tls_downgrade(self) -> None:
        offered = self._metadata.client_versions
        negotiated = self._metadata.versions
        if "TLS 1.3" in offered and negotiated and "TLS 1.2" in negotiated and "TLS 1.3" not in negotiated:
            self._compatibility_notes.append(
                "Outer TLS downgrade: client offered TLS 1.3 but negotiated TLS 1.2"
            )

    def _reset_survey_state(self) -> None:
        self._tls = None
        self._method = None
        self._incoming_tls.clear()
        self._incoming_expected = None
        self._outgoing_tls.clear()
        self._inner_buffer.clear()
        self._response_cache.clear()

    async def _survey_legacy_outer(self, transport: WlanTransport, timeout: float) -> set[int]:
        if self._legacy_survey_done or self.our_mac is None:
            return set()
        self._legacy_survey_done = True
        self._reset_survey_state()
        self._event("preflight", "Downgrade survey: probing legacy outer EAP offers", direction="local")
        await transport.send_no_wait(eapol_start_frame(self.bssid, self.our_mac))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        methods: set[int] = set()
        rejected_tunnel = False
        while loop.time() < deadline:
            frame = await transport.recv(max(0.01, min(0.5, deadline - loop.time())))
            if frame is None:
                continue
            packet = WlanFrameParser.parse_80211_frame(frame, 0)
            if not isinstance(packet, EapPacket):
                continue
            if packet.eap_code != EAP_REQUEST or packet.eap_type is None:
                continue
            methods.add(packet.eap_type)
            if packet.eap_type == EAP_TYPE_IDENTITY:
                await self._send_response(
                    transport,
                    eap_identity_response_frame(self.bssid, self.our_mac, packet.eap_identifier),
                    "Survey outer identity",
                    packet,
                )
                continue
            if packet.eap_type in EAP_TLS_TYPES and not rejected_tunnel:
                rejected_tunnel = True
                await self._send_response(
                    transport,
                    eap_nak_response_frame(
                        self.bssid,
                        self.our_mac,
                        packet.eap_identifier,
                        (EAP_TYPE_MD5,),
                    ),
                    "Survey NAK: prefer legacy EAP-MD5",
                    packet,
                )
                continue
            if packet.eap_type == EAP_TYPE_MD5:
                self._compatibility_notes.append(
                    "Downgrade survey: RADIUS offered EAP-MD5 after tunnel methods were NAK'd"
                )
                break
        return methods

    async def _survey_tunnel_preferences(
        self,
        transport: WlanTransport,
        timeout: float,
    ) -> None:
        assert self.our_mac is not None
        scenarios = (
            (
                "NAK PEAP → prefer TTLS/TLS",
                EAP_TYPE_PEAP,
                (EAP_TYPE_TTLS, EAP_TYPE_TLS),
            ),
            (
                "NAK TTLS → prefer EAP-TLS",
                EAP_TYPE_TTLS,
                (EAP_TYPE_TLS,),
            ),
        )
        per = max(4.0, timeout / len(scenarios))
        for label, reject_method, prefer in scenarios:
            self._reset_eap_phase_state()
            self._event("survey", f"Tunnel preference: {label}", direction="local")
            await transport.send_no_wait(eapol_start_frame(self.bssid, self.our_mac))
            loop = asyncio.get_running_loop()
            deadline = loop.time() + per
            rejected = False
            while loop.time() < deadline:
                frame = await transport.recv(max(0.01, min(0.5, deadline - loop.time())))
                if frame is None:
                    continue
                packet = WlanFrameParser.parse_80211_frame(frame, 0)
                if not isinstance(packet, EapPacket):
                    continue
                if packet.eap_code != EAP_REQUEST or packet.eap_type is None:
                    continue
                self._server_methods.add(packet.eap_type)
                if packet.eap_type == EAP_TYPE_IDENTITY:
                    await self._send_response(
                        transport,
                        eap_identity_response_frame(
                            self.bssid,
                            self.our_mac,
                            packet.eap_identifier,
                            identity=self._outer_identity,
                        ),
                        "Survey outer identity",
                        packet,
                    )
                    continue
                if packet.eap_type == reject_method and not rejected:
                    rejected = True
                    await self._send_response(
                        transport,
                        eap_nak_response_frame(
                            self.bssid,
                            self.our_mac,
                            packet.eap_identifier,
                            prefer,
                        ),
                        f"Survey NAK ({label})",
                        packet,
                    )
                    continue
                if packet.eap_type in prefer:
                    self._compatibility_notes.append(
                        f"Tunnel survey: server offered EAP type {packet.eap_type} after {label}"
                    )
                    break

    async def _consume_inner(
        self,
        data: bytes,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> None:
        if self._method == EAP_TYPE_TTLS and await self._consume_ttls(
            data, transport, outer_identifier
        ):
            return
        self._inner_buffer.extend(data)
        packets = list(self._iter_inner_packets())
        if data and not packets and self._inner_buffer:
            preview = bytes(self._inner_buffer[:16]).hex()
            self._event(
                "eap",
                f"PEAP inner pending ({len(self._inner_buffer)} B {preview})",
                direction="rx",
            )
        for packet in packets:
            await self._handle_inner_packet(packet, transport, outer_identifier)

    def _iter_inner_packets(self):
        while self._inner_buffer:
            while len(self._inner_buffer) > 1 and self._inner_buffer[0] == 0:
                del self._inner_buffer[0]
            if not self._inner_buffer:
                break
            header = _inner_eap_header_status(self._inner_buffer)
            if header == "complete":
                length = struct.unpack(">H", self._inner_buffer[2:4])[0]
                yield bytes(self._inner_buffer[:length])
                del self._inner_buffer[:length]
                continue
            if header == "incomplete":
                break
            condensed = _synthesize_peap_inner(self._inner_buffer)
            if condensed is None:
                break
            packet, consumed = condensed
            del self._inner_buffer[:consumed]
            yield packet

    async def _handle_inner_packet(
        self,
        packet: bytes,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> None:
        if len(packet) < 5:
            return
        code, identifier, length = struct.unpack(">BBH", packet[:4])
        body = packet[4:length]
        if code != EAP_REQUEST or not body:
            return
        eap_type = body[0]
        payload = body[1:]
        self._inner_eap_types.add(eap_type)
        self._event("eap", f"Inner EAP Request type {eap_type}", direction="rx")
        if eap_type == EAP_TYPE_IDENTITY:
            identity = self._inner_identity.rstrip(b"\x00")
            # PEAP phase-2 identity uses EAP-Type + UTF-8 identity only (no EAP header).
            inner = bytes([EAP_TYPE_IDENTITY]) + identity
            await self._send_inner(
                transport,
                outer_identifier,
                inner,
                f"Inner identity ({identity.decode('utf-8', errors='replace')})",
            )
            return
        if eap_type == EAP_TYPE_MSCHAPV2 and self._inner_mschap_survey:
            alt = bytes([EAP_TYPE_PAP, EAP_TYPE_GTC, EAP_TYPE_MSCHAPV2])
            inner = bytes([EAP_TYPE_NAK]) + alt
            await self._send_inner(
                transport,
                outer_identifier,
                inner,
                "Inner NAK (survey PAP/GTC/MS-CHAPv2)",
            )
            self._compatibility_notes.append(
                "Inner survey: NAK'd MS-CHAPv2 to probe alternate inner EAP methods"
            )
            return
        if eap_type == EAP_TYPE_MSCHAPV2:
            challenge = parse_mschapv2_challenge_payload(payload)
            if challenge is not None:
                self._record_mschap_challenge(
                    challenge.server_challenge,
                    "PEAP tunnel: MS-CHAPv2 server challenge captured (no password sent)",
                    authenticator_name=challenge.authenticator_name,
                )

    async def _send_inner(
        self,
        transport: WlanTransport,
        outer_identifier: int,
        inner_eap: bytes,
        detail: str,
    ) -> None:
        if self._tls is None:
            return
        outgoing = self._tls.write_app(inner_eap)
        self._event("eap", detail, direction="tx")
        await self._queue_tls(transport, outer_identifier, outgoing)

    def _record_mschap_challenge(
        self,
        challenge: bytes,
        detail: str,
        *,
        authenticator_name: str | None = None,
    ) -> None:
        if len(challenge) != 16:
            self._event(
                "eap",
                f"MS-CHAP challenge {challenge.hex()} ({len(challenge)} B, not Hashcat 5500)",
                direction="rx",
            )
            return
        self._mschap_username = self._vault_username()
        self._mschap_challenge_hex = challenge.hex()
        self._capture_done = True
        self._finish_detail = detail
        extra = (
            f" (authenticator {authenticator_name})"
            if authenticator_name
            else ""
        )
        self._event(
            "eap",
            f"MS-CHAPv2 challenge {self._mschap_challenge_hex}{extra}",
            direction="rx",
        )

    async def _send_ttls_username(
        self,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> None:
        if self._tls is None or self._ttls_identity_sent:
            return
        identity = self._inner_identity.rstrip(b"\x00")
        avp = bytes([_RADIUS_USER_NAME, 2 + len(identity)]) + identity
        outgoing = self._tls.write_app(avp)
        self._ttls_identity_sent = True
        self._event(
            "eap",
            f"TTLS User-Name ({identity.decode('utf-8', errors='replace')})",
            direction="tx",
        )
        await self._queue_tls(transport, outer_identifier, outgoing)

    async def _consume_ttls(
        self,
        data: bytes,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> bool:
        if not data:
            return False
        handled = False
        for typ, value in _iter_radius_avps(data):
            handled = True
            if typ == _RADIUS_EAP_MESSAGE:
                await self._consume_inner_eap_bytes(value, transport, outer_identifier)
                continue
            if typ == _RADIUS_VENDOR:
                challenge = _ms_chap_challenge_from_vsa(value)
                if challenge is not None:
                    self._record_mschap_challenge(
                        challenge,
                        "TTLS tunnel: MS-CHAP challenge captured (no password sent)",
                    )
        if not handled and data[0] in (EAP_REQUEST, EAP_TYPE_IDENTITY, EAP_TYPE_MSCHAPV2):
            return False
        return handled

    async def _consume_inner_eap_bytes(
        self,
        data: bytes,
        transport: WlanTransport,
        outer_identifier: int,
    ) -> None:
        self._inner_buffer.extend(data)
        packets = list(self._iter_inner_packets())
        for packet in packets:
            await self._handle_inner_packet(packet, transport, outer_identifier)

    def _finalize_result(
        self,
        ok: bool,
        status: str,
        detail: str,
        methods: set[int],
    ) -> EnterpriseProbeResult:
        if self._mschap_challenge_hex and "MS-CHAPv2" not in detail:
            detail = f"{detail}; MS-CHAPv2 challenge {self._mschap_challenge_hex}"
        if methods:
            self._compatibility_notes.append(
                "Outer EAP methods observed: " + ", ".join(str(code) for code in sorted(methods))
            )
        return self._result(ok, status, detail, methods)

    @staticmethod
    def _request_key(packet: EapPacket) -> tuple[int, int | None, bytes]:
        return (
            packet.eap_identifier,
            packet.eap_type,
            hashlib.sha256(packet.eap_data).digest()[:8],
        )

    async def _send_response(
        self,
        transport: WlanTransport,
        frame: bytes,
        detail: str,
        packet: EapPacket | None = None,
    ) -> None:
        key = self._request_key(packet) if packet is not None else self._current_request_key
        if key is not None:
            self._response_cache[key] = frame
            if len(self._response_cache) > 64:
                self._response_cache.pop(next(iter(self._response_cache)))
        self._event("eap", detail, direction="tx", packet=packet)
        await transport.send_no_wait(frame)

    def _event(
        self,
        phase: str,
        detail: str,
        *,
        direction: str | None = None,
        packet: EapPacket | None = None,
    ) -> None:
        event = EnterpriseProbeEvent(
            timestamp=time.time(),
            phase=phase,
            detail=detail,
            direction=direction,
            eap_identifier=packet.eap_identifier if packet is not None else None,
            eap_type=packet.eap_type if packet is not None else None,
        )
        self._events.append(event)
        if len(self._events) > 128:
            del self._events[:-128]
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                logger.debug("Enterprise probe progress callback failed", exc_info=True)

    def cancelled_result(self) -> EnterpriseProbeResult:
        return self._result(
            False,
            "cancelled",
            "probe cancelled by operator",
            self._server_methods,
        )

    def _result(
        self,
        ok: bool,
        status: str,
        detail: str,
        methods: set[int],
    ) -> EnterpriseProbeResult:
        if self._tls is not None and self._tls.error:
            self._compatibility_notes.append(f"TLS stack: {self._tls.error}")
        result = EnterpriseProbeResult(
            ok=ok,
            status=status,
            detail=detail,
            association_ok=self._associated,
            eap_method=self._method,
            client_mac=self.our_mac.hex(":") if self.our_mac is not None else None,
            server_methods=set(methods),
            tls=self._metadata,
            started_at=self._started_at,
            ended_at=time.time(),
            events=list(self._events),
            pcap_path=self._pcap_path,
            inner_eap_types=set(self._inner_eap_types),
            compatibility_notes=list(self._compatibility_notes),
            mschap_username=self._mschap_username,
            mschap_challenge_hex=self._mschap_challenge_hex,
            mschap_challenge_path=self._mschap_challenge_path,
            lab_correlation=None,
        )
        try:
            from wifit3.campaigns.eap_lab_radius_correlate import (
                correlate_probe_with_radius_log,
                default_eap_lab_radius_log,
            )
            from wifit3.persist.save import save_enterprise_probe_dump

            lab_log = default_eap_lab_radius_log()
            lab_correlation = None
            if lab_log is not None:
                lab_correlation = correlate_probe_with_radius_log(
                    log_path=lab_log,
                    client_mac=result.client_mac,
                    ssid=self.ap.ssid or "",
                    started_at=result.started_at,
                    ended_at=result.ended_at,
                )
                if lab_correlation and lab_correlation.get("diagnosis"):
                    self._compatibility_notes.append(
                        "RADIUS lab: " + str(lab_correlation["diagnosis"]),
                    )
                    result.compatibility_notes = list(self._compatibility_notes)
                radius_challenge = (
                    lab_correlation.get("mschap_challenge_hex")
                    if lab_correlation
                    else None
                )
                if radius_challenge and not self._mschap_challenge_hex:
                    self._mschap_challenge_hex = str(radius_challenge)
                    self._mschap_username = (
                        self._mschap_username
                        or self._inner_identity.decode("utf-8", errors="replace")
                    )
                    self._capture_done = True
                    self._finish_detail = (
                        "MS-CHAPv2 server challenge recovered from RADIUS lab log "
                        "(PEAP inner framing missed the tunneled copy)"
                    )
                    result.mschap_challenge_hex = self._mschap_challenge_hex
                    result.mschap_username = self._mschap_username
                    result.ok = True
                    result.status = "complete"
                    result.detail = self._finish_detail
                    result.inner_eap_types = set(self._inner_eap_types) | {EAP_TYPE_MSCHAPV2}
            saved = save_enterprise_probe_dump(
                self.ap,
                result,
                tls_error=self._tls.error if self._tls is not None else None,
                lab_correlation=lab_correlation,
            )
            if saved is not None:
                result.dump_path = str(saved.path)
                result.lab_correlation = lab_correlation
        except Exception:
            logger.warning("Could not save Enterprise probe dump", exc_info=True)
        return result

    def _open_pcap(self) -> None:
        try:
            from wifit3.persist.common import bssid_to_dashed, safe_ssid
            from wifit3.persist.config import Config
            from wifit3.persist.pcap import PcapWriter
            from wifit3.persist.private_files import ensure_private_directory

            directory = Path(Config.captures_dir)
            ensure_private_directory(directory)
            name = (
                f"{safe_ssid(self.ap.ssid)}_{bssid_to_dashed(self.ap.bssid)}_"
                f"{int(time.time())}_enterprise_probe.pcap"
            )
            self._pcap = PcapWriter(directory / name)
            self._pcap_path = str(self._pcap.path)
            self.iface.register_rx_callback(self._pcap_rx)
            logger.info("Enterprise probe capture %s", self._pcap_path)
        except Exception:
            logger.exception("Enterprise probe capture unavailable")
            self._pcap = None
            self._pcap_path = None

    def _write_pcap(self, frame: bytes) -> None:
        if self._pcap is None or not frame:
            return
        try:
            self._pcap.write(frame)
        except Exception:
            logger.debug("enterprise probe pcap write failed", exc_info=True)

    def _pcap_rx(self, pkt) -> None:
        raw = getattr(pkt, "raw", b"")
        if len(raw) < 24 or self.our_mac is None:
            return
        dest, src = raw[4:10], raw[10:16]
        if dest != self.our_mac and src != self.bssid and dest != b"\xff" * 6:
            return
        self._write_pcap(raw)

    def _close_pcap(self) -> None:
        try:
            self.iface.unregister_rx_callback(self._pcap_rx)
        except Exception:
            pass
        if self._pcap is not None:
            try:
                self._pcap.close()
            except Exception:
                logger.debug("enterprise probe pcap close failed", exc_info=True)
            self._pcap = None
