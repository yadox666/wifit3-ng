from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from collections import deque
from dataclasses import dataclass, field

from wifit3.campaigns.auth_assoc import Association, WlanTransport, build_client_leaving
from wifit3.dot11 import str_to_mac
from wifit3.dot11.eap import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_SUCCESS,
    EAP_TLS_TYPES,
    EAP_TYPE_IDENTITY,
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


_SUPPORTED_AKMS = (1, 5)
_MAX_TLS_BYTES = 1_048_576
_TLS_FRAGMENT_BYTES = 900


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

    def advance(self, incoming: bytes = b"") -> bytes:
        if incoming:
            self._incoming.write(incoming)
        try:
            self.ssl.do_handshake()
            self.complete = True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        except ssl.SSLError as exc:
            self.error = str(exc)
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
    def __init__(self, iface, ap, *, tx_observer=None) -> None:
        self.iface = iface
        self.ap = ap
        self.tx_observer = tx_observer
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

    async def run(self, timeout: float = 15.0) -> EnterpriseProbeResult:
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

        await self.iface.set_channel(self.ap.channel)
        fake_mac = await self.iface.set_fake_mac(None, self.bssid)
        our_mac_text = fake_mac or (
            self.iface.mac_address if isinstance(self.iface.mac_address, str) else None
        )
        if our_mac_text is None:
            return self._result(False, "failed", "active monitor unavailable", set())
        self.our_mac = str_to_mac(our_mac_text)
        association = Association(
            self.iface,
            self.ap.bssid,
            self.ap.ssid or "",
            self.ap.channel,
            our_mac=self.our_mac,
            assoc_trailer_ies=rsn_ie,
            auth_timeout=0.8,
            assoc_timeout=1.2,
        )
        transport = WlanTransport(
            self.iface,
            self.bssid,
            self.our_mac,
            tx_observer=self.tx_observer,
        )
        association.start()
        transport.start()
        associated = False
        try:
            self._event("association", "Sending Open Authentication and Association", direction="tx")
            associated = await association.associate(attempts=3)
            if not associated:
                return self._result(
                    False,
                    "failed",
                    association.fail_reason or "association rejected",
                    set(),
                )
            self._associated = True
            self._event("association", "Association accepted", direction="rx")
            return await self._exchange(transport, timeout)
        finally:
            transport.stop()
            association.stop()
            if self.our_mac is not None:
                try:
                    await self.iface.send_no_wait(build_client_leaving(self.bssid, self.our_mac))
                except Exception:
                    pass
            await self.iface.clear_fake_mac()

    def _selected_akm(self) -> int | None:
        for suite in _SUPPORTED_AKMS:
            if suite in self.ap.akm_suites:
                return suite
        if not self.ap.akm_suites and any("EAP" in name for name in self.ap.akms):
            return 1
        return None

    async def _exchange(
        self,
        transport: WlanTransport,
        timeout: float,
    ) -> EnterpriseProbeResult:
        assert self.our_mac is not None
        start = eapol_start_frame(self.bssid, self.our_mac)
        self._event("eap", "EAPOL-Start", direction="tx")
        await transport.send_no_wait(start)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        last_start = loop.time()
        methods = set()
        self._server_methods = methods
        nak_count = 0

        while loop.time() < deadline:
            frame = await transport.recv(max(0.01, min(0.8, deadline - loop.time())))
            if frame is None:
                if not methods and loop.time() - last_start >= 1.0:
                    await transport.send_no_wait(start)
                    last_start = loop.time()
                continue
            packet = WlanFrameParser.parse_80211_frame(frame, 0)
            if not isinstance(packet, EapPacket):
                continue
            if packet.eap_code == EAP_SUCCESS:
                self._event("eap", "EAP Success", direction="rx", packet=packet)
                return self._result(True, "complete", "EAP authentication completed", methods)
            if packet.eap_code == EAP_FAILURE:
                self._event("eap", "EAP Failure", direction="rx", packet=packet)
                ok = bool(self._metadata.versions or self._metadata.certificates)
                detail = (
                    "outer TLS inspected; server stopped before inner authentication"
                    if ok else "EAP negotiation failed before TLS"
                )
                return self._result(ok, "partial" if ok else "failed", detail, methods)
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
            methods.add(packet.eap_type)
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
                )
                await self._send_response(
                    transport,
                    response,
                    "Anonymous outer identity",
                    packet,
                )
                continue
            if packet.eap_type not in EAP_TLS_TYPES:
                nak_count += 1
                if nak_count > 4:
                    return self._result(False, "unsupported", "no supported TLS EAP method", methods)
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
                return self._result(False, "failed", str(exc), methods)
            if self._tls is not None and self._tls.complete:
                self._merge_metadata(self._tls.negotiated_metadata())
                return self._result(
                    True,
                    "complete",
                    "outer TLS completed; stopped before inner authentication",
                    methods,
                )
            if self._tls is not None and self._tls.error:
                ok = bool(self._metadata.versions or self._metadata.certificates)
                return self._result(
                    ok,
                    "partial" if ok else "failed",
                    f"TLS stopped: {self._tls.error}",
                    methods,
                )
        ok = bool(self._metadata.versions or self._metadata.certificates)
        return self._result(
            ok,
            "partial" if ok else "timeout",
            "probe timeout after collecting available outer evidence",
            methods,
        )

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
        if packet.eap_data:
            self._method_version_flags = packet.eap_data[0] & 0x1F
        more, start, total_length, fragment = eap_tls_fragment(packet.eap_data)
        if start and not fragment:
            outgoing = self._tls.advance() if self._tls is not None else b""
            await self._queue_tls(transport, packet.eap_identifier, outgoing)
            return
        if self._outgoing_tls and not fragment:
            await self._send_next_tls_fragment(transport, packet.eap_identifier)
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
        self._merge_metadata(parse_tls_records(incoming))
        outgoing = self._tls.advance(incoming) if self._tls is not None else b""
        await self._queue_tls(transport, packet.eap_identifier, outgoing)

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

    def _merge_metadata(self, metadata: TlsMetadata) -> None:
        self._metadata.versions.update(metadata.versions)
        self._metadata.client_versions.update(metadata.client_versions)
        self._metadata.cipher_suites.update(metadata.cipher_suites)
        self._metadata.client_cipher_suites.update(metadata.client_cipher_suites)
        self._metadata.server_names.update(metadata.server_names)
        self._metadata.supported_groups.update(metadata.supported_groups)
        self._metadata.signature_algorithms.update(metadata.signature_algorithms)
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
        ):
            self._event("tls", "Observed outer TLS metadata", direction="local")

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
        self._events.append(EnterpriseProbeEvent(
            timestamp=time.time(),
            phase=phase,
            detail=detail,
            direction=direction,
            eap_identifier=packet.eap_identifier if packet is not None else None,
            eap_type=packet.eap_type if packet is not None else None,
        ))
        if len(self._events) > 128:
            del self._events[:-128]

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
        return EnterpriseProbeResult(
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
        )
