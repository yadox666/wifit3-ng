import shutil
import ssl
import struct

import pytest

from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig
from wifit3.campaigns.eap_lab_tls import ensure_lab_tls_material
from wifit3.campaigns.peap_server import PeapServerSession, tls_content_hint, tls_handshake_names
from wifit3.dot11.eap import (
    EAP_REQUEST,
    EAP_RESPONSE,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_MSCHAPV2,
    EAP_TYPE_NAK,
    EAP_TYPE_PAP,
    EAP_TYPE_PEAP,
    EAP_TYPE_TLS,
    EAP_TYPE_TTLS,
)
from wifit3.dot11.enterprise import eap_tls_fragment
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.parser import WlanFrameParser


BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "02:11:22:33:44:55"


def _packet(code, identifier, eap_type=None, data=b""):
    body = b"" if eap_type is None else bytes([eap_type]) + data
    eap = struct.pack(">BBH", code, identifier, 4 + len(body)) + body
    dot1x = struct.pack(">BBH", 2, 0, len(eap)) + eap
    frame = (
        data_header(
            to_ds=True,
            bssid=str_to_mac(BSSID),
            client=str_to_mac(CLIENT),
        )
        + LLC_SNAP_EAPOL
        + dot1x
    )
    return WlanFrameParser.parse_80211_frame(frame, 0)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_server_sends_identity_then_peap_start(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    start = session.on_eapol_start(str_to_mac(BSSID), str_to_mac(CLIENT))
    assert len(start.outgoing) == 1
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"user@corp.example")
    result = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    assert len(result.outgoing) == 1
    parsed = WlanFrameParser.parse_80211_frame(result.outgoing[0], 0)
    assert parsed.eap_type == EAP_TYPE_PEAP
    assert parsed.eap_data[0] & 0x20
    assert parsed.eap_data[0] & 0x1F == 1
    assert "PEAP start" in result.detail
    assert "accepted user user@corp.example" in result.detail
    assert session._inner_username == "user@corp.example"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_server_captures_rfc_mschapv2_response(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    session._server_challenge = b"\x11" * 16
    session._inner_username = "labuser"
    name = b"labuser"
    value = (b"\x22" * 16) + (b"\x00" * 8) + (b"\x44" * 24) + b"\x00"
    mschap = (
        bytes([2, 1])
        + (4 + 1 + 49 + len(name)).to_bytes(2, "big")
        + bytes([49])
        + value
        + name
    )
    inner = struct.pack(">BBH", 2, 7, 5 + len(mschap)) + bytes([EAP_TYPE_MSCHAPV2]) + mschap
    result = session._consume_inner(str_to_mac(BSSID), str_to_mac(CLIENT), inner)
    assert result.capture is not None
    assert result.capture.username == "labuser"
    assert result.capture.nt_response == b"\x44" * 24
    assert result.capture.server_challenge == b"\x11" * 16
    assert "user labuser" in (result.detail or "")
    assert "challenge " + ("11" * 16) in (result.detail or "")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_silent_method_advances_to_peap(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(
        material,
        eap_methods=(EAP_TYPE_TTLS, EAP_TYPE_PEAP, EAP_TYPE_TLS),
    )
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser")
    first = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    assert first.eap_method == EAP_TYPE_TTLS
    assert "TTLS start" in first.detail
    assert session.method_offer_pending()
    nxt = session.on_method_timeout(str_to_mac(BSSID), str_to_mac(CLIENT))
    assert nxt.eap_method == EAP_TYPE_PEAP
    assert "PEAP start" in nxt.detail
    assert "silent TTLS" in nxt.detail
    parsed = WlanFrameParser.parse_80211_frame(nxt.outgoing[0], 0)
    assert parsed.eap_type == EAP_TYPE_PEAP
    assert parsed.eap_data[0] & 0x21 == 0x21


# TLS ClientHello captured from the lab phone (no credentials).
_PEAP_CLIENT_HELLO = bytes.fromhex(
    "810000009716030100920100008e03036aca4745c36edff0c2eded43f9474512"
    "3eedcadc039dccf5c0802784f34b343700002c00ffc02cc02bc024c023c00ac0"
    "09c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a01"
    "000039000a00080006001700180019000b00020100000d001200100401020105"
    "01060104030203050306030005000501000000000012000000170000"
)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_clienthello_does_not_fail_when_tls_is_lazy(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    session.on_eapol_start(str_to_mac(BSSID), str_to_mac(CLIENT))
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser")
    start = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    assert start.eap_method == EAP_TYPE_PEAP
    assert session._tls is None
    hello = _packet(EAP_RESPONSE, 2, EAP_TYPE_PEAP, _PEAP_CLIENT_HELLO)
    result = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), hello)
    assert session._tls is not None
    assert not result.failed
    assert result.outgoing
    parsed = WlanFrameParser.parse_80211_frame(result.outgoing[0], 0)
    assert parsed.eap_identifier != 2
    assert parsed.eap_code == EAP_REQUEST
    replay = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), hello)
    assert not replay.failed
    if session._tls_frag_rest:
        ack = _packet(EAP_RESPONSE, parsed.eap_identifier, EAP_TYPE_PEAP, b"\x01")
        nxt = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), ack)
        assert nxt.outgoing
        assert "fragment" in (nxt.detail or "")


def _tls_from_eap_frames(frames):
    buf = bytearray()
    for frame in frames:
        parsed = WlanFrameParser.parse_80211_frame(frame, 0)
        _more, _start, _total, fragment = eap_tls_fragment(parsed.eap_data or b"")
        buf.extend(fragment)
    return bytes(buf)


def _handshake_until_last_fragment(session):
    session.on_eapol_start(str_to_mac(BSSID), str_to_mac(CLIENT))
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser")
    session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    hello = _packet(EAP_RESPONSE, 2, EAP_TYPE_PEAP, _PEAP_CLIENT_HELLO)
    result = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), hello)
    frames = list(result.outgoing)
    while session._tls_frag_rest:
        last = WlanFrameParser.parse_80211_frame(frames[-1], 0)
        ack = _packet(EAP_RESPONSE, last.eap_identifier, EAP_TYPE_PEAP, b"\x01")
        nxt = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), ack)
        frames.extend(nxt.outgoing)
    return frames


def test_tls_content_hint_lists_certificaterequest():
    def _hs(kind, body=b"x"):
        return bytes([kind]) + len(body).to_bytes(3, "big") + body

    def _rec(payload):
        return bytes([0x16, 0x03, 0x03]) + len(payload).to_bytes(2, "big") + payload

    flight = _rec(_hs(2) + _hs(11) + _hs(13) + _hs(14, b""))
    hint = tls_content_hint(flight)
    assert "ServerHello" in hint
    assert "CertificateRequest" in hint
    assert "ServerHelloDone" in hint


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_serverhello_omits_certificaterequest(tmp_path):
    material = ensure_lab_tls_material(tmp_path, request_client_cert=True)
    session = PeapServerSession(material)
    frames = _handshake_until_last_fragment(session)
    names = tls_handshake_names(_tls_from_eap_frames(frames))
    assert "ServerHello" in names
    assert "Certificate" in names
    assert "ServerHelloDone" in names
    assert "CertificateRequest" not in names
    assert "SKE" not in names
    assert "ServerKeyExchange" not in names
    last = WlanFrameParser.parse_80211_frame(frames[-1], 0)
    ack = _packet(EAP_RESPONSE, last.eap_identifier, EAP_TYPE_PEAP, b"\x01")
    extra = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), ack)
    assert extra.outgoing == []
    assert "no pending fragment" not in (extra.detail or "")
    assert session.awaiting_client_tls()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_serverhello_fits_in_one_eap_frame(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    session.on_eapol_start(str_to_mac(BSSID), str_to_mac(CLIENT))
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser")
    session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    hello = _packet(EAP_RESPONSE, 2, EAP_TYPE_PEAP, _PEAP_CLIENT_HELLO)
    result = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), hello)
    assert result.outgoing
    assert len(result.outgoing) == 1
    assert session._tls_frag_rest == []
    assert "fragment" not in (result.detail or "")
    names = tls_handshake_names(_tls_from_eap_frames(result.outgoing))
    assert "ServerHello" in names
    assert "Certificate" in names
    assert "ServerHelloDone" in names


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_accepts_condensed_inner_mschapv2(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    session._server_challenge = b"\x11" * 16
    session._inner_username = "labuser"
    name = b"labuser"
    value = (b"\x22" * 16) + (b"\x00" * 8) + (b"\x44" * 24) + b"\x00"
    mschap = (
        bytes([2, 1])
        + (4 + 1 + 49 + len(name)).to_bytes(2, "big")
        + bytes([49])
        + value
        + name
    )
    condensed = bytes([EAP_TYPE_MSCHAPV2]) + mschap
    result = session._consume_inner(str_to_mac(BSSID), str_to_mac(CLIENT), condensed)
    assert result.capture is not None
    assert result.capture.username == "labuser"
    assert result.capture.nt_response == b"\x44" * 24
    assert not result.failed


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_hello_overrides_silent_ttls_offer(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(
        material,
        eap_methods=(EAP_TYPE_TTLS, EAP_TYPE_PEAP),
    )
    identity = _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser")
    first = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), identity)
    assert first.eap_method == EAP_TYPE_TTLS
    hello = _packet(EAP_RESPONSE, 2, EAP_TYPE_PEAP, _PEAP_CLIENT_HELLO)
    result = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), hello)
    assert result.eap_method == EAP_TYPE_PEAP
    assert not result.failed
    assert result.outgoing


def _peap_tls(payload: bytes) -> bytes:
    return bytes([0x81]) + len(payload).to_bytes(4, "big") + payload


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_peap_client_key_exchange_is_not_treated_as_hello_replay(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    client_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    client_ctx.set_ciphers("AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:@SECLEVEL=0")
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    client = client_ctx.wrap_bio(incoming, outgoing, server_side=False)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    session = PeapServerSession(material)
    session.on_eapol_start(str_to_mac(BSSID), str_to_mac(CLIENT))
    session.on_eap(
        str_to_mac(BSSID),
        str_to_mac(CLIENT),
        _packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"labuser"),
    )
    server = session.on_eap(
        str_to_mac(BSSID),
        str_to_mac(CLIENT),
        _packet(EAP_RESPONSE, 2, EAP_TYPE_PEAP, _peap_tls(hello)),
    )
    incoming.write(_tls_from_eap_frames(server.outgoing))
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    cke = outgoing.read()
    assert cke.startswith(b"\x16")
    assert cke[5] != 1
    assert session._is_tls_replay(cke) is False
    result = session.on_eap(
        str_to_mac(BSSID),
        str_to_mac(CLIENT),
        _packet(EAP_RESPONSE, 3, EAP_TYPE_PEAP, _peap_tls(cke)),
    )
    assert not result.failed
    assert "retransmit" not in (result.detail or "")
    assert result.outgoing
    assert session._tunnel_ready
    hint = tls_handshake_names(_tls_from_eap_frames(result.outgoing))
    assert "ChangeCipherSpec" in hint
    assert "inner EAP-Request Identity" not in (result.detail or "")
    ack = _packet(EAP_RESPONSE, 4, EAP_TYPE_PEAP, b"\x01")
    phase2 = session.on_eap(str_to_mac(BSSID), str_to_mac(CLIENT), ack)
    assert "inner PAP probe" in (phase2.detail or "")
    assert not session._sent_mschap_challenge
    fallback = session.on_phase2_timeout(str_to_mac(BSSID), str_to_mac(CLIENT))
    assert "MS-CHAPv2 Challenge" in (fallback.detail or "")
    assert session._sent_mschap_challenge


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_inner_pap_accept_is_finding_and_never_logs_secret(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(material)
    session._inner_username = "labuser"
    session._offered_inner_pap = True
    secret = b"not-a-real-password"
    inner = struct.pack(">BBH", EAP_RESPONSE, 8, 5 + len(secret)) + bytes([EAP_TYPE_PAP]) + secret
    result = session._consume_inner(str_to_mac(BSSID), str_to_mac(CLIENT), inner)
    assert result.complete
    assert result.misconfiguration == "inner_pap_accepted"
    assert "vulnerable" in (result.detail or "")
    assert "labuser" in (result.detail or "")
    assert secret.decode() not in (result.detail or "")
    assert result.capture is None
    assert result.lab_credential == ("labuser", secret.decode())


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")
def test_inner_pap_nak_falls_back_to_mschapv2(tmp_path):
    material = ensure_lab_tls_material(tmp_path)
    session = PeapServerSession(
        material,
        launch=EapLabLaunchConfig(timeout=30, probe_inner_pap=True),
    )
    session._inner_username = "labuser"
    session._offered_inner_pap = True
    nak = struct.pack(">BBH", EAP_RESPONSE, 8, 6) + bytes([EAP_TYPE_NAK, EAP_TYPE_MSCHAPV2])
    result = session._consume_inner(str_to_mac(BSSID), str_to_mac(CLIENT), nak)
    assert "NAK of PAP" in (result.detail or "")
    assert "MS-CHAPv2 Challenge" in (result.detail or "")
    assert session._sent_mschap_challenge
