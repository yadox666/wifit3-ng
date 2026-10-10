import asyncio
import struct
from types import SimpleNamespace

import pytest

from wifit3.campaigns.enterprise_probe import EnterpriseProbe
from wifit3.dot11.eap import (
    EAP_TLS_TYPES,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_MSCHAPV2,
    EAP_TYPE_PEAP,
    EAP_TYPE_TTLS,
)
from wifit3.dot11.enterprise import TlsMetadata
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.enterprise import eap_tls_fragment, parse_tls_records
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.packet import EapPacket
from wifit3.dot11.parser import WlanFrameParser


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "02:11:22:33:44:55"


def _eap_request(identifier, eap_type=None, data=b"", *, code=1):
    body = b"" if eap_type is None else bytes([eap_type]) + data
    eap = struct.pack(">BBH", code, identifier, 4 + len(body)) + body
    dot1x = struct.pack(">BBH", 2, 0, len(eap)) + eap
    return (
        data_header(
            to_ds=False,
            bssid=str_to_mac(BSSID),
            client=str_to_mac(CLIENT),
        )
        + LLC_SNAP_EAPOL
        + dot1x
    )


class _Transport:
    def __init__(self, frames=()):
        self.frames = list(frames)
        self.sent = []

    async def send_no_wait(self, frame):
        self.sent.append(frame)
        return True

    async def recv(self, timeout):
        if self.frames:
            return self.frames.pop(0)
        await asyncio.sleep(timeout)
        return None


def _probe():
    ap = SimpleNamespace(
        bssid=BSSID,
        ssid="Enterprise",
        channel=1,
        akms=["EAP"],
        akm_suites=[1],
        rsn_ie=b"",
        pmf_capable=False,
        pmf_required=False,
    )
    probe = EnterpriseProbe(
        SimpleNamespace(),
        ap,
        deep_lab=False,
        lab_identities=("anonymous",),
    )
    probe.our_mac = str_to_mac(CLIENT)
    return probe


async def test_exchange_uses_anonymous_identity_and_naks_unsupported_method():
    identity_request = _eap_request(1, EAP_TYPE_IDENTITY)
    transport = _Transport([
        identity_request,
        identity_request,
        _eap_request(2, 4),
        _eap_request(3, code=4),
    ])
    probe = _probe()
    await probe._exchange_phase(transport, timeout=0.5)
    result = probe._finalize_battery()

    identity = WlanFrameParser.parse_80211_frame(transport.sent[1], 0)
    nak = WlanFrameParser.parse_80211_frame(transport.sent[3], 0)
    assert isinstance(identity, EapPacket)
    assert identity.eap_type == EAP_TYPE_IDENTITY
    assert identity.eap_data == b""
    assert b"anonymous" in transport.sent[1]
    assert transport.sent[1] == transport.sent[2]
    assert isinstance(nak, EapPacket)
    assert nak.eap_type == 3
    assert set(nak.eap_nak_types) == EAP_TLS_TYPES
    assert result.status == "failed"
    assert result.server_methods == {1, 4}
    assert any(event.phase == "retransmission" for event in result.events)


async def test_tls_start_generates_parseable_client_hello():
    probe = _probe()
    transport = _Transport()
    request = WlanFrameParser.parse_80211_frame(
        _eap_request(7, 25, b"\x20"),
        0,
    )
    assert isinstance(request, EapPacket)

    await probe._handle_tls_request(transport, request)

    fragments = []
    total_length = None
    index = 0
    while True:
        response = WlanFrameParser.parse_80211_frame(transport.sent[index], 0)
        assert isinstance(response, EapPacket)
        more, _start, length, fragment = eap_tls_fragment(response.eap_data)
        total_length = total_length or length
        fragments.append(fragment)
        if not more:
            break
        index += 1
        ack = WlanFrameParser.parse_80211_frame(
            _eap_request(7 + index, 25, b"\x00"),
            0,
        )
        assert isinstance(ack, EapPacket)
        await probe._handle_tls_request(transport, ack)
    client_hello = b"".join(fragments)
    assert total_length == len(client_hello)
    metadata = parse_tls_records(client_hello)
    assert metadata.client_versions
    assert metadata.client_cipher_suites


async def test_progress_callback_receives_events():
    seen = []

    def on_event(event):
        seen.append(event.phase)

    probe = _probe()
    probe.on_event = on_event
    probe._event("preflight", "test", direction="local")
    assert seen == ["preflight"]


async def test_inner_eap_waits_for_client_finished_tls_outgoing():
    inner_identity_req = struct.pack(">BBH", 1, 42, 5) + bytes([EAP_TYPE_IDENTITY])
    write_app_calls: list[bytes] = []

    class _FakeTls:
        complete = True
        error = None

        def feed(self, incoming=b""):
            return (b"X" * 1000, inner_identity_req)

        def write_app(self, inner: bytes) -> bytes:
            write_app_calls.append(inner)
            return b"INNER_TLS"

        def drain_app(self) -> bytes:
            return b""

        def negotiated_metadata(self) -> TlsMetadata:
            return TlsMetadata()

    probe = _probe()
    probe._method = EAP_TYPE_PEAP
    probe._tls = _FakeTls()
    transport = _Transport()
    request = WlanFrameParser.parse_80211_frame(
        _eap_request(73, EAP_TYPE_PEAP, b"\x00" + b"server-flight"),
        0,
    )
    assert isinstance(request, EapPacket)

    await probe._handle_tls_request(transport, request)
    assert write_app_calls == []
    assert probe._pending_inner_app is not None or probe._outgoing_tls

    identifier = 73
    while probe._outgoing_tls or probe._pending_inner_app:
        identifier += 1
        ack = WlanFrameParser.parse_80211_frame(
            _eap_request(identifier, EAP_TYPE_PEAP, b"\x00"),
            0,
        )
        assert isinstance(ack, EapPacket)
        await probe._handle_tls_request(transport, ack)

    assert len(write_app_calls) == 1
    assert write_app_calls[0] == bytes([EAP_TYPE_IDENTITY]) + b"anonymous"


async def test_peap_condensed_mschapv2_challenge_is_captured():
    challenge = bytes.fromhex("bee8766b074f7aebed2e268e02d67173")
    condensed = (
        bytes([EAP_TYPE_MSCHAPV2, 1, 0xDD])
        + struct.pack(">H", 16)
        + challenge
        + b"freeradius-3.2.10"
    )
    probe = _probe()
    probe._inner_identity = b"labuser"
    await probe._consume_inner(condensed, _Transport(), 221)
    assert probe._capture_done
    assert probe._mschap_challenge_hex == challenge.hex()
    assert probe._mschap_username == "labuser"
    assert EAP_TYPE_MSCHAPV2 in probe._inner_eap_types


async def test_peap_freeradius_rfc_inner_mschapv2_is_captured():
    inner = bytes.fromhex(
        "01dd002b1a01dd002610bee8766b074f7aebed2e268e02d67173667265657261646975732d332e322e3130"
    )
    probe = _probe()
    await probe._consume_inner(inner, _Transport(), 221)
    assert probe._mschap_challenge_hex == "bee8766b074f7aebed2e268e02d67173"


async def test_peap_full_inner_mschapv2_challenge_is_captured():
    challenge = bytes.fromhex("0123456789abcdef0123456789abcdef")
    payload = bytes([1, 7]) + struct.pack(">H", 16) + challenge + b"lab"
    body = bytes([EAP_TYPE_MSCHAPV2]) + payload
    inner = struct.pack(">BBH", 1, 7, 4 + len(body)) + body
    probe = _probe()
    await probe._consume_inner(inner, _Transport(), 80)
    assert probe._mschap_challenge_hex == challenge.hex()


async def test_tls_declared_length_mismatch_is_rejected():
    probe = _probe()
    transport = _Transport()
    request = WlanFrameParser.parse_80211_frame(
        _eap_request(9, 25, b"\x80" + (10).to_bytes(4, "big") + b"abc"),
        0,
    )
    assert isinstance(request, EapPacket)

    with pytest.raises(ValueError, match="length mismatch"):
        await probe._handle_tls_request(transport, request)


def test_identity_phases_use_dialog_users_and_skip_anonymous_match():
    probe = EnterpriseProbe(
        SimpleNamespace(),
        SimpleNamespace(
            bssid=BSSID,
            ssid="Enterprise",
            channel=1,
            akms=["EAP"],
            akm_suites=[1],
            rsn_ie=b"",
            pmf_capable=False,
            pmf_required=False,
        ),
        deep_lab=True,
        lab_identities=("labuser", "anonymous"),
    )
    titles = [title for title, *_ in probe._identity_phases()]
    assert any("labuser" in title and "anon outer" in title for title in titles)
    assert any("matched labuser" in title for title in titles)
    assert not any("matched anonymous" in title for title in titles)


async def test_ttls_vendor_challenge_is_captured():
    challenge = bytes.fromhex("bee8766b074f7aebed2e268e02d67173")
    vsa = (311).to_bytes(4, "big") + bytes([11, 18]) + challenge
    avp = bytes([26, 2 + len(vsa)]) + vsa
    probe = _probe()
    probe._method = EAP_TYPE_TTLS
    await probe._consume_inner(avp, _Transport(), 9)
    assert probe._mschap_challenge_hex == challenge.hex()
