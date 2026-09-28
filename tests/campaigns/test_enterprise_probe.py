import asyncio
import struct
from types import SimpleNamespace

import pytest

from wifit3.campaigns.enterprise_probe import EnterpriseProbe
from wifit3.dot11.eap import EAP_TLS_TYPES, EAP_TYPE_IDENTITY
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
    probe = EnterpriseProbe(SimpleNamespace(), ap)
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
    result = await _probe()._exchange(transport, timeout=0.5)

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
