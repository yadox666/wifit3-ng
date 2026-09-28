import shutil
import struct

import pytest

from wifit3.campaigns.eap_lab_tls import ensure_lab_tls_material
from wifit3.campaigns.peap_server import PeapServerSession
from wifit3.dot11.eap import EAP_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_PEAP
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
