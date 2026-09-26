from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.enterprise import parse_der_certificate, parse_tls_records
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.packet import EapPacket
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models import AccessPoint
from wifit3.wlan.enterprise_risk import enterprise_findings
from wifit3.wlan.sink import WlanSink

from tests.frames import pkt


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "12:22:33:44:55:66"


def _eap_frame(eap_type, data=b"", *, code=1, to_ds=False):
    eap = bytes([code, 7]) + (5 + len(data)).to_bytes(2, "big")
    eap += bytes([eap_type]) + data
    dot1x = bytes([2, 0]) + len(eap).to_bytes(2, "big") + eap
    return (
        data_header(
            to_ds=to_ds,
            bssid=str_to_mac(BSSID),
            client=str_to_mac(CLIENT),
        )
        + LLC_SNAP_EAPOL
        + dot1x
    )


def _server_hello(cipher=0x000A):
    body = b"\x03\x03" + bytes(32) + b"\x00"
    body += cipher.to_bytes(2, "big") + b"\x00\x00\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _tlv(tag, value):
    if len(value) < 128:
        length = bytes([len(value)])
    else:
        encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


def _test_certificate():
    sha1_rsa = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010105")))
    rsa = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010101")))
    issuer = _tlv(0x30, _tlv(0x31, _tlv(
        0x30, _tlv(0x06, bytes.fromhex("550403")) + _tlv(0x0C, b"Test CA"),
    )))
    subject = _tlv(0x30, _tlv(0x31, _tlv(
        0x30, _tlv(0x06, bytes.fromhex("550403")) + _tlv(0x0C, b"radius.test"),
    )))
    validity = _tlv(
        0x30,
        _tlv(0x17, b"240101000000Z") + _tlv(0x17, b"300101000000Z"),
    )
    modulus = _tlv(0x02, b"\x00" + b"\x80" + bytes(127))
    rsa_key = _tlv(0x30, modulus + _tlv(0x02, b"\x01\x00\x01"))
    public_key = _tlv(0x30, rsa + _tlv(0x03, b"\x00" + rsa_key))
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))
        + _tlv(0x02, b"\x01")
        + sha1_rsa
        + issuer
        + validity
        + subject
        + public_key,
    )
    return _tlv(0x30, tbs + sha1_rsa + _tlv(0x03, b"\x00\x00"))


def test_parser_identifies_eap_method_without_retaining_identity():
    parsed = WlanFrameParser.parse_80211_frame(
        _eap_frame(1, b"private-user@example.test", code=2, to_ds=True),
        -40,
    )
    assert isinstance(parsed, EapPacket)
    assert parsed.eap_type == 1
    assert parsed.eap_code == 2
    assert parsed.eap_data == b""


def test_parser_keeps_only_tls_method_payload_for_passive_inspection():
    tls = b"\x00" + _server_hello()
    parsed = WlanFrameParser.parse_80211_frame(_eap_frame(25, tls), -40)
    assert isinstance(parsed, EapPacket)
    assert parsed.eap_data == tls


def test_tls_parser_extracts_server_version_and_cipher():
    metadata = parse_tls_records(_server_hello())
    assert metadata.versions == {"TLS 1.2"}
    assert metadata.cipher_suites == {0x000A}


def test_certificate_parser_extracts_risk_relevant_metadata():
    certificate = parse_der_certificate(_test_certificate())
    assert certificate is not None
    assert len(certificate.fingerprint) == 64
    assert certificate.signature_algorithm == "RSA-SHA1"
    assert certificate.public_key_algorithm == "RSA"
    assert certificate.public_key_bits == 1024
    assert certificate.not_after is not None

    ap = AccessPoint(bssid=BSSID, ssid="Enterprise", akms=["EAP"])
    ap.enterprise.certificates[certificate.fingerprint] = certificate
    labels = {finding.label for finding in enterprise_findings(ap)}
    assert "Weak certificate signature RSA-SHA1" in labels
    assert "Short RSA certificate key (1024 bits)" in labels


def test_tls_parser_extracts_certificate_message():
    der = _test_certificate()
    certificate_list = len(der).to_bytes(3, "big") + der
    body = len(certificate_list).to_bytes(3, "big") + certificate_list
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

    metadata = parse_tls_records(record)

    assert len(metadata.certificates) == 1
    assert len(metadata.certificates[0].fingerprint) == 64


def test_sink_profiles_eap_for_ap_and_client_and_flags_weak_methods():
    sink = WlanSink()
    ap = AccessPoint(
        bssid=BSSID,
        ssid="Enterprise",
        encryption="WPA2",
        akms=["EAP"],
        pairwise_ciphers=["CCMP"],
    )
    sink.access_points[BSSID] = ap
    sink.update(pkt({
        "type": "eapol",
        "bssid": BSSID,
        "source": BSSID,
        "dest": CLIENT,
        "from_ds": True,
        "rssi": -40,
        "eap_code": 1,
        "eap_type": 17,
    }), "wlan0")

    assert ap.enterprise.server_eap_types == {17}
    assert sink.clients[CLIENT].enterprise.server_eap_types == {17}
    assert any("LEAP" in finding.label for finding in enterprise_findings(ap))


def test_sink_reassembles_fragmented_outer_tls():
    sink = WlanSink()
    ap = AccessPoint(bssid=BSSID, ssid="Enterprise", akms=["EAP"])
    sink.access_points[BSSID] = ap
    tls = _server_hello()
    split = len(tls) // 2
    fragments = (
        b"\xC0" + len(tls).to_bytes(4, "big") + tls[:split],
        b"\x00" + tls[split:],
    )
    for data in fragments:
        sink.update(pkt({
            "type": "eapol",
            "bssid": BSSID,
            "source": BSSID,
            "dest": CLIENT,
            "from_ds": True,
            "rssi": -40,
            "eap_code": 1,
            "eap_type": 25,
            "eap_data": data,
        }), "wlan0")

    assert ap.enterprise.tls_versions == {"TLS 1.2"}
    assert ap.enterprise.tls_cipher_suites == {0x000A}
    assert any("3DES" in finding.label for finding in enterprise_findings(ap))
