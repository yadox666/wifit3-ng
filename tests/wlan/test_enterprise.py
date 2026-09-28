import sqlite3

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.enterprise import parse_der_certificate, parse_tls_records
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.packet import EapPacket
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models import (
    AccessPoint,
    EnterpriseCertificate,
    EnterpriseProbeEvent,
    EnterpriseProbeRun,
)
from wifit3.persist.enterprise_sessions import EnterpriseSessionStore
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


def _eap_result_frame(code):
    eap = bytes([code, 7]) + (4).to_bytes(2, "big")
    dot1x = bytes([2, 0]) + len(eap).to_bytes(2, "big") + eap
    return (
        data_header(
            to_ds=False,
            bssid=str_to_mac(BSSID),
            client=str_to_mac(CLIENT),
        )
        + LLC_SNAP_EAPOL
        + dot1x
    )


def test_enterprise_certificate_structure_findings():
    ap = AccessPoint(bssid=BSSID, ssid="Corp", akms=["EAP"])
    leaf = EnterpriseCertificate(
        fingerprint="a" * 64,
        subject="CN=radius.example.test",
        issuer="CN=Unexpected CA",
        public_key_algorithm="EC",
        public_key_bits=224,
        extended_key_usage=("clientAuth",),
        is_ca=True,
    )
    parent = EnterpriseCertificate(
        fingerprint="b" * 64,
        subject="CN=Different CA",
        issuer="CN=Different CA",
        is_ca=True,
    )
    ap.enterprise.certificates = {
        leaf.fingerprint: leaf,
        parent.fingerprint: parent,
    }

    labels = {finding.label for finding in enterprise_findings(ap)}

    assert "Short EC certificate key (224 bits)" in labels
    assert "RADIUS leaf certificate lacks serverAuth EKU" in labels
    assert "RADIUS leaf certificate is marked as a CA" in labels
    assert "RADIUS leaf certificate has no DNS SAN" in labels
    assert "RADIUS certificate chain appears incomplete" in labels
    assert "RADIUS certificate chain issuer mismatch" in labels


def _server_hello(cipher=0x000A):
    body = b"\x03\x03" + bytes(32) + b"\x00"
    body += cipher.to_bytes(2, "big") + b"\x00\x00\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _client_hello():
    ciphers = bytes.fromhex("1301c02f")
    extensions = b""
    extensions += bytes.fromhex("002b0005") + bytes.fromhex("0403040303")
    sni_name = b"radius.example.test"
    sni = b"\x00" + len(sni_name).to_bytes(2, "big") + sni_name
    sni = len(sni).to_bytes(2, "big") + sni
    extensions += bytes.fromhex("0000") + len(sni).to_bytes(2, "big") + sni
    groups = bytes.fromhex("001d0017")
    groups = len(groups).to_bytes(2, "big") + groups
    extensions += bytes.fromhex("000a") + len(groups).to_bytes(2, "big") + groups
    signatures = bytes.fromhex("08040403")
    signatures = len(signatures).to_bytes(2, "big") + signatures
    extensions += bytes.fromhex("000d") + len(signatures).to_bytes(2, "big") + signatures
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


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
    san_value = _tlv(0x30, _tlv(0x82, b"radius.test"))
    san = _tlv(
        0x30,
        _tlv(0x06, bytes.fromhex("551d11")) + _tlv(0x04, san_value),
    )
    eku_value = _tlv(0x30, _tlv(0x06, bytes.fromhex("2b06010505070301")))
    eku = _tlv(
        0x30,
        _tlv(0x06, bytes.fromhex("551d25")) + _tlv(0x04, eku_value),
    )
    basic = _tlv(
        0x30,
        _tlv(0x06, bytes.fromhex("551d13")) + _tlv(0x04, _tlv(0x30, b"")),
    )
    extensions = _tlv(0xA3, _tlv(0x30, san + eku + basic))
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))
        + _tlv(0x02, b"\x01")
        + sha1_rsa
        + issuer
        + validity
        + subject
        + public_key
        + extensions,
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


def test_parser_extracts_legacy_nak_alternative_methods():
    parsed = WlanFrameParser.parse_80211_frame(
        _eap_frame(3, bytes([13, 25, 55]), code=2, to_ds=True),
        -40,
    )

    assert isinstance(parsed, EapPacket)
    assert parsed.eap_nak_types == (13, 25, 55)


def test_sink_records_terminal_eap_outcomes_without_an_eap_type():
    sink = WlanSink()
    ap = AccessPoint(bssid=BSSID, ssid="Enterprise", akms=["EAP"])
    sink.access_points[BSSID] = ap

    success = WlanFrameParser.parse_80211_frame(_eap_result_frame(3), -40)
    failure = WlanFrameParser.parse_80211_frame(_eap_result_frame(4), -40)
    assert isinstance(success, EapPacket)
    assert isinstance(failure, EapPacket)
    sink.update(success, "wlan0")
    sink.update(failure, "wlan0")

    assert ap.enterprise.eap_successes == 1
    assert ap.enterprise.eap_failures == 1
    assert [session.outcome for session in ap.enterprise.sessions] == ["success", "failure"]
    assert all(CLIENT not in session.client_id for session in ap.enterprise.sessions)


def test_sink_persists_pseudonymous_enterprise_sessions(tmp_path):
    path = tmp_path / "enterprise_sessions.sqlite3"
    store = EnterpriseSessionStore(path)
    sink = WlanSink(enterprise_sessions=store)
    ap = AccessPoint(bssid=BSSID, ssid="Enterprise", akms=["EAP"])
    sink.access_points[BSSID] = ap

    sink.update(pkt({
        "type": "eapol",
        "bssid": BSSID,
        "source": BSSID,
        "dest": CLIENT,
        "from_ds": True,
        "rssi": -40,
        "eap_code": 1,
        "eap_type": 25,
    }), "wlan0")
    success = WlanFrameParser.parse_80211_frame(_eap_result_frame(3), -40)
    assert isinstance(success, EapPacket)
    sink.update(success, "wlan0")
    ap.enterprise.probe_attempts = 1
    ap.enterprise.probe_last_status = "complete"
    ap.enterprise.probe_last_detail = "outer TLS completed"
    ap.enterprise.probe_last_seen = 1234
    ap.enterprise.probe_history.append(EnterpriseProbeRun(
        started_at=1233,
        ended_at=1234,
        status="complete",
        detail="outer TLS completed",
        association_ok=True,
        eap_method=25,
        events=[EnterpriseProbeEvent(
            timestamp=1233.5,
            phase="tls",
            detail="metadata observed",
            direction="local",
        )],
    ))
    store.remember(ap, force=True)

    reloaded = EnterpriseSessionStore(path)
    persisted = reloaded.profile_for(BSSID)
    assert persisted is not None
    assert persisted.server_eap_types == {25}
    assert len(persisted.sessions) == 1
    assert persisted.sessions[0].outcome == "success"
    assert persisted.sessions[0].client_id == reloaded.client_id(BSSID, CLIENT)
    assert persisted.probe_attempts == 1
    assert persisted.probe_last_status == "complete"
    assert persisted.probe_history[0].events[0].phase == "tls"
    with sqlite3.connect(path) as connection:
        stored_json = connection.execute(
            "SELECT profile_json FROM enterprise_profiles WHERE bssid = ?",
            (BSSID,),
        ).fetchone()[0]
    assert CLIENT not in stored_json


def test_tls_parser_extracts_server_version_and_cipher():
    metadata = parse_tls_records(_server_hello())
    assert metadata.versions == {"TLS 1.2"}
    assert metadata.cipher_suites == {0x000A}


def test_tls_parser_extracts_client_hello_capabilities():
    metadata = parse_tls_records(_client_hello())

    assert metadata.client_versions == {"TLS 1.2", "TLS 1.3"}
    assert metadata.client_cipher_suites == {0x1301, 0xC02F}
    assert metadata.server_names == {"radius.example.test"}
    assert metadata.supported_groups == {0x001D, 0x0017}
    assert metadata.signature_algorithms == {0x0804, 0x0403}


def test_certificate_parser_extracts_risk_relevant_metadata():
    certificate = parse_der_certificate(_test_certificate())
    assert certificate is not None
    assert len(certificate.fingerprint) == 64
    assert certificate.signature_algorithm == "RSA-SHA1"
    assert certificate.public_key_algorithm == "RSA"
    assert certificate.public_key_bits == 1024
    assert certificate.not_after is not None
    assert certificate.subject == "CN=radius.test"
    assert certificate.issuer == "CN=Test CA"
    assert certificate.san_dns == ("radius.test",)
    assert certificate.extended_key_usage == ("serverAuth",)
    assert certificate.is_ca is False

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
    assert ap.enterprise.eap_requests == 1
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
