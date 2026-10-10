from pathlib import Path
from types import SimpleNamespace

from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig
from wifit3.persist.pcap import LINKTYPE_IEEE802_11, PCAP_MAGIC
from wifit3.campaigns.peap_honeypot import PeapHoneypotCampaign
from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.auth_assoc import assoc_req, auth_req
from wifit3.dot11.deauth import build_deauth
from wifit3.dot11.eap import EAP_RESPONSE, EAP_TYPE_IDENTITY
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.mac import mac_to_str, str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_req
from wifit3.persist.config import Config


CLIENT = bytes.fromhex("021122334455")
REAL = "00:15:6d:7c:f1:90"


class _Iface:
    def __init__(self, name="wlan0", channels=None):
        self.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE)
        self.supported_channels = list(channels or [1, 6, 11])
        self.name = name
        self.sent = []

    async def send_no_wait(self, frame):
        self.sent.append(bytes(frame))
        return True

    def register_rx_callback(self, callback):
        return None

    def unregister_rx_callback(self, callback):
        return None


class _Array:
    def __init__(self, iface):
        self.members = [iface]
        self.preferred = iface

    def register_own_fake_ap(self, *args, **kwargs):
        return SimpleNamespace()

    def record_own_fake_ap_beacon(self, bssid):
        return None

    def finish_own_fake_ap(self, bssid):
        return None

    def register_own_mac(self, mac):
        return None

    def unregister_own_mac(self, mac):
        return None


def _campaign(tmp_path, monkeypatch, **launch_kw):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path / "captures"))
    monkeypatch.setattr(
        "wifit3.campaigns.peap_honeypot.ensure_lab_tls_material",
        lambda *a, **k: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "wifit3.campaigns.peap_honeypot.ensure_private_directory",
        lambda p: p,
    )
    iface = _Iface()
    ap = SimpleNamespace(
        bssid=REAL,
        ssid="EAP-TEST",
        channel=1,
        last_beacon_frame=None,
        rsn_ie=b"",
        pmf_capable=False,
        pmf_required=False,
        akms=["EAP"],
    )
    camp = PeapHoneypotCampaign(
        _Array(iface),
        ap,
        launch=EapLabLaunchConfig(timeout=60, eviction=False, **launch_kw),
    )
    camp._iface = iface
    return camp


def _parse(frame):
    return WlanFrameParser.parse_80211_frame(frame, -40)


def test_directed_probe_and_real_ap_auth_are_logged(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    camp._dispatch(_parse(probe_req(camp.bssid, CLIENT, camp.ssid)))
    camp._dispatch(_parse(auth_req(str_to_mac(REAL), CLIENT)))
    camp._dispatch(_parse(auth_req(camp.bssid, CLIENT)))
    text = "\n".join(camp._events)
    assert camp.ssid == "EAP-TEST-LAB"
    assert f"directed probe for {camp.ssid}" in text
    assert "auth to the REAL AP" in text
    assert "Auth Open-System" in text
    assert camp.bssid_text in text


def test_disassoc_from_lab_client_is_logged(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    camp._dispatch(_parse(assoc_req(camp.bssid, CLIENT, camp.ssid)))
    camp._dispatch(
        _parse(build_deauth(camp.bssid, CLIENT, camp.bssid, 8, disassoc=True))
    )
    text = "\n".join(camp._events)
    assert "Disassoc" in text


def test_assoc_sends_eap_identity_request(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    camp._dispatch(_parse(assoc_req(camp.bssid, CLIENT, camp.ssid)))
    text = "\n".join(camp._events)
    assert "associated to Enterprise lab AP" in text
    assert "EAP-Request Identity" in text


def test_identity_logs_outer_method_start(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    camp._dispatch(_parse(assoc_req(camp.bssid, CLIENT, camp.ssid)))
    identity = (
        data_header(to_ds=True, bssid=camp.bssid, client=CLIENT)
        + LLC_SNAP_EAPOL
        + bytes([2, 0, 0, 12])
        + bytes([EAP_RESPONSE, 1, 0, 12, EAP_TYPE_IDENTITY])
        + b"labuser"
    )
    camp._dispatch(_parse(identity))
    text = "\n".join(camp._events)
    assert "Identity (labuser)" in text
    assert "start" in text
    assert "AP · →" in text
    client = camp._clients[mac_to_str(CLIENT)]
    assert client.session is not None
    assert client.session.method_offer_pending()


def test_eapol_before_assoc_is_accepted(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    frame = (
        data_header(to_ds=True, bssid=camp.bssid, client=CLIENT)
        + LLC_SNAP_EAPOL
        + bytes([1, 1, 0, 0])
    )
    camp._dispatch(_parse(frame))
    text = "\n".join(camp._events)
    assert "EAPOL before assoc" in text
    assert mac_to_str(CLIENT) in camp._clients


def test_record_pcap_writes_libpcap_from_start(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch)
    camp._open_pcap()
    assert camp.pcap_path
    path = Path(camp.pcap_path)
    header = path.read_bytes()[:24]
    assert header[:4] == PCAP_MAGIC.to_bytes(4, "little")
    assert int.from_bytes(header[20:24], "little") == LINKTYPE_IEEE802_11
    camp._capture_frame(b"\x80" + b"\x00" * 23)
    camp._close_pcap()
    text = "\n".join(camp._events)
    assert "tcpdump capture ON" in text
    assert path.name in text
    assert "tcpdump capture saved" in text
    assert path.stat().st_size > 24


def test_honeypot_uses_selected_card_and_channel(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch, iface_name="wlan0", lab_channel=6)
    assert camp.channel == 6
    assert camp.iface.name == "wlan0"


def test_record_pcap_can_be_disabled(tmp_path, monkeypatch):
    camp = _campaign(tmp_path, monkeypatch, record_pcap=False)
    camp._open_pcap()
    assert camp.pcap_path is None
    assert camp._pcap is None
    assert "tcpdump capture OFF" in "\n".join(camp._events)
