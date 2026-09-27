import asyncio
from types import SimpleNamespace

from wifit3.campaigns.open_probe_ap import (
    OpenProbeApCampaign,
    OpenProbePhase,
    random_bssid,
)
from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.auth_assoc import assoc_req, auth_req
from wifit3.dot11.dhcp import build_discover
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header, eapol_key
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_req
from wifit3.models import Client

CLIENT = bytes.fromhex("021122334455")
OTHER = bytes.fromhex("02aabbccddee")
SSID = "DefaultSSID"


class _Iface:
    def __init__(self, channels=(1, 6, 11)):
        self.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE)
        self.supported_channels = list(channels)
        self.name = "wlan0"
        self.sent = []

    async def send_no_wait(self, frame):
        self.sent.append(bytes(frame))
        return True


class _Array:
    def __init__(self, members):
        self.members = members
        self.preferred = None
        self.injected_eapol = []

    def record_injected_eapol(self, frame):
        self.injected_eapol.append(frame)


def _parse(frame):
    return WlanFrameParser.parse_80211_frame(frame, -40)


def _m2(bssid, client):
    payload = eapol_key(
        key_info=0x010A,
        key_len=0,
        replay=1,
        nonce=bytes(range(32)),
        key_data=GENERIC_RSN_IE,
    )
    return data_header(
        to_ds=True, bssid=bssid, client=client,
    ) + LLC_SNAP_EAPOL + payload


async def _flush():
    await asyncio.sleep(0.01)


def test_random_bssid_is_local_unicast_and_campaign_selects_spoofable_interface():
    bssid = random_bssid()
    assert bssid[0] & 0x02
    assert not bssid[0] & 0x01

    unsupported = _Iface((36,))
    supported = _Iface((6,))
    campaign = OpenProbeApCampaign(
        _Array([unsupported, supported]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
    )
    assert campaign.iface is supported
    assert campaign.timeout == 60


async def test_directed_and_wildcard_probes_are_distinguished():
    campaign = OpenProbeApCampaign(
        _Array([_Iface((6,))]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        bssid=bytes.fromhex("02deadbeef01"),
    )

    campaign.on_rx(_parse(probe_req(campaign.bssid, CLIENT, "")))
    campaign.on_rx(_parse(probe_req(campaign.bssid, CLIENT, SSID)))
    await _flush()

    attempt = campaign.stats.clients["02:11:22:33:44:55"]
    assert attempt.wildcard_probes == attempt.directed_probes == 1
    assert any("wildcard scan observed" in event for event in campaign.stats.events)
    assert any("directed probe received" in event for event in campaign.stats.events)


async def test_all_clients_are_answered_and_recorded_through_dhcp():
    iface = _Iface((6,))
    campaign = OpenProbeApCampaign(
        _Array([iface]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        bssid=bytes.fromhex("02deadbeef01"),
    )

    campaign.on_rx(_parse(probe_req(campaign.bssid, OTHER, SSID)))
    await _flush()
    other_text = "02:aa:bb:cc:dd:ee"
    assert campaign.stats.clients[other_text].phase is OpenProbePhase.PROBED
    assert campaign.stats.clients[other_text].is_target is False
    assert len(iface.sent) == 1
    assert iface.sent[-1][4:10] == OTHER

    campaign.on_rx(_parse(auth_req(campaign.bssid, OTHER)))
    campaign.on_rx(_parse(assoc_req(
        campaign.bssid, OTHER, SSID, privacy=False, channel=6,
    )))
    campaign.on_rx(_parse(build_discover(campaign.bssid, OTHER, 0x87654321)))
    other = campaign.stats.clients[other_text]
    assert other.phase is OpenProbePhase.DHCP
    assert other.probes == other.auth == other.assoc == other.dhcp == 1
    assert other.directed_probes == 1 and other.wildcard_probes == 0
    assert any(event.startswith(f"CLIENT {other_text}") for event in campaign.stats.events)

    campaign.on_rx(_parse(probe_req(campaign.bssid, CLIENT, SSID)))
    campaign.on_rx(_parse(auth_req(campaign.bssid, CLIENT)))
    campaign.on_rx(_parse(assoc_req(
        campaign.bssid, CLIENT, SSID, privacy=False, channel=6,
    )))
    await _flush()

    assert campaign.stats.phase is OpenProbePhase.DHCP
    assert campaign.stats.probes == campaign.stats.auth == campaign.stats.assoc == 2
    assert any(frame[:2] == b"\x50\x00" for frame in iface.sent)
    assert any(frame[:2] == b"\xb0\x00" for frame in iface.sent)
    assoc_response = next(frame for frame in iface.sent if frame[:2] == b"\x10\x00")
    assert assoc_response[24:26] == b"\x01\x00"

    campaign.on_rx(_parse(build_discover(campaign.bssid, CLIENT, 0x12345678)))
    assert campaign.stats.phase is OpenProbePhase.DHCP
    assert campaign.stats.dhcp_discover == 2
    target = campaign.stats.clients["02:11:22:33:44:55"]
    assert target.is_target and target.phase is OpenProbePhase.DHCP
    assert target.probes == target.auth == target.assoc == target.dhcp == 1
    assert campaign.stats.events[-1] == (
        "ORIGIN 02:11:22:33:44:55 · DHCP Discover observed"
    )


async def test_wpa2_mode_advertises_rsn_and_captures_m2():
    iface = _Iface((6,))
    array = _Array([iface])
    campaign = OpenProbeApCampaign(
        array,
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        bssid=bytes.fromhex("02deadbeef01"),
        encryption="WPA2",
    )

    campaign.on_rx(_parse(probe_req(campaign.bssid, CLIENT, SSID)))
    campaign.on_rx(_parse(auth_req(campaign.bssid, CLIENT)))
    campaign.on_rx(_parse(assoc_req(
        campaign.bssid, CLIENT, SSID, GENERIC_RSN_IE, channel=6,
    )))
    await _flush()

    assert GENERIC_RSN_IE in campaign._beacon
    assert len(array.injected_eapol) == 1
    assert array.injected_eapol[0] in iface.sent

    campaign.on_rx(_parse(_m2(campaign.bssid, CLIENT)))
    target = campaign.stats.clients["02:11:22:33:44:55"]
    assert target.m2 == 1
    assert target.phase is OpenProbePhase.EAPOL_M2
    assert campaign.stats.m2 == 1
    assert campaign._result_for_phase() == "handshake"
