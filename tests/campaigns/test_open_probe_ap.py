import asyncio
import os
from types import SimpleNamespace

from wifit3.campaigns import open_probe_ap
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
        self.rx_callbacks = []

    async def send_no_wait(self, frame):
        self.sent.append(bytes(frame))
        return True

    def register_rx_callback(self, callback):
        self.rx_callbacks.append(callback)

    def unregister_rx_callback(self, callback):
        if callback in self.rx_callbacks:
            self.rx_callbacks.remove(callback)


class _FakeAp:
    def __init__(self, bssid, ssid, channel, encryption):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.encryption = encryption
        self.last_beacon_frame = None
        self.beacons = 0
        self.active = True


class _Lease:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Claim:
    def __init__(self, iface):
        self.iface = iface

    async def __aenter__(self):
        return self.iface

    async def __aexit__(self, *exc):
        return False


class _Array:
    def __init__(self, members):
        self.members = members
        self.preferred = None
        self.injected_eapol = []
        self.access_points = {}
        self.own_macs = set()
        self.fake_aps = {}

    def record_injected_eapol(self, frame):
        self.injected_eapol.append(frame)

    def register_own_fake_ap(self, bssid, ssid, channel, encryption):
        ap = _FakeAp(bssid, ssid, channel, encryption)
        self.fake_aps[bssid] = ap
        self.access_points[bssid] = ap
        return ap

    def record_own_fake_ap_beacon(self, bssid):
        ap = self.fake_aps.get(bssid)
        if ap is not None:
            ap.beacons += 1

    def finish_own_fake_ap(self, bssid):
        ap = self.fake_aps.get(bssid)
        if ap is not None:
            ap.active = False

    def register_own_mac(self, mac):
        text = mac if isinstance(mac, str) else mac.hex()
        self.own_macs.add(text)
        return text

    def unregister_own_mac(self, mac):
        text = mac if isinstance(mac, str) else mac.hex()
        self.own_macs.discard(text)

    def claim(self, iface):
        return _Claim(iface)

    def lease(self, **kwargs):
        return _Lease()


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


async def test_engaging_clients_bypass_the_probe_observer_cap(monkeypatch):
    # A noisy channel of passive scanners is bounded, but a client that actually
    # authenticates is always registered: a honeypot must log every victim.
    monkeypatch.setattr(open_probe_ap, "_MAX_OBSERVED_CLIENTS", 2)
    campaign = OpenProbeApCampaign(
        _Array([_Iface((6,))]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        bssid=bytes.fromhex("02deadbeef01"),
    )

    # Fill the observer table with wildcard scanners up to the cap.
    for _ in range(5):
        scanner = b"\x02" + os.urandom(5)
        campaign.on_rx(_parse(probe_req(campaign.bssid, scanner, "")))
    await _flush()
    assert len(campaign.stats.clients) == 2

    # A brand-new client that authenticates is still recorded past the cap.
    victim = bytes.fromhex("02cafef00d99")
    campaign.on_rx(_parse(auth_req(campaign.bssid, victim)))
    await _flush()
    victim_text = "02:ca:fe:f0:0d:99"
    assert victim_text in campaign.stats.clients
    assert campaign.stats.clients[victim_text].phase is OpenProbePhase.AUTHENTICATED


def _endpoints_by_enc(campaign):
    return {ep.encryption: ep for ep in campaign.endpoints}


def test_dual_mode_builds_open_and_wpa2_endpoints_with_distinct_bssids():
    campaign = OpenProbeApCampaign(
        _Array([_Iface((6,))]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        encryption="BOTH",
    )
    assert campaign.is_dual
    endpoints = _endpoints_by_enc(campaign)
    assert set(endpoints) == {"OPEN", "WPA2"}
    assert endpoints["OPEN"].bssid != endpoints["WPA2"].bssid
    assert GENERIC_RSN_IE in endpoints["WPA2"].beacon
    assert GENERIC_RSN_IE not in endpoints["OPEN"].beacon
    # Single-mode surface still points at the first (OPEN) endpoint.
    assert campaign.stats is campaign.endpoints[0].stats
    assert campaign.bssid == campaign.endpoints[0].bssid


async def test_dual_dispatch_routes_by_bssid():
    campaign = OpenProbeApCampaign(
        _Array([_Iface((6,))]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        encryption="BOTH",
    )
    open_ep = _endpoints_by_enc(campaign)["OPEN"]
    wpa2_ep = _endpoints_by_enc(campaign)["WPA2"]
    client_text = "02:aa:bb:cc:dd:ee"

    # A directed probe reaches both APs; both answer and log the client.
    campaign.on_rx(_parse(probe_req(open_ep.bssid, OTHER, SSID)))
    await _flush()
    assert client_text in open_ep.stats.clients
    assert client_text in wpa2_ep.stats.clients

    # Auth addressed to the WPA2 BSSID only advances the WPA2 AP.
    campaign.on_rx(_parse(auth_req(wpa2_ep.bssid, OTHER)))
    campaign.on_rx(_parse(assoc_req(
        wpa2_ep.bssid, OTHER, SSID, GENERIC_RSN_IE, channel=6,
    )))
    await _flush()
    assert wpa2_ep.stats.clients[client_text].phase is OpenProbePhase.ASSOCIATED
    assert open_ep.stats.clients[client_text].phase is OpenProbePhase.PROBED
    assert len(campaign.array.injected_eapol) == 1

    campaign.on_rx(_parse(_m2(wpa2_ep.bssid, OTHER)))
    assert wpa2_ep.stats.m2 == 1
    assert open_ep.stats.m2 == 0
    assert campaign._result_for_phase() == "handshake"


async def test_dual_mode_uses_two_radios_when_available():
    radio_a = _Iface((6,))
    radio_b = _Iface((6,))
    array = _Array([radio_a, radio_b])
    campaign = OpenProbeApCampaign(
        array, Client(mac="02:11:22:33:44:55"), SSID, 6, encryption="BOTH",
    )

    task = asyncio.create_task(campaign._loop())
    await asyncio.sleep(0.02)
    campaign.stopped = True
    await task

    # One BSSID per radio, each beaconing on its own interface.
    assert campaign.endpoints[0].iface is radio_a
    assert campaign.endpoints[1].iface is radio_b
    assert any(frame[:2] == b"\x80\x00" for frame in radio_a.sent)
    assert any(frame[:2] == b"\x80\x00" for frame in radio_b.sent)
    assert len(array.fake_aps) == 2

    await campaign.teardown()
    assert array.own_macs == set()
    assert all(not ap.active for ap in array.fake_aps.values())


async def test_dual_mode_shares_one_radio_when_only_one_is_available():
    radio = _Iface((6,))
    array = _Array([radio])
    campaign = OpenProbeApCampaign(
        array, Client(mac="02:11:22:33:44:55"), SSID, 6, encryption="BOTH",
    )

    task = asyncio.create_task(campaign._loop())
    await asyncio.sleep(0.02)
    campaign.stopped = True
    await task

    # Both BSSIDs share the single spoofable radio.
    assert campaign.endpoints[0].iface is radio
    assert campaign.endpoints[1].iface is radio
    assert len(array.fake_aps) == 2
    beacons = [frame for frame in radio.sent if frame[:2] == b"\x80\x00"]
    assert len(beacons) >= 2  # both BSSIDs beacon on the shared radio


async def test_teardown_drains_pending_tx_tasks():
    iface = _Iface((6,))
    campaign = OpenProbeApCampaign(
        _Array([iface]),
        Client(mac="02:11:22:33:44:55"),
        SSID,
        6,
        bssid=bytes.fromhex("02deadbeef01"),
    )
    campaign.on_rx(_parse(probe_req(campaign.bssid, CLIENT, SSID)))
    # A response task is scheduled but not yet awaited.
    assert campaign._tx_tasks

    await campaign.teardown()

    assert campaign._tx_tasks == set()
    assert any(frame[:2] == b"\x50\x00" for frame in iface.sent)
