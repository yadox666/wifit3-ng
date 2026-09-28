import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from wifit3.campaigns.fake_connect import FakeConnectCampaign
from wifit3.dot11.connectivity import HttpProbeResponse
from wifit3.dot11.dhcp import DhcpOffer
from wifit3.dot11.station_crypto import CcmpStationCodec
from wifit3.models import AccessPoint
from wifit3.models.access_point import CaptureType, PersistedCapture


class _VaultStub:
    def __init__(self, *, psk=None, captures=()):
        self._psk = psk
        self._captures = captures

    def known_psk(self, _ap):
        return self._psk

    def persisted(self, _bssid):
        return self._captures


class _Context:
    def __init__(self, value):
        self.value = value
        self.mac = None

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *_args):
        return None


class _Arm(_Context):
    def __init__(self, mac):
        super().__init__(self)
        self.mac = mac


class _Iface:
    def __init__(self):
        self.sent = []

    async def send_no_wait(self, frame):
        self.sent.append(frame)
        return True


class _Array:
    def __init__(self, aps=()):
        self.iface = _Iface()
        self.access_points = {ap.bssid: ap for ap in aps}
        self.fake_clients = {}

    def select_iface(self, _channel):
        return self.iface

    def lease(self, **kwargs):
        if "fake_mac" in kwargs:
            mac = ":".join(f"{byte:02x}" for byte in kwargs["fake_mac"])
            return _Arm(mac)
        return _Context(self.iface)

    def register_fake_client(self, mac, bssid):
        key = ":".join(f"{byte:02x}" for byte in mac)
        self.fake_clients[key] = bssid

    def unregister_fake_client(self, mac):
        key = ":".join(f"{byte:02x}" for byte in mac)
        self.fake_clients.pop(key, None)


async def test_fake_connect_associates_until_stopped_then_sends_leave(monkeypatch):
    instances = []

    class _Association:
        def __init__(self, *_args, **_kwargs):
            self.associated = False
            self.fail_reason = None
            self.ready = asyncio.Event()
            self.privacy = _kwargs.get("privacy")
            instances.append(self)

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=3):
            self.associated = True
            self.ready.set()
            return True

    monkeypatch.setattr("wifit3.campaigns.fake_connect.Association", _Association)
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Cafe", channel=6, encryption="OPEN",
    )
    array = _Array([ap])
    campaign = FakeConnectCampaign(
        array, ap, source_mac=bytes.fromhex("021122334455"),
    )
    campaign._discover_dhcp = AsyncMock(return_value=None)

    task = asyncio.create_task(campaign._loop())
    while not instances:
        await asyncio.sleep(0)
    await instances[0].ready.wait()
    await asyncio.sleep(0)
    assert campaign.associated is True
    assert instances[0].privacy is False
    assert campaign.client_mac in array.fake_clients

    campaign.stopped = True
    await task

    assert campaign.associated is False
    assert campaign.client_mac not in array.fake_clients
    assert len(array.iface.sent) == 1


def test_fake_connect_applies_to_open_and_wep_aps_with_known_ssid():
    open_ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Cafe", encryption="OPEN",
    )
    hidden = AccessPoint(
        bssid="aa:bb:cc:dd:ee:00", ssid=None, encryption="OPEN",
    )
    secure = AccessPoint(
        bssid="aa:bb:cc:dd:ee:11", ssid="Secure", encryption="WPA2",
        akm_suites=[2],
    )
    wep = AccessPoint(
        bssid="aa:bb:cc:dd:ee:22", ssid="Legacy", encryption="WEP",
    )

    assert FakeConnectCampaign.visible(open_ap) is True
    assert FakeConnectCampaign.ineligible_reason(open_ap) is None
    assert FakeConnectCampaign.visible(hidden) is True
    assert "hidden SSID" in FakeConnectCampaign.ineligible_reason(hidden)
    assert FakeConnectCampaign.visible(wep) is True
    assert FakeConnectCampaign.visible(secure) is False

    psk_ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:12", ssid="Secure", encryption="WPA2",
        akm_suites=[2], wps_pbc_psk="hunter2",
    )
    assert FakeConnectCampaign.visible(psk_ap) is True
    vault = _VaultStub(psk="vaultpsk")
    assert FakeConnectCampaign.visible(secure, vault) is True
    assert FakeConnectCampaign.ineligible_reason(secure, vault) is None
    placeholder_vault = _VaultStub(psk="PLACEHOLDER")
    assert FakeConnectCampaign.visible(secure, placeholder_vault) is False
    assert "no captured WPA2-PSK" in FakeConnectCampaign.ineligible_reason(
        secure, placeholder_vault,
    )


def test_fake_connect_can_try_the_strongest_named_sibling_ssid():
    hidden = AccessPoint(
        bssid="02:00:00:00:00:01", ssid=None, encryption="OPEN",
        siblings=["02:00:00:00:00:02", "02:00:00:00:00:03"],
    )
    weaker = AccessPoint(
        bssid="02:00:00:00:00:02", ssid="Other", beacons=10,
    )
    stronger = AccessPoint(
        bssid="02:00:00:00:00:03", ssid="Previously Seen", beacons=50,
    )
    array = _Array([hidden, weaker, stronger])

    campaign = FakeConnectCampaign(array, hidden)

    assert FakeConnectCampaign.ineligible_reason(hidden) is None
    assert campaign.association_ssid == "Previously Seen"
    assert campaign.ssid_is_guess is True


def test_fake_connect_reuses_one_client_mac_per_ap_during_the_session():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Cafe", channel=6, encryption="OPEN",
    )
    array = _Array([ap])

    first = FakeConnectCampaign(array, ap)
    second = FakeConnectCampaign(array, ap)

    assert second.source_mac == first.source_mac


async def test_connectivity_probe_classifies_expected_http_204_as_internet():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Cafe", channel=6, encryption="OPEN",
    )
    campaign = FakeConnectCampaign(_Array([ap]), ap)
    campaign._resolve_arp = AsyncMock(return_value=bytes.fromhex("102030405060"))
    campaign._resolve_dns = AsyncMock(return_value=("142.250.74.131",))
    campaign._http_probe = AsyncMock(
        return_value=(HttpProbeResponse(204, None), True),
    )
    lease = DhcpOffer(
        offered_ip="192.168.1.20",
        server="192.168.1.1",
        subnet_mask="255.255.255.0",
        routers=("192.168.1.1",),
        dns_servers=("192.168.1.1",),
        domain=None,
        portal=None,
        lease_seconds=3600,
    )

    result = await campaign._test_lease_connectivity(
        campaign.array, object(), bytes.fromhex("aabbccddeeff"), lease,
    )

    assert result.status == "internet_confirmed"
    assert result.gateway_reachable is True
    assert result.dns_reachable is True
    assert result.tcp_reachable is True


def test_resolve_credential_reads_wep_key_from_vault():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:22", ssid="Legacy", encryption="WEP",
    )
    cap = PersistedCapture(
        type=CaptureType.WEP, timestamp=1, path="/tmp/x", bssid=ap.bssid,
        value="0011223344",
    )
    vault = _VaultStub(captures=[cap])
    assert FakeConnectCampaign.resolve_credential(ap, vault) == bytes.fromhex(
        "0011223344",
    )


async def test_wep_fake_connect_stops_after_association_without_dhcp(monkeypatch):
    instances = []

    class _Association:
        def __init__(self, *_args, **kwargs):
            self.associated = False
            self.fail_reason = None
            self.privacy = kwargs.get("privacy")
            instances.append(self)

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=3):
            self.associated = True
            return True

    monkeypatch.setattr("wifit3.campaigns.fake_connect.Association", _Association)
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Legacy", channel=6, encryption="WEP",
    )
    array = _Array([ap])
    campaign = FakeConnectCampaign(array, ap)
    campaign._discover_dhcp = AsyncMock()

    task = asyncio.create_task(campaign._loop())
    while not campaign.associated:
        await asyncio.sleep(0)

    assert instances[0].privacy is True
    assert campaign.client_mac in array.fake_clients
    campaign._discover_dhcp.assert_not_awaited()

    campaign.stopped = True
    await task
    assert campaign.client_mac not in array.fake_clients


async def test_wep_fake_connect_with_key_runs_dhcp(monkeypatch):
    instances = []

    class _Association:
        def __init__(self, *_args, **kwargs):
            self.associated = False
            self.fail_reason = None
            self.privacy = kwargs.get("privacy")
            instances.append(self)

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=3):
            self.associated = True
            return True

    monkeypatch.setattr("wifit3.campaigns.fake_connect.Association", _Association)
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Legacy", channel=6, encryption="WEP",
    )
    array = _Array([ap])
    campaign = FakeConnectCampaign(
        array, ap, credential=bytes.fromhex("0011223344"),
    )
    campaign._establish_data_security = AsyncMock(return_value=True)
    campaign._discover_dhcp = AsyncMock(return_value=None)

    task = asyncio.create_task(campaign._loop())
    while not campaign.associated:
        await asyncio.sleep(0)

    assert campaign.association_only is False
    campaign._establish_data_security.assert_awaited()
    campaign._discover_dhcp.assert_awaited()

    campaign.stopped = True
    await task


class _AckIface:
    """Iface stub that link-ACKs sends and lets the 'AP' emit RX frames.

    ``on_send`` is called with the iface only (data-path probe); ``on_frame`` is
    called with (iface, frame) for every transmitted frame (ARP sweep)."""

    def __init__(self, on_send=None, on_frame=None):
        self.sent = []
        self.callbacks = []
        self._on_send = on_send
        self.on_frame = on_frame

    def register_rx_callback(self, cb):
        self.callbacks.append(cb)

    def unregister_rx_callback(self, cb):
        if cb in self.callbacks:
            self.callbacks.remove(cb)

    async def enable_rx_acks(self):
        pass

    async def disable_rx_acks(self):
        pass

    async def send_until_ack(self, frame, max_retries=0):
        self.sent.append(frame)
        if self._on_send is not None:
            self._on_send(self)
        if self.on_frame is not None:
            self.on_frame(self, frame)
        return True

    async def send_no_wait(self, frame):
        self.sent.append(frame)
        if self.on_frame is not None:
            self.on_frame(self, frame)
        return True

    def emit(self, raw):
        packet = SimpleNamespace(raw=raw, rssi=-40)
        for cb in list(self.callbacks):
            cb(packet)


def _arp_reply_frame(bssid, sender_ip, sender_mac, target_mac, target_ip):
    """A FromDS 802.11 data frame carrying an ARP reply to ``target_mac``."""
    import ipaddress

    from wifit3.dot11.connectivity import LLC_ARP

    body = (
        b"\x00\x01\x08\x00\x06\x04\x00\x02"
        + sender_mac
        + ipaddress.IPv4Address(sender_ip).packed
        + target_mac
        + ipaddress.IPv4Address(target_ip).packed
    )
    header = bytes((0x08, 0x02)) + b"\x00\x00" + target_mac + bssid + bssid + b"\x00\x00"
    return header + LLC_ARP + body


def _downlink_data_frame(bssid: bytes, client: bytes, body: bytes) -> bytes:
    """A FromDS data frame (Addr2 == BSSID) carrying an opaque body."""
    return (
        bytes((0x08, 0x02)) + b"\x00\x00" + client + bssid + bssid + b"\x00\x00" + body
    )


async def test_encrypted_datapath_verifies_write_and_read_round_trip():
    ap = AccessPoint(
        bssid="00:11:22:33:44:55", ssid="Net", channel=6, encryption="WPA2",
        akm_suites=[2],
    )
    campaign = FakeConnectCampaign(_Array([ap]), ap, credential="pw")
    campaign.security = "wpa2"
    temporal_key = bytes(range(16))
    campaign._codec = CcmpStationCodec(temporal_key)

    bssid = bytes.fromhex("001122334455")
    peer = CcmpStationCodec(temporal_key)   # the AP side, sharing the pairwise key

    def on_send(iface):
        downlink = _downlink_data_frame(bssid, campaign.source_mac, b"\x11" * 40)
        iface.emit(peer.protect(downlink))

    iface = _AckIface(on_send)

    assert await campaign._verify_encrypted_datapath(iface, bssid) is True
    assert campaign.datapath_verified is True
    # We transmitted a Protected (WEP/CCMP bit set) data frame.
    assert any(frame[1] & 0x40 for frame in iface.sent)


def test_sweep_targets_scopes_large_subnets_to_a_24_and_excludes_self():
    from wifit3.campaigns.fake_connect import _sweep_targets

    hosts = _sweep_targets("192.168.0.79", "255.255.255.0")
    assert "192.168.0.79" not in hosts       # our own address excluded
    assert "192.168.0.1" in hosts and "192.168.0.254" in hosts
    assert len(hosts) == 253                  # 254 usable minus ourselves

    # A /16 lease is scoped down to the /24 around us and capped.
    scoped = _sweep_targets("10.0.5.10", "255.255.0.0")
    assert all(ip.startswith("10.0.5.") for ip in scoped)
    assert len(scoped) <= 256


async def test_arp_sweep_collects_responders(monkeypatch):
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="Cafe", channel=6, encryption="OPEN",
    )
    campaign = FakeConnectCampaign(
        _Array([ap]), ap, source_mac=bytes.fromhex("020000000001"),
    )
    monkeypatch.setattr(
        "wifit3.campaigns.fake_connect.ARP_SWEEP_SETTLE_SECONDS", 0.05,
    )
    monkeypatch.setattr(
        "wifit3.campaigns.fake_connect.ARP_SWEEP_PACING_SECONDS", 0.0,
    )

    bssid = bytes.fromhex("aabbccddeeff")
    client_ip = "192.168.0.79"
    responder_ip = "192.168.0.5"
    responder_mac = bytes.fromhex("aabbcc001122")

    def on_frame(frame_iface, _frame):
        frame_iface.emit(
            _arp_reply_frame(
                bssid=bssid,
                sender_ip=responder_ip,
                sender_mac=responder_mac,
                target_mac=campaign.source_mac,
                target_ip=client_ip,
            )
        )

    iface = _AckIface(on_frame=on_frame)
    lease = DhcpOffer(
        offered_ip=client_ip, server="192.168.0.1", subnet_mask="255.255.255.0",
        routers=("192.168.0.1",), dns_servers=("192.168.0.1",), domain=None,
        portal=None, lease_seconds=3600,
    )

    await campaign._sweep_arp_neighbors(iface, bssid, lease)

    assert (responder_ip, "aa:bb:cc:00:11:22") in campaign.arp_neighbors


async def test_arp_sweep_decodes_encrypted_replies(monkeypatch):
    ap = AccessPoint(
        bssid="00:11:22:33:44:55", ssid="Net", channel=6, encryption="WPA2",
        akm_suites=[2],
    )
    campaign = FakeConnectCampaign(
        _Array([ap]), ap, credential="pw", source_mac=bytes.fromhex("020000000009"),
    )
    campaign.security = "wpa2"
    temporal_key = bytes(range(16))
    campaign._codec = CcmpStationCodec(temporal_key)
    peer = CcmpStationCodec(temporal_key)   # AP encrypts the reply with the same TK

    monkeypatch.setattr(
        "wifit3.campaigns.fake_connect.ARP_SWEEP_SETTLE_SECONDS", 0.05,
    )
    monkeypatch.setattr(
        "wifit3.campaigns.fake_connect.ARP_SWEEP_PACING_SECONDS", 0.0,
    )

    bssid = bytes.fromhex("001122334455")
    client_ip = "192.168.0.140"
    responder_ip = "192.168.0.1"
    responder_mac = bytes.fromhex("3c0102030405")
    emitted = {"done": False}

    def on_frame(frame_iface, _frame):
        if emitted["done"]:
            return
        emitted["done"] = True   # one encrypted reply is enough
        clear = _arp_reply_frame(
            bssid=bssid,
            sender_ip=responder_ip,
            sender_mac=responder_mac,
            target_mac=campaign.source_mac,
            target_ip=client_ip,
        )
        frame_iface.emit(peer.protect(clear))

    iface = _AckIface(on_frame=on_frame)
    lease = DhcpOffer(
        offered_ip=client_ip, server="192.168.0.1", subnet_mask="255.255.255.0",
        routers=("192.168.0.1",), dns_servers=("192.168.0.1",), domain=None,
        portal=None, lease_seconds=3600,
    )

    await campaign._sweep_arp_neighbors(iface, bssid, lease)

    assert (responder_ip, "3c:01:02:03:04:05") in campaign.arp_neighbors


async def test_encrypted_datapath_rejects_wrong_key_downlink(monkeypatch):
    ap = AccessPoint(
        bssid="00:11:22:33:44:55", ssid="Net", channel=6, encryption="WPA2",
        akm_suites=[2],
    )
    campaign = FakeConnectCampaign(_Array([ap]), ap, credential="pw")
    campaign.security = "wpa2"
    campaign._codec = CcmpStationCodec(bytes(range(16)))

    bssid = bytes.fromhex("001122334455")
    wrong_peer = CcmpStationCodec(bytes(range(16, 32)))   # different key

    def on_send(iface):
        downlink = _downlink_data_frame(bssid, campaign.source_mac, b"\x11" * 40)
        iface.emit(wrong_peer.protect(downlink))

    monkeypatch.setattr(
        "wifit3.campaigns.fake_connect.DATAPATH_VERIFY_SECONDS", 0.2,
    )
    result = await campaign._verify_encrypted_datapath(_AckIface(on_send), bssid)

    assert result is False
    assert campaign.datapath_verified is False
