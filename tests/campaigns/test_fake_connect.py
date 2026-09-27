import asyncio
from unittest.mock import AsyncMock

from wifit3.campaigns.fake_connect import FakeConnectCampaign
from wifit3.dot11.connectivity import HttpProbeResponse
from wifit3.dot11.dhcp import DhcpOffer
from wifit3.models import AccessPoint


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
