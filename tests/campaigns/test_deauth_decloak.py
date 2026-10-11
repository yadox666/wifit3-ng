"""Deauth-driven hidden SSID discovery campaign."""
import time
from types import SimpleNamespace

from wifit3.campaigns.deauth_decloak import DeauthDecloakCampaign
from wifit3.models import AccessPoint, Client
from wifit3.wlan.interface import DeauthResult
from wifit3.wlan.lease import Lease

_BSSID = "aa:bb:cc:dd:ee:01"


class _FakeRadio:
    def __init__(self):
        self.current_channel = 6
        self.calls: list[str] = []

    async def set_channel(self, ch, scan=False):
        self.current_channel = ch
        return True

    async def deauth_client(self, ap_bssid, client_bssid, rounds=10):
        self.calls.append(client_bssid)
        return DeauthResult(client_sent=rounds, client_acks=rounds,
                            ap_sent=rounds, ap_acks=rounds, measured=True)


class _FakeArray:
    def __init__(self, radio, ap, clients):
        self._radio = radio
        self.access_points = {_BSSID: ap}
        self.clients = clients
        self.forged_macs = set()
        self._wait_calls = 0

    def select_iface(self, channel):
        return self._radio

    def lease(self, channel=None, fake_mac=None, bssid=None, ack_tally=False, iface=None):
        return Lease(self, iface or self._radio, channel=channel, fake_mac=fake_mac,
                     bssid=bssid, ack_tally=ack_tally)

    async def wait_until(self, condition, timeout, poll=0.05):
        self._wait_calls += 1
        if self._wait_calls == 1:
            self.access_points[_BSSID].ssid = "RevealedNet"
        return bool(condition())


async def test_deauth_decloak_deauths_strongest_client_first_and_stops_on_ssid():
    ap = AccessPoint(bssid=_BSSID, ssid="<hidden>", channel=6, encryption="WPA2")
    now = time.time()
    weak = Client(mac="c1", bssid=_BSSID, signal_by_card={"a": -70}, last_seen=now)
    strong = Client(mac="c2", bssid=_BSSID, signal_by_card={"a": -40}, last_seen=now)
    radio = _FakeRadio()
    array = _FakeArray(radio, ap, {"c1": weak, "c2": strong})
    camp = DeauthDecloakCampaign(array, ap)

    await camp._loop()

    assert radio.calls == ["c2"]
    assert camp.revealed_ssid == "RevealedNet"


def test_visible_and_allowed_require_hidden_no_pmf_and_clients():
    ap = AccessPoint(bssid=_BSSID, ssid=None, pmf_required=False)
    assert DeauthDecloakCampaign.visible(ap) is True
    assert DeauthDecloakCampaign.allowed(ap, live_client_count=1) is True
    assert DeauthDecloakCampaign.allowed(ap, live_client_count=0) is False
    assert DeauthDecloakCampaign.ineligible_reason(ap, live_client_count=0) == (
        "No live associated clients"
    )
    ap.pmf_required = True
    assert DeauthDecloakCampaign.visible(ap) is False
    ap.pmf_required = False
    ap.ssid = "Known"
    assert DeauthDecloakCampaign.visible(ap) is False
