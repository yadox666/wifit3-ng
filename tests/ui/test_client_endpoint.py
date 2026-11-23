from types import SimpleNamespace

import pytest

from wifit3.models import AccessPoint, Client
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.focus_v2.client_endpoint import ClientEndpoint
from wifit3.ui.screens.focus_v2.client_focus_screen import ClientFocusView


def test_client_power_meter_uses_rssi_not_zero_packet_rate():
    endpoint = ClientEndpoint(mac="3a:35:38:2d:04:38", power_dbm=-56, signal=0.0)
    line = endpoint._power_line()
    plain = line.plain
    assert "╳" not in plain and "✕" not in plain
    assert "-56 dBm" in plain


def test_client_power_meter_warming_when_no_rssi():
    endpoint = ClientEndpoint(power_dbm=-100)
    assert endpoint._meter_rate() is None


@pytest.mark.asyncio
async def test_client_focus_view_mounts_and_refreshes_without_crashing():
    ap = AccessPoint(bssid="11:22:33:44:55:66", ssid="TestAP", channel=6)
    client = Client(mac="aa:bb:cc:dd:ee:ff", bssid=ap.bssid)

    class FakeArray:
        def __init__(self) -> None:
            self.access_points = {ap.bssid: ap}
            self.clients = {client.mac: client}
            self.forged_macs = set()
            self.supported_channels = [1, 6, 11]
            self.members = []
            self.gps_manager = None
            self.packet_stats = SimpleNamespace(snapshot=lambda _b: {"beacon": 10, "data": 3})
            self.pbc_candidates = {}

        def get_access_points(self, include_eviltwin: bool = True):
            return list(self.access_points.values())

        def get_clients(self):
            return list(self.clients.values())

        def clients_for(self, _bssid):
            return [client]

        def select_iface(self, _ch):
            return None

        def active_campaigns(self):
            return []

        async def set_channel_spec(self, *_a, **_k):
            return True

        async def start_hopping(self, *_a, **_k):
            pass

        async def stop_hopping(self):
            pass

        async def tune_channel(self, *_a, **_k):
            pass

        def drain_threats(self):
            return []

    app = WifiteApp()
    async with app.run_test() as pilot:
        app.array = FakeArray()
        app.target_ap = ap
        app.target_client = client
        app.push_screen("client-focus")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ClientFocusView)
        endpoint = app.screen.query_one("#client-endpoint", ClientEndpoint)
        endpoint.update(mac=client.mac, label="Test", power_dbm=-50, signal=None)

