"""A MAC this app armed must not reappear as a client after the radio releases it."""
import pytest

from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.mac import mac_to_str
from wifit3.models import AccessPoint
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.wlan.interface import WlanInterface
from wifit3.wlan.sink import WlanSink

from tests.frames import pkt

BSSID = "aa:bb:cc:dd:ee:ff"
OURS = "02:10:20:30:40:50"
CARD = "wlan0"


def test_retired_mac_is_not_recorded_as_a_client(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    store.remember(
        AccessPoint(bssid=BSSID, ssid="Lab", channel=6, encryption="WPA2"),
        force=True,
    )
    sink = WlanSink(ap_history=store)
    sink.update(pkt({
        "type": "beacon", "bssid": BSSID, "source": BSSID, "dest": "ff:ff:ff:ff:ff:ff",
        "rssi": -40, "ssid": "Lab", "channel": 6, "encryption": "WPA2",
    }), CARD)
    sink.register_own_mac(OURS)
    sink.unregister_own_mac(OURS)

    sink.update(pkt({
        "type": "assoc_req", "bssid": BSSID, "source": OURS, "dest": BSSID, "rssi": -40,
    }), CARD)
    sink.update(pkt({
        "type": "assoc_resp", "bssid": BSSID, "source": BSSID, "dest": OURS, "rssi": -40,
    }), CARD)

    assert OURS not in sink.clients
    assert store.is_own_station(OURS)
    assert store.clients_for_ap(BSSID) == []
    store.close()


class _Radio:
    FAKE_MAC = FakeMacSupport.SPOOFABLE

    def __init__(self):
        self.events: list[str] = []

    def register_rx_callback(self, _callback) -> None:
        return None

    def register_disconnect_callback(self, _callback) -> None:
        return None

    async def enter_active_monitor(self, mac, _bssid=None):
        self.events.append(f"radio:{mac_to_str(mac)}")
        return mac


class _Registry:
    def __init__(self, radio: _Radio):
        self.radio = radio
        self.macs: list[str] = []

    def register_own_mac(self, mac) -> None:
        text = mac_to_str(mac) if isinstance(mac, (bytes, bytearray)) else str(mac)
        self.macs.append(text)
        self.radio.events.append(f"registered:{text}")


@pytest.mark.asyncio
async def test_fake_mac_is_registered_before_the_radio_acks():
    radio = _Radio()
    iface = WlanInterface(radio, "wlan0", "test")
    registry = _Registry(radio)
    iface.bind_own_mac_registry(registry)

    armed = await iface.set_fake_mac(bytes.fromhex("021020304050"), BSSID)

    assert armed == OURS
    assert radio.events[0] == f"registered:{OURS}"
    assert radio.events[1] == f"radio:{OURS}"
