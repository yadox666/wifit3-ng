from types import SimpleNamespace
from unittest.mock import Mock

from wifit3.persist.pcap import PcapWriter
from wifit3.ui.screens.client_focus import ClientFocusView


def test_client_focus_packet_capture_keeps_only_target_client(tmp_path):
    screen = ClientFocusView()
    writer = PcapWriter(tmp_path / "client.pcap")
    screen._writer = writer
    screen._client_mac = "aa:bb:cc:dd:ee:ff"
    screen._network_bssid = "00:11:22:33:44:55"
    screen._network_analyzer = Mock()
    screen._network_analyzer.observe.return_value = {"aa:bb:cc:dd:ee:ff"}

    screen._capture_packet(SimpleNamespace(
        client_mac="11:22:33:44:55:66", raw=b"other",
    ))
    screen._capture_packet(SimpleNamespace(
        client_mac="AA:BB:CC:DD:EE:FF", raw=b"target",
    ))
    screen._capture_packet(SimpleNamespace(
        client_mac=None,
        bssid="00:11:22:33:44:55",
        raw=b"broadcast-dhcp-for-target",
    ))
    writer.close()

    assert writer.count == 2
    screen._network_analyzer.observe.assert_called_once()
    assert any(
        binding.key == "x" and binding.description == "Capture PCAP"
        for binding in ClientFocusView.BINDINGS
    )
