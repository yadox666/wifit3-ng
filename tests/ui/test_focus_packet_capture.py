from types import SimpleNamespace
from unittest.mock import Mock

from wifit3.persist.pcap import PcapWriter
from wifit3.ui.screens.focus_v2 import FocusViewV2


def test_focus_packet_capture_keeps_only_target_bssid(tmp_path):
    screen = FocusViewV2()
    writer = PcapWriter(tmp_path / "focused.pcap")
    screen._packet_capture = writer
    screen._packet_capture_bssid = "aa:bb:cc:dd:ee:ff"
    screen._network_analyzer = Mock()

    screen._capture_packet(SimpleNamespace(
        bssid="11:22:33:44:55:66", raw=b"other",
    ))
    screen._capture_packet(SimpleNamespace(
        bssid="AA:BB:CC:DD:EE:FF", raw=b"target",
    ))
    writer.close()

    assert writer.count == 1
    screen._network_analyzer.observe.assert_not_called()
    assert any(
        binding.key == "x" and binding.description == "Capture PCAP"
        for binding in FocusViewV2.BINDINGS
    )


def test_focus_network_analysis_runs_without_packet_capture():
    screen = FocusViewV2()
    screen._network_bssid = "aa:bb:cc:dd:ee:ff"
    screen._network_analyzer = Mock()
    packet = SimpleNamespace(bssid="AA:BB:CC:DD:EE:FF")

    screen._observe_network_packet(packet)

    screen._network_analyzer.observe.assert_called_once_with(packet)
