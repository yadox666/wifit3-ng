from types import SimpleNamespace

from wifit3.persist.pcap import PcapWriter
from wifit3.ui.screens.focus_v2 import FocusViewV2


def test_focus_packet_capture_keeps_only_target_bssid(tmp_path):
    screen = FocusViewV2()
    writer = PcapWriter(tmp_path / "focused.pcap")
    screen._packet_capture = writer
    screen._packet_capture_bssid = "aa:bb:cc:dd:ee:ff"

    screen._capture_packet(SimpleNamespace(
        bssid="11:22:33:44:55:66", raw=b"other",
    ))
    screen._capture_packet(SimpleNamespace(
        bssid="AA:BB:CC:DD:EE:FF", raw=b"target",
    ))
    writer.close()

    assert writer.count == 1
    assert any(
        binding.key == "x" and binding.description == "Capture PCAP"
        for binding in FocusViewV2.BINDINGS
    )
