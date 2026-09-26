from types import SimpleNamespace

from wifit3.persist.pcap import PcapWriter
from wifit3.ui.screens.client_focus import ClientFocusView


def test_client_focus_packet_capture_keeps_only_target_client(tmp_path):
    screen = ClientFocusView()
    writer = PcapWriter(tmp_path / "client.pcap")
    screen._writer = writer
    screen._client_mac = "aa:bb:cc:dd:ee:ff"

    screen._capture_packet(SimpleNamespace(
        client_mac="11:22:33:44:55:66", raw=b"other",
    ))
    screen._capture_packet(SimpleNamespace(
        client_mac="AA:BB:CC:DD:EE:FF", raw=b"target",
    ))
    writer.close()

    assert writer.count == 1
    assert any(
        binding.key == "x" and binding.description == "Capture PCAP"
        for binding in ClientFocusView.BINDINGS
    )
