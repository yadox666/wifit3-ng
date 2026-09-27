"""libpcap writer: saves LINKTYPE_IEEE802_11 frames verbatim. Callers deliver
FCS-less MPDU bodies (every chip driver strips at RX ingress), so the writer
no longer second-guesses the frame tail."""

from wifit3.persist.pcap import PcapWriter, write_pcap


def _first_packet(path) -> bytes:
    """Extract the first packet's payload from a libpcap file (24-byte global
    header + 16-byte record header, all little-endian)."""
    raw = path.read_bytes()
    caplen = int.from_bytes(raw[24 + 8: 24 + 12], "little")
    return raw[40: 40 + caplen]


def _beacon_body() -> bytes:
    # Minimal beacon-ish MPDU: 24-byte hdr + 12 fixed params + SSID IE.
    return (
        b"\x80\x00" + b"\x00" * 22          # FC + dur + addr1/2/3 + seq (24 B)
        + b"\x00" * 12                       # timestamp/interval/caps
        + b"\x00\x04test"                    # SSID IE: tag 0, len 4
    )


def _record_header(path, index: int) -> tuple[int, int, int]:
    """(ts_sec, ts_usec, caplen) of the Nth packet record (little-endian).
    24-byte global header, then 16-byte record headers + payloads."""
    raw = path.read_bytes()
    off = 24
    for _ in range(index):
        caplen = int.from_bytes(raw[off + 8: off + 12], "little")
        off += 16 + caplen
    sec = int.from_bytes(raw[off: off + 4], "little")
    usec = int.from_bytes(raw[off + 4: off + 8], "little")
    caplen = int.from_bytes(raw[off + 8: off + 12], "little")
    return sec, usec, caplen


def test_write_pcap_writes_frame_verbatim(tmp_path):
    body = _beacon_body()
    path = tmp_path / "a.pcap"
    assert write_pcap(path, [(body, 0.0)]) == 1
    assert _first_packet(path) == body


def test_write_pcap_preserves_per_frame_timestamps(tmp_path):
    # Each frame keeps its own capture time (epoch seconds, µs resolution),
    # required so a round-tripped pcap re-extracts correctly in hcxpcapngtool.
    path = tmp_path / "b.pcap"
    recs = [(_beacon_body(), 1000.5), (_beacon_body(), 1002.25)]
    assert write_pcap(path, recs) == 2
    assert _record_header(path, 0)[:2] == (1000, 500000)
    assert _record_header(path, 1)[:2] == (1002, 250000)


def test_streaming_pcap_writer_appends_and_closes(tmp_path):
    path = tmp_path / "stream.pcap"
    writer = PcapWriter(path)
    assert writer.write(_beacon_body(), 1000.5)
    assert writer.write(b"", 1001.0) is False
    writer.close()

    assert writer.count == 1
    assert _first_packet(path) == _beacon_body()
    assert writer.write(_beacon_body(), 1002.0) is False


def test_streaming_pcap_writer_rotates_and_limits_parts(tmp_path):
    path = tmp_path / "Net_aa-bb-cc-dd-ee-ff_1700000000_packet_capture.pcap"
    writer = PcapWriter(path, max_bytes=50, max_parts=2)
    assert writer.write(b"first")
    assert writer.write(b"second")
    assert writer.part_count == 2
    assert writer.total_bytes == 91
    assert writer.write(b"third") is False
    writer.close()

    assert writer.count == 2
    assert writer.dropped == 1
    assert writer.total_bytes == 91
    assert [item.name for item in writer.paths] == [
        "Net_aa-bb-cc-dd-ee-ff_1700000000_packet_capture.pcap",
        "Net_aa-bb-cc-dd-ee-ff_1700000001_packet_capture.pcap",
    ]


def test_streaming_pcap_writer_rotates_without_part_limit(tmp_path):
    writer = PcapWriter(tmp_path / "capture.pcap", max_bytes=50, max_parts=0)
    assert writer.write(b"first")
    assert writer.write(b"second")
    assert writer.write(b"third")
    writer.close()

    assert writer.part_count == 3
    assert writer.count == 3
    assert writer.dropped == 0
