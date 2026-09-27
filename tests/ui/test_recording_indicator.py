from types import SimpleNamespace

from wifit3.ui.recording_indicator import pcap_progress, recording_indicator


def test_recording_indicator_blinks_led_and_keeps_label_visible():
    bright = recording_indicator("PCAP RECORDING", True, now=0.0)
    dim = recording_indicator("PCAP RECORDING", True, now=0.5)

    assert bright.plain == "● PCAP RECORDING"
    assert dim.plain == bright.plain
    assert "red" in str(bright.style)
    assert "#500000" in str(dim.style)
    assert recording_indicator("PCAP RECORDING", False).plain == ""


def test_recording_indicator_shows_all_pcap_parts_and_total_megabytes():
    writer = SimpleNamespace(part_count=10, total_bytes=814 * 1024 * 1024)

    progress = pcap_progress(writer)
    indicator = recording_indicator(
        "PCAP RECORDING", True, now=0.0, detail=progress,
    )

    assert progress == "10 files: 814 MB"
    assert indicator.plain == "● PCAP RECORDING\n10 files: 814 MB"
