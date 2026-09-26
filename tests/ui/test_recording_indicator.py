from wifit3.ui.recording_indicator import recording_indicator


def test_recording_indicator_blinks_led_and_keeps_label_visible():
    bright = recording_indicator("PCAP RECORDING", True, now=0.0)
    dim = recording_indicator("PCAP RECORDING", True, now=0.5)

    assert bright.plain == "● PCAP RECORDING"
    assert dim.plain == bright.plain
    assert "red" in str(bright.style)
    assert "#500000" in str(dim.style)
    assert recording_indicator("PCAP RECORDING", False).plain == ""
