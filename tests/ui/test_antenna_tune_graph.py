"""AntennaTune column-wave renderers."""
from wifit3.ui.antenna_tune_graph import render_strength_wave, render_tx_ack_wave, window


def test_window_pads_and_keeps_newest_right():
    assert window([1, 2, 3], 5) == [0.0, 0.0, 1, 2, 3]
    assert window([1, 2, 3, 4, 5], 3) == [3, 4, 5]


def test_strength_wave_is_tall_and_multicolor():
    wave = render_strength_wave([0.5, 4.0, 9.0], rows=6, peak=10.0, colors=[0.1, 0.5, 1.0])
    lines = wave.plain.splitlines()
    assert len(lines) == 6
    styles = {str(style) for _start, _end, style in wave.spans if style}
    assert len(styles) >= 2


def test_tx_ack_wave_pairs_sent_and_acked():
    wave = render_tx_ack_wave([1, 1, 0], [1, 0, 0], rows=4, peak=1.0)
    lines = wave.plain.splitlines()
    assert len(lines) == 4
    styles = " ".join(str(style) for _start, _end, style in wave.spans if style)
    assert "80,170,255" in styles
    assert "40,210,90" in styles
