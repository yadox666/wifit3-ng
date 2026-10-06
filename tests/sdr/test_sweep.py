import struct

import numpy as np

from wifit3.sdr.sweep import (
    HackRfSweep,
    _FFT_SIZE,
    _SAMPLE_RATE_HZ,
    _SET_LNA_GAIN,
    _SET_VGA_GAIN,
)


def _sweep() -> HackRfSweep:
    return HackRfSweep(lambda _points: None, lambda _message: None)


def test_direct_sweep_centers_cover_range_without_rf_gaps():
    sweep = _sweep()
    sweep._start_mhz = 2400
    sweep._stop_mhz = 2500

    assert sweep._centers() == [2408, 2424, 2440, 2456, 2472, 2488, 2492]


def test_in_process_fft_maps_tone_to_expected_frequency_bin():
    sweep = _sweep()
    sweep._start_mhz = 2400
    sweep._stop_mhz = 2420
    sample_indexes = np.arange(_FFT_SIZE)
    tone = np.exp(2j * np.pi * 2_000_000 * sample_indexes / _SAMPLE_RATE_HZ)

    points = sweep._power_bins(tone, 2_410_000_000)
    strongest = max(points, key=lambda point: point.power_dbfs)

    assert strongest.frequency_hz == 2_412_500_000


def test_in_process_fft_removes_hackrf_dc_center_spur():
    sweep = _sweep()
    sweep._start_mhz = 2400
    sweep._stop_mhz = 2420

    points = sweep._power_bins(
        np.ones(_FFT_SIZE, dtype=np.complex64),
        2_410_000_000,
    )

    assert max(point.power_dbfs for point in points) <= -200


def test_capture_tile_retunes_receiver_with_little_endian_frequency():
    calls = []
    sweep = _sweep()
    sweep._usb_device = object()
    sweep._read_iq = lambda: np.zeros(_FFT_SIZE, dtype=np.complex64)
    sweep._power_bins = lambda _samples, _center_hz: []
    sweep._control_out = lambda request, **kwargs: calls.append((request, kwargs))
    sweep._applied_gains = (16, 20)

    sweep._capture_tile(2412.5)

    assert [request for request, _kwargs in calls] == [16]
    assert calls[0][1]["data"] == struct.pack("<II", 2412, 500_000)


def test_gain_changes_are_applied_once_at_the_next_capture_boundary():
    calls = []
    sweep = _sweep()
    sweep._usb_device = object()
    sweep._applied_gains = (16, 20)
    sweep._set_gain = lambda request, value: calls.append((request, value))

    sweep.set_gains(32, 40)
    sweep._apply_gains()
    sweep._apply_gains()

    assert calls == [(_SET_LNA_GAIN, 32), (_SET_VGA_GAIN, 40)]


def test_iq_reader_reports_near_rail_samples_as_clipping():
    raw = np.zeros(4096, dtype=np.int8)
    raw[:40] = 127

    class FakeUsbDevice:
        def read(self, *_args, **_kwargs):
            return raw.tobytes()

    sweep = _sweep()
    sweep._usb_device = FakeUsbDevice()

    sweep._read_iq()

    assert sweep.clip_ratio == 40 / 4096
