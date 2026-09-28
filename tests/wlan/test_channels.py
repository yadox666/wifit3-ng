"""Channel helpers: scan-hop ordering and per-band label/range compression."""
from types import SimpleNamespace

import pytest

from wifit3.wlan.channels import (
    ChannelSpec,
    _compress_runs,
    band_label,
    band_ranges,
    channel_spec_for_ap,
    scan_hop_order,
)


def test_scan_hop_order_front_loads_busy_24ghz():
    # Sequential SUPPORTED_CHANNELS → 1/6/11 first, then rest of 2.4, then 5 GHz.
    got = scan_hop_order(list(range(1, 14)) + [36, 40, 44, 48, 149])
    assert got == [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 36, 40, 44, 48, 149]


def test_scan_hop_order_is_a_permutation():
    # Pure reorder: same channels in, same channels out (no adds/drops).
    src = list(range(1, 14)) + [36, 40, 44, 48, 149, 153, 157, 161, 165]
    assert sorted(scan_hop_order(src)) == sorted(src)


def test_scan_hop_order_partial_priority_set():
    # Only the priority channels actually present are front-loaded.
    assert scan_hop_order([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert scan_hop_order([2, 3, 6, 4]) == [6, 2, 3, 4]


def test_channel_spec_for_40mhz_ap_uses_secondary_and_center():
    ap = SimpleNamespace(
        channel=9,
        capabilities=SimpleNamespace(
            operating_width_mhz=40,
            secondary_channel_offset=-1,
            center_channel_0=7,
        ),
    )
    assert channel_spec_for_ap(ap) == ChannelSpec(9, 40, 7, -1)


def test_channel_spec_falls_back_to_20_when_operation_is_incomplete():
    ap = SimpleNamespace(
        channel=44,
        capabilities=SimpleNamespace(
            operating_width_mhz=40,
            secondary_channel_offset=None,
            center_channel_0=None,
        ),
    )
    assert channel_spec_for_ap(ap) == ChannelSpec(44)
    with pytest.raises(ValueError, match="secondary"):
        ChannelSpec(9, 40)


# --- band label / range compression (scanner init line + Channel Filter log) --------

def test_band_label():
    assert band_label(list(range(1, 14))) == "2.4 GHz"
    assert band_label([36, 40, 44, 48, 149]) == "5 GHz"
    assert band_label([1, 6, 11, 36, 149]) == "2.4 GHz + 5 GHz"
    assert band_label([]) == ""


def test_compress_runs_24ghz_step1():
    assert _compress_runs(list(range(1, 14)), 1) == "1-13"
    assert _compress_runs([1, 2, 3, 4, 5, 6, 11], 1) == "1-6, 11"
    assert _compress_runs([1], 1) == "1"
    assert _compress_runs([], 1) == ""


def test_compress_runs_5ghz_step4():
    # 5 GHz channels are spaced by 4, so 36,40,44,48 collapse to one run; the big
    # gap to UNII-3 (and any excluded DFS slot) breaks it.
    assert _compress_runs([36, 40, 44, 48, 149, 153, 157, 161, 165], 4) == "36-48, 149-165"
    assert _compress_runs([44], 4) == "44"
    # DFS included: UNII-1+2 are contiguous (36-64), UNII-2e separate (100-144).
    full = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124,
            128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    assert _compress_runs(full, 4) == "36-64, 100-144, 149-165"


def test_band_ranges_always_per_band():
    # The chosen rule: every case breaks out per band, each with its own ranges.
    assert band_ranges(list(range(1, 14))) == [("2.4 GHz", "1-13")]
    assert band_ranges([36, 40, 44, 48, 149, 153, 157, 161, 165]) == [
        ("5 GHz", "36-48, 149-165")
    ]
    assert band_ranges(list(range(1, 14)) + [36, 40, 44, 48, 149, 153, 157, 161, 165]) == [
        ("2.4 GHz", "1-13"),
        ("5 GHz", "36-48, 149-165"),
    ]
    # A custom cross-band filter stays per-band (not a merged range run).
    assert band_ranges([1, 2, 3, 4, 5, 6, 11, 44]) == [
        ("2.4 GHz", "1-6, 11"),
        ("5 GHz", "44"),
    ]
