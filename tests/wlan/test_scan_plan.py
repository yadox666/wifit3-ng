from wifit3.wlan.scan_plan import (
    channels_for_scan_band,
    member_channels_for_scan,
    uses_per_card_scan_bands,
)


class _Member:
    def __init__(self, name: str, channels: list[int], key: tuple):
        self.name = name
        self.supported_channels = channels
        self.instance_key = key


def test_channels_for_scan_band_splits_24_and_5():
    supported = [1, 6, 11, 36, 40]
    assert channels_for_scan_band(supported, "2g") == [1, 6, 11]
    assert channels_for_scan_band(supported, "5g") == [36, 40]
    assert channels_for_scan_band(supported, "all") == [1, 6, 11, 36, 40]


def test_member_channels_none_when_every_card_all_bands():
    a = _Member("wlan0", [1, 6, 36], (1, 2, 3, 4))
    b = _Member("wlan1", [1, 6, 36], (1, 2, 3, 5))
    plan = {a.instance_key: "all", b.instance_key: "all"}
    assert member_channels_for_scan([a, b], None, plan) is None
    assert not uses_per_card_scan_bands([a, b], plan)


def test_member_channels_pins_each_card_to_one_band():
    a = _Member("wlan0", [1, 6, 11], (1, 2, 3, 4))
    b = _Member("wlan1", [36, 40, 44], (1, 2, 3, 5))
    plan = {a.instance_key: "2g", b.instance_key: "5g"}
    assignment = member_channels_for_scan([a, b], None, plan)
    assert assignment is not None
    assert assignment[a] == [1, 6, 11]
    assert assignment[b] == [36, 40, 44]


def test_member_channels_respects_global_channel_lock():
    a = _Member("wlan0", [1, 6, 11], (1, 2, 3, 4))
    plan = {a.instance_key: "2g"}
    assignment = member_channels_for_scan([a], [6], plan)
    assert assignment[a] == [6]
