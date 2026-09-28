"""A final channel lock must restore RTL8814AU monitor data-frame admission."""
from unittest.mock import MagicMock

from wifit3.chips.rtl8814au_dkms import driver as driver_mod
from wifit3.chips.rtl8814au_dkms.driver import Rtl8814auDkmsDriver


class _Reader:
    def __init__(self, events):
        self.events = events

    def pause(self):
        self.events.append("pause")
        return True

    def resume(self):
        self.events.append("resume")


async def test_deliberate_channel_lock_rearms_monitor_filter(monkeypatch):
    events = []
    transport = MagicMock()
    transport.reset_rx_pipe.side_effect = lambda: events.append("reset-pipe")
    drv = Rtl8814auDkmsDriver(transport)
    drv._reader = _Reader(events)
    monkeypatch.setattr(drv, "_tune", lambda _t, ch: events.append(("tune", ch)))
    monkeypatch.setattr(
        driver_mod,
        "enter_monitor",
        lambda _t: events.append("enter-monitor"),
    )

    assert await drv.set_channel(9, scan=False)
    assert events == ["pause", ("tune", 9), "enter-monitor", "reset-pipe", "resume"]


async def test_scan_hop_does_not_rearm_monitor_filter(monkeypatch):
    events = []
    drv = Rtl8814auDkmsDriver(MagicMock())
    drv._reader = _Reader(events)
    monkeypatch.setattr(drv, "_tune", lambda _t, ch: events.append(("tune", ch)))
    monkeypatch.setattr(
        driver_mod,
        "enter_monitor",
        lambda _t: events.append("enter-monitor"),
    )

    assert await drv.set_channel(6, scan=True)
    assert events == [("tune", 6)]
