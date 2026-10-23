from wifit3.persist.config import Config
from wifit3.safety import deauth_limits


def test_deauth_limits_follow_active_intensity(monkeypatch):
    monkeypatch.setattr(Config, "active_action_intensity", "low")
    assert deauth_limits() == (5, 10)
    monkeypatch.setattr(Config, "active_action_intensity", "high")
    assert deauth_limits() == (20, 40)


def test_deauth_limits_never_below_ten_frames(monkeypatch):
    """Focus/API deauth bursts must send at least 10 broadcast frames (and 5 client rounds)."""
    monkeypatch.setattr(Config, "active_action_intensity", "low")
    rounds, broadcast = deauth_limits()
    assert broadcast >= 10
    assert rounds >= 5
