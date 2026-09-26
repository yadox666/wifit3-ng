from wifit3.persist.config import Config
from wifit3.safety import deauth_limits


def test_deauth_limits_follow_active_intensity(monkeypatch):
    monkeypatch.setattr(Config, "active_action_intensity", "low")
    assert deauth_limits() == (3, 6)
    monkeypatch.setattr(Config, "active_action_intensity", "high")
    assert deauth_limits() == (20, 40)
