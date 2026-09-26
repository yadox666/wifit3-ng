from __future__ import annotations

from wifit3.persist.config import Config


_DEAUTH_LIMITS = {
    "low": (3, 6),
    "normal": (10, 20),
    "high": (20, 40),
}


def deauth_limits() -> tuple[int, int]:
    """Return client rounds and broadcast frames for the configured active intensity."""
    return _DEAUTH_LIMITS.get(Config.active_action_intensity, _DEAUTH_LIMITS["normal"])
