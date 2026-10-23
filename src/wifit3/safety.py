from __future__ import annotations

from wifit3.persist.config import Config


# Directed deauth sends two frames per round (AP→client and client→AP).
_MIN_DEAUTH_CLIENT_ROUNDS = 5
_MIN_DEAUTH_BROADCAST_FRAMES = 10

_DEAUTH_LIMITS = {
    "low": (5, 10),
    "normal": (10, 20),
    "high": (20, 40),
}


def deauth_limits() -> tuple[int, int]:
    """Return client rounds and broadcast frames for the configured active intensity."""
    rounds, broadcast = _DEAUTH_LIMITS.get(
        Config.active_action_intensity, _DEAUTH_LIMITS["normal"],
    )
    return (
        max(rounds, _MIN_DEAUTH_CLIENT_ROUNDS),
        max(broadcast, _MIN_DEAUTH_BROADCAST_FRAMES),
    )
