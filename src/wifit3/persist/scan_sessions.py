from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Iterable


_WORDS = (
    "amber", "anchor", "apricot", "atlas", "bamboo", "beacon", "birch",
    "breeze", "brook", "canyon", "cedar", "cipher", "cobalt", "comet",
    "coral", "cosmos", "crystal", "delta", "ember", "falcon", "fern",
    "fjord", "forest", "fox", "galaxy", "garden", "glacier", "harbor",
    "hazel", "horizon", "indigo", "island", "jade", "juniper", "lagoon",
    "lantern", "lilac", "lotus", "maple", "marble", "meadow", "meteor",
    "mist", "moon", "mosaic", "nebula", "oasis", "ocean", "olive",
    "onyx", "orbit", "otter", "pebble", "pine", "plum", "prairie",
    "quartz", "raven", "reef", "river", "robin", "saffron", "sage",
    "signal", "silver", "sparrow", "spruce", "star", "stone", "summit",
    "sunset", "tide", "timber", "topaz", "valley", "violet", "willow",
    "wind", "winter", "zenith",
)


@dataclass(frozen=True, slots=True)
class ScanSession:
    id: str
    name: str
    started_at: float
    media: frozenset[str]
    mode: str


def generate_session_name(existing: Iterable[str] = ()) -> str:
    """Return a memorable, non-sensitive two/three-word session label."""
    used = {str(name).casefold() for name in existing}
    while True:
        word_count = 2 if secrets.randbelow(4) == 0 else 3
        name = "-".join(secrets.SystemRandom().sample(_WORDS, word_count))
        if name.casefold() not in used:
            return name


def new_scan_session(
    media: Iterable[str],
    *,
    mode: str,
    existing_names: Iterable[str] = (),
) -> ScanSession:
    normalized = frozenset(str(item).strip().casefold() for item in media if item)
    if not normalized:
        raise ValueError("A scan session requires at least one medium")
    return ScanSession(
        id=str(uuid.uuid4()),
        name=generate_session_name(existing_names),
        started_at=time.time(),
        media=normalized,
        mode=mode,
    )
