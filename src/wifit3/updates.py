from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.request import Request, urlopen

from wifit3 import __version__


LATEST_RELEASE_API = "https://api.github.com/repos/yadox666/wifit3/releases/latest"
RELEASES_URL = "https://github.com/yadox666/wifit3/releases"
MAX_RESPONSE_BYTES = 65_536


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    release_url: str

    @property
    def update_available(self) -> bool:
        return _version_key(self.latest_version) > _version_key(self.current_version)


def _version_key(version: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", version)
    return tuple(int(number) for number in numbers[:4])


def check_for_update(*, opener=urlopen) -> UpdateInfo:
    """Query this fork's GitHub release endpoint without sending scan or device data."""
    request = Request(
        LATEST_RELEASE_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"wifit3/{__version__}"},
    )
    with opener(request, timeout=5.0) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Update response is too large")
    payload = json.loads(raw.decode("utf-8"))
    latest = str(payload["tag_name"]).lstrip("v")
    release_url = str(payload.get("html_url") or RELEASES_URL)
    return UpdateInfo(__version__, latest, release_url)
