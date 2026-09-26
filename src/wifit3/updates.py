from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version

from wifit3 import __version__


LATEST_RELEASE_API = "https://api.github.com/repos/yadox666/wifit3-ng/releases/latest"
RELEASES_URL = "https://github.com/yadox666/wifit3-ng/releases"
MAX_RESPONSE_BYTES = 65_536
_RELEASE_PATH_PREFIX = "/yadox666/wifit3-ng/releases/"


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    release_url: str

    @property
    def update_available(self) -> bool:
        return Version(self.latest_version) > Version(self.current_version)


def _release_url(value: object) -> str:
    candidate = str(value or "")
    parsed = urlparse(candidate)
    if (
        parsed.scheme == "https"
        and parsed.netloc.casefold() == "github.com"
        and parsed.path.casefold().startswith(_RELEASE_PATH_PREFIX)
    ):
        return candidate
    return RELEASES_URL


def check_for_update(*, opener=urlopen) -> UpdateInfo:
    """Query this fork's GitHub release endpoint without sending scan or device data."""
    request = Request(
        LATEST_RELEASE_API,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"wifit3-ng/{__version__}",
        },
    )
    with opener(request, timeout=5.0) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Update response is too large")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Invalid update response")
    latest = str(payload.get("tag_name", "")).removeprefix("v")
    try:
        Version(latest)
        Version(__version__)
    except InvalidVersion as exc:
        raise ValueError("Invalid release version") from exc
    release_url = _release_url(payload.get("html_url"))
    return UpdateInfo(__version__, latest, release_url)
