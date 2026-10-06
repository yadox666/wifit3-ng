from __future__ import annotations

import json
import hashlib
import os
import platform
import ssl
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import certifi
from packaging.version import InvalidVersion, Version

from wifit3 import __version__


LATEST_RELEASE_API = "https://api.github.com/repos/yadox666/wifit3-ng/releases/latest"
RELEASES_URL = "https://github.com/yadox666/wifit3-ng/releases"
MAX_RESPONSE_BYTES = 65_536
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
_RELEASE_PATH_PREFIX = "/yadox666/wifit3-ng/releases/"


def _tls_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def _secure_urlopen(request: Request, *, timeout: float):
    """Open HTTPS using a CA bundle that is also present in frozen builds."""
    return urlopen(request, timeout=timeout, context=_tls_context())


@dataclass(frozen=True)
class UpdateAsset:
    name: str
    download_url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    release_url: str
    asset: UpdateAsset | None = None

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


def _asset_name() -> str | None:
    if sys.platform == "darwin":
        return "wifit3-macos-universal2"
    if sys.platform == "win32":
        return "wifit3-windows-x64.exe"
    if sys.platform.startswith("linux"):
        machine = platform.machine().casefold()
        if machine in {"aarch64", "arm64"}:
            return "wifit3-linux-arm64"
        if machine in {"x86_64", "amd64"}:
            return "wifit3-linux-x64"
    return None


def _release_asset(payload: dict, version: str) -> UpdateAsset | None:
    expected_name = _asset_name()
    assets = payload.get("assets")
    if expected_name is None or not isinstance(assets, list):
        return None
    for value in assets:
        if not isinstance(value, dict) or value.get("name") != expected_name:
            continue
        url = str(value.get("browser_download_url", ""))
        parsed = urlparse(url)
        expected_path = (
            f"/yadox666/wifit3-ng/releases/download/v{version}/{expected_name}"
        )
        digest = str(value.get("digest", ""))
        sha256 = digest.removeprefix("sha256:")
        size = value.get("size")
        if (
            parsed.scheme != "https"
            or parsed.netloc.casefold() != "github.com"
            or parsed.path != expected_path
            or digest == sha256
            or len(sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in sha256)
            or not isinstance(size, int)
            or not 0 < size <= MAX_DOWNLOAD_BYTES
        ):
            return None
        return UpdateAsset(expected_name, url, sha256.casefold(), size)
    return None


def _asset_is_trusted(asset: UpdateAsset, version: str) -> bool:
    expected_name = _asset_name()
    parsed = urlparse(asset.download_url)
    return (
        expected_name is not None
        and asset.name == expected_name
        and parsed.scheme == "https"
        and parsed.netloc.casefold() == "github.com"
        and parsed.path
        == f"/yadox666/wifit3-ng/releases/download/v{version}/{expected_name}"
        and len(asset.sha256) == 64
        and not any(char not in "0123456789abcdef" for char in asset.sha256)
        and 0 < asset.size <= MAX_DOWNLOAD_BYTES
    )


def check_for_update(*, opener=_secure_urlopen) -> UpdateInfo:
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
    return UpdateInfo(__version__, latest, release_url, _release_asset(payload, latest))


def can_install_update(update: UpdateInfo) -> bool:
    """Return whether this process can safely replace its bundled executable."""
    return (
        update.asset is not None
        and sys.platform != "win32"
        and bool(getattr(sys, "frozen", False))
        and Path(sys.executable).is_file()
        and not Path(sys.executable).is_symlink()
    )


def install_update(
    update: UpdateInfo,
    *,
    opener=_secure_urlopen,
    executable_path: Path | None = None,
) -> Path:
    """Download, verify, and atomically replace a macOS/Linux one-file executable."""
    asset = update.asset
    if asset is None or not _asset_is_trusted(asset, update.latest_version):
        raise ValueError("No verified update is available for this platform")
    if executable_path is None:
        if not can_install_update(update):
            raise RuntimeError("Automatic installation is unavailable for this build")
        executable_path = Path(sys.executable)
    requested_target = Path(executable_path)
    if requested_target.is_symlink():
        raise RuntimeError("The running executable cannot be replaced safely")
    target = requested_target.resolve()
    if not target.is_file():
        raise RuntimeError("The running executable cannot be replaced safely")

    request = Request(
        asset.download_url,
        headers={"User-Agent": f"wifit3-ng/{__version__}"},
    )
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".update", dir=target.parent,
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    received = 0
    try:
        with os.fdopen(fd, "wb") as output, opener(request, timeout=30.0) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > asset.size or received > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Update download is larger than published")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if received != asset.size:
            raise ValueError("Update download is incomplete")
        if digest.hexdigest() != asset.sha256:
            raise ValueError("Update checksum verification failed")
        os.chmod(temporary, stat.S_IMODE(target.stat().st_mode))
        os.replace(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)
