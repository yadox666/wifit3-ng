import json
import hashlib
import os
import platform
import sys

import pytest

import wifit3.updates as updates_module
from wifit3 import __version__
from wifit3.updates import (
    LATEST_RELEASE_API,
    RELEASES_URL,
    UpdateAsset,
    UpdateInfo,
    check_for_update,
    install_update,
)


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, size=-1):
        return json.dumps(self._payload).encode()[:size]


def test_secure_opener_uses_bundled_ca_file(monkeypatch):
    request = object()
    context = object()
    calls = {}
    monkeypatch.setattr(updates_module.certifi, "where", lambda: "/bundle/cacert.pem")
    monkeypatch.setattr(
        updates_module.ssl,
        "create_default_context",
        lambda *, cafile: calls.setdefault("cafile", cafile) and context,
    )

    def fake_urlopen(value, *, timeout, context):
        calls.update(request=value, timeout=timeout, context=context)
        return "response"

    monkeypatch.setattr(updates_module, "urlopen", fake_urlopen)

    assert updates_module._secure_urlopen(request, timeout=5.0) == "response"
    assert calls == {
        "cafile": "/bundle/cacert.pem",
        "request": request,
        "timeout": 5.0,
        "context": context,
    }


def test_update_check_reads_fork_release_response():
    requests = []

    def opener(request, timeout):
        requests.append((request, timeout))
        return _Response({
            "tag_name": "v99.1.0",
            "html_url": "https://github.com/yadox666/wifit3-ng/releases/tag/v99.1.0",
        })

    update = check_for_update(opener=opener)

    assert update.current_version == __version__
    assert update.latest_version == "99.1.0"
    assert update.update_available is True
    assert requests[0][1] == 5.0
    assert requests[0][0].full_url == LATEST_RELEASE_API
    assert requests[0][0].get_header("User-agent") == f"wifit3-ng/{__version__}"
    assert requests[0][0].get_header("X-github-api-version") == "2022-11-28"


def test_update_check_rejects_oversized_response():
    class OversizedResponse(_Response):
        def read(self, size=-1):
            return b"x" * size

    with pytest.raises(ValueError, match="too large"):
        check_for_update(opener=lambda *_args, **_kwargs: OversizedResponse({}))


@pytest.mark.parametrize("tag_name", ["", "latest", "v1.not-a-version"])
def test_update_check_rejects_invalid_release_versions(tag_name):
    with pytest.raises(ValueError, match="Invalid release version"):
        check_for_update(
            opener=lambda *_args, **_kwargs: _Response({"tag_name": tag_name}),
        )


def test_update_check_does_not_trust_an_external_release_url():
    update = check_for_update(
        opener=lambda *_args, **_kwargs: _Response({
            "tag_name": "v99.1.0",
            "html_url": "https://example.invalid/download",
        }),
    )

    assert update.release_url == RELEASES_URL


def test_pep440_prerelease_is_older_than_its_stable_release():
    update = UpdateInfo(
        current_version="2.0.0rc1",
        latest_version="2.0.0",
        release_url=RELEASES_URL,
    )

    assert update.update_available is True


def _platform_asset_name():
    if sys.platform == "darwin":
        return "wifit3-macos-universal2"
    if sys.platform == "win32":
        return "wifit3-windows-x64.exe"
    return (
        "wifit3-linux-arm64"
        if platform.machine().casefold() in {"aarch64", "arm64"}
        else "wifit3-linux-x64"
    )


def test_update_check_selects_verified_platform_asset():
    name = _platform_asset_name()
    update = check_for_update(
        opener=lambda *_args, **_kwargs: _Response({
            "tag_name": "v99.1.0",
            "html_url": "https://github.com/yadox666/wifit3-ng/releases/tag/v99.1.0",
            "assets": [{
                "name": name,
                "browser_download_url": (
                    f"https://github.com/yadox666/wifit3-ng/releases/download/"
                    f"v99.1.0/{name}"
                ),
                "digest": f"sha256:{'a' * 64}",
                "size": 123,
            }],
        }),
    )

    assert update.asset == UpdateAsset(
        name=name,
        download_url=(
            f"https://github.com/yadox666/wifit3-ng/releases/download/v99.1.0/{name}"
        ),
        sha256="a" * 64,
        size=123,
    )


class _DownloadResponse:
    def __init__(self, content):
        self.content = content
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, size=-1):
        if size < 0:
            size = len(self.content)
        chunk = self.content[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


@pytest.mark.skipif(sys.platform == "win32", reason="Windows locks the running executable")
def test_install_update_verifies_and_atomically_replaces_executable(tmp_path):
    content = b"new executable"
    name = _platform_asset_name()
    target = tmp_path / "wifit3"
    target.write_bytes(b"old executable")
    target.chmod(0o751)
    update = UpdateInfo(
        current_version="1.0.0",
        latest_version="99.1.0",
        release_url="https://github.com/yadox666/wifit3-ng/releases/tag/v99.1.0",
        asset=UpdateAsset(
            name=name,
            download_url=(
                f"https://github.com/yadox666/wifit3-ng/releases/download/"
                f"v99.1.0/{name}"
            ),
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
        ),
    )

    installed = install_update(
        update,
        executable_path=target,
        opener=lambda *_args, **_kwargs: _DownloadResponse(content),
    )

    assert installed == target
    assert target.read_bytes() == content
    assert os.stat(target).st_mode & 0o777 == 0o751


@pytest.mark.skipif(sys.platform == "win32", reason="Windows locks the running executable")
def test_install_update_rejects_checksum_mismatch(tmp_path):
    content = b"tampered executable"
    name = _platform_asset_name()
    target = tmp_path / "wifit3"
    target.write_bytes(b"old executable")
    update = UpdateInfo(
        current_version="1.0.0",
        latest_version="99.1.0",
        release_url="https://github.com/yadox666/wifit3-ng/releases/tag/v99.1.0",
        asset=UpdateAsset(
            name=name,
            download_url=(
                f"https://github.com/yadox666/wifit3-ng/releases/download/"
                f"v99.1.0/{name}"
            ),
            sha256="0" * 64,
            size=len(content),
        ),
    )

    with pytest.raises(ValueError, match="checksum"):
        install_update(
            update,
            executable_path=target,
            opener=lambda *_args, **_kwargs: _DownloadResponse(content),
        )

    assert target.read_bytes() == b"old executable"
