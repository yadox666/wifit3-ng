import json

import pytest

from wifit3 import __version__
from wifit3.updates import (
    LATEST_RELEASE_API,
    RELEASES_URL,
    UpdateInfo,
    check_for_update,
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
