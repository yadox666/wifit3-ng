import json

import pytest

from wifit3 import __version__
from wifit3.updates import LATEST_RELEASE_API, check_for_update


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
            "html_url": "https://github.com/yadox666/wifit3/releases/tag/v99.1.0",
        })

    update = check_for_update(opener=opener)

    assert update.current_version == __version__
    assert update.latest_version == "99.1.0"
    assert update.update_available is True
    assert requests[0][1] == 5.0
    assert requests[0][0].full_url == LATEST_RELEASE_API


def test_update_check_rejects_oversized_response():
    class OversizedResponse(_Response):
        def read(self, size=-1):
            return b"x" * size

    with pytest.raises(ValueError, match="too large"):
        check_for_update(opener=lambda *_args, **_kwargs: OversizedResponse({}))
