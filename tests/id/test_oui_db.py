"""IEEE oui.txt parse, 30-day cache, and lookup overlay. No network."""
import gzip
import os
import time
import urllib.error

import pytest

from wifit3.id import oui_db
from wifit3.id.common import lookup_oui

_SAMPLE = """
OUI/MA-L                                                    Organization

00-03-93   (hex)\t\tApple, Inc.
000393     (base 16)\t\tApple, Inc.
\t\t\t\t1 Infinite Loop

E8-0A-B9   (hex)\t\tCisco Systems, Inc
E0-06-30   (hex)\t\tHUAWEI TECHNOLOGIES CO.,LTD
AA-BB-CC   (hex)\t\tCostco
B8-4C-87   (hex)\t\tIEEE Registration Authority
E4-F1-4C   (hex)\t\tPrivate
00-11-22   (hex)\t\tAcme Widgets, Inc.
"""


@pytest.fixture(autouse=True)
def _restore_oui():
    prior = dict(oui_db.mapping())
    yield
    oui_db.install(prior)


@pytest.fixture
def one_vendor(monkeypatch):
    monkeypatch.setattr(oui_db, "MIN_VENDORS", 1)


def test_parse_oui_txt_cleans_names_and_skips_non_vendors():
    vendors = oui_db.parse_oui_txt(_SAMPLE)
    assert vendors["000393"] == "Apple"
    assert vendors["E80AB9"] == "Cisco"
    assert vendors["E00630"] == "Huawei Technologies"
    assert vendors["AABBCC"] == "Costco"
    assert vendors["001122"] == "Acme Widgets"
    assert "B84C87" not in vendors
    assert "E4F14C" not in vendors
    assert "000393" in vendors


def test_cache_is_fresh_for_thirty_days(tmp_path):
    path = tmp_path / "oui.txt"
    path.write_text("x", encoding="utf-8")
    now = 1_000_000.0
    os.utime(path, (now, now))
    assert oui_db.cache_is_fresh(path, now + oui_db.MAX_AGE_S - 1)
    assert not oui_db.cache_is_fresh(path, now + oui_db.MAX_AGE_S)
    assert not oui_db.cache_is_fresh(tmp_path / "missing.txt", now)


def test_ensure_reuses_a_fresh_cache(tmp_path, one_vendor):
    path = tmp_path / "oui.txt"
    path.write_text(_SAMPLE, encoding="utf-8")
    now = time.time()

    def fetch(_url):
        raise AssertionError("fresh cache must not download")

    status = oui_db.ensure(path=path, fetch=fetch, now=now)
    assert status.ok and not status.downloaded
    assert status.count == 5
    assert oui_db.mapping()["001122"] == "Acme Widgets"
    assert "press u to refresh" in status.message


def test_ensure_downloads_when_the_cache_is_a_month_old(tmp_path, one_vendor):
    path = tmp_path / "oui.txt"
    path.write_text(_SAMPLE, encoding="utf-8")
    old = time.time() - 40 * 86400
    os.utime(path, (old, old))
    fetched = []

    def fetch(url):
        fetched.append(url)
        return b"00-22-33   (hex)\t\tZebra Labs\n"

    status = oui_db.ensure(path=path, fetch=fetch, now=time.time())
    assert fetched == [oui_db._OUI_URL]
    assert status.ok and status.downloaded
    assert oui_db.mapping() == {"002233": "Zebra Labs"}
    assert b"Zebra Labs" in path.read_bytes()


def test_ensure_force_downloads_a_fresh_cache(tmp_path, one_vendor):
    path = tmp_path / "oui.txt"
    path.write_text(_SAMPLE, encoding="utf-8")

    def fetch(_url):
        return b"00-22-33   (hex)\t\tZebra Labs\n"

    status = oui_db.ensure(force=True, path=path, fetch=fetch, now=time.time())
    assert status.downloaded
    assert "002233" in oui_db.mapping()


def test_ensure_keeps_a_stale_cache_when_download_fails(tmp_path, one_vendor):
    path = tmp_path / "oui.txt"
    path.write_text(_SAMPLE, encoding="utf-8")
    old = time.time() - 40 * 86400
    os.utime(path, (old, old))

    def fetch(_url):
        raise TimeoutError("offline")

    status = oui_db.ensure(path=path, fetch=fetch, now=time.time())
    assert not status.ok
    assert "cache" in status.message
    assert oui_db.mapping()["000393"] == "Apple"


def test_ensure_falls_back_to_builtin_list_without_a_cache(tmp_path, one_vendor):
    gen = oui_db.generation()

    def fetch(_url):
        raise urllib.error.URLError("offline")

    status = oui_db.ensure(
        force=True, path=tmp_path / "missing.txt", fetch=fetch, now=time.time(),
    )
    assert not status.ok
    assert status.count == 0
    assert "built-in" in status.message
    assert oui_db.generation() == gen


def test_ensure_accepts_a_gzip_body(tmp_path, one_vendor):
    body = b"00-11-22   (hex)\t\tAcme Widgets, Inc.\n"

    def fetch(_url):
        return gzip.compress(body)

    status = oui_db.ensure(
        force=True, path=tmp_path / "oui.txt", fetch=fetch, now=time.time(),
    )
    assert status.ok and status.downloaded
    assert oui_db.mapping()["001122"] == "Acme Widgets"
    assert path_text(tmp_path / "oui.txt").startswith("00-11-22")


def path_text(path):
    return path.read_text(encoding="utf-8")


def test_redirect_must_stay_on_the_ieee_host():
    handler = oui_db._HostRedirect()
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/oui.txt")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(
            None, None, 302, "Found", {}, "http://standards-oui.ieee.org/oui/oui.txt",
        )


def test_live_oui_overrides_24bit_and_keeps_longer_prefixes():
    specific = lookup_oui("00:1b:c5:00:0a:bb")
    assert specific and "Parent" not in specific
    oui_db.install({"001BC5": "Parent Block", "00000B": "Live Vendor"})
    assert lookup_oui("00:1b:c5:00:0a:bb") == specific
    assert lookup_oui("00:00:0b:aa:bb:cc") == "Live Vendor"
