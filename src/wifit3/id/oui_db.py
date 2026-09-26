"""IEEE oui.txt cache. Downloaded from standards-oui.ieee.org, reused for 30 days."""
from __future__ import annotations

import gzip
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from platformdirs import user_cache_dir

from wifit3.models.identity import canonical_vendor

_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
_OUI_HOST = "standards-oui.ieee.org"
MAX_AGE_S = 30 * 24 * 60 * 60
MIN_VENDORS = 1000
_MAX_BYTES = 24 * 1024 * 1024
_TIMEOUT_S = 60

_HEX_LINE = re.compile(
    r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$"
)
_SUFFIX_RE = re.compile(
    r",?\s*("
    r"incorporated|inc\.?|llc\.?|ltd\.?|co\.,?\s*ltd\.?|corporation|corp\.?|gmbh|"
    r"s\.a\.?|s\.p\.a\.?|b\.v\.?|pty\.?\s*ltd\.?|pvt\.?\s*ltd\.?|ag|company|limited|"
    r"closed joint stock company|open joint stock company|jsc|oao|zao|ooo|systems|holding"
    r")\.?\s*$",
    re.IGNORECASE,
)
_TRAILING_CO = re.compile(r"(?<![A-Za-z])co\.?\s*$", re.IGNORECASE)
_NOT_A_VENDOR = frozenset({"ieee registration authority", "private"})
_SKIP_START = frozenset({
    "shengzen", "shenzhen", "beijing", "shanghai", "wuhan", "hangzhou", "guangxi",
    "guangdong", "chengdu",
})
_SPECIAL_CASE = {
    "At&T": "AT&T",
    "Samsung Electronics": "SAMSUNG Electronics",
    "Advanced Micro Devices": "AMD",
}

_mapping: dict[str, str] = {}
_generation = 0


@dataclass(frozen=True, slots=True)
class OuiStatus:
    """Outcome of one cache load or download."""

    ok: bool
    downloaded: bool
    count: int
    message: str


def mapping() -> dict[str, str]:
    """The oui.txt vendors installed for this process (empty until a load)."""
    return _mapping


def generation() -> int:
    """Bumps each time ``install`` replaces the vendor map."""
    return _generation


def install(vendors: dict[str, str]) -> None:
    """Replace the in-memory oui.txt map."""
    global _mapping, _generation
    _mapping = dict(vendors)
    _generation += 1


def cache_path() -> Path:
    """On-disk oui.txt, under the OS user cache directory."""
    return Path(user_cache_dir("wifit3", appauthor=False)) / "oui.txt"


def cache_is_fresh(path: Path | None = None, now: float | None = None) -> bool:
    """True when cached oui.txt exists and is younger than 30 days."""
    path = cache_path() if path is None else path
    now = time.time() if now is None else now
    try:
        return (now - path.stat().st_mtime) < MAX_AGE_S
    except OSError:
        return False


def parse_oui_txt(text: str) -> dict[str, str]:
    """Parse IEEE oui.txt ``(hex)`` lines into a 24-bit prefix -> vendor map."""
    vendors: dict[str, str] = {}
    for line in text.splitlines():
        if "(hex)" not in line:
            continue
        matched = _HEX_LINE.match(line)
        if matched is None:
            continue
        name = _vendor_name(matched.group(4))
        if name is None:
            continue
        prefix = (matched.group(1) + matched.group(2) + matched.group(3)).upper()
        vendors[prefix] = name
    return vendors


def ensure(
    *,
    force: bool = False,
    now: float | None = None,
    path: Path | None = None,
    fetch: Callable[[str], bytes] | None = None,
) -> OuiStatus:
    """Load oui.txt, downloading when missing, older than 30 days, or ``force``."""
    path = cache_path() if path is None else path
    now = time.time() if now is None else now
    fetch = _download if fetch is None else fetch
    if not force and cache_is_fresh(path, now):
        cached = _read_cache(path)
        if cached is not None:
            install(cached)
            return OuiStatus(
                True, False, len(cached),
                f"current, {len(cached)} vendors, {_updated(path, now)}; press u to refresh",
            )
    try:
        data = fetch(_OUI_URL)
        vendors = parse_oui_txt(_decode(data))
        if len(vendors) < MIN_VENDORS:
            raise ValueError("not an OUI database")
    except Exception as exc:
        return _use_cache_or_builtin(path, now, exc.__class__.__name__)
    try:
        _write_cache(path, _decode(data).encode("utf-8"))
    except OSError:
        pass
    install(vendors)
    return OuiStatus(
        True, True, len(vendors),
        f"downloaded {len(vendors)} vendors from {_OUI_HOST}",
    )


def _use_cache_or_builtin(path: Path, now: float, reason: str) -> OuiStatus:
    cached = _read_cache(path)
    if cached is not None:
        install(cached)
        return OuiStatus(
            False, False, len(cached),
            f"download failed ({reason}); using cache, {_updated(path, now)}, {len(cached)} vendors",
        )
    return OuiStatus(
        False, False, 0,
        f"download failed ({reason}); using the built-in vendor list",
    )


def _read_cache(path: Path) -> dict[str, str] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    vendors = parse_oui_txt(text)
    if len(vendors) < MIN_VENDORS:
        return None
    return vendors


def _write_cache(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.partial")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _updated(path: Path, now: float) -> str:
    try:
        days = int(max(0, now - path.stat().st_mtime) // 86400)
    except OSError:
        return "updated today"
    if days <= 0:
        return "updated today"
    unit = "day" if days == 1 else "days"
    return f"updated {days} {unit} ago"


def _decode(data: bytes) -> str:
    if data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
    if len(data) > _MAX_BYTES:
        raise ValueError("OUI download exceeded size limit")
    return data.decode("utf-8", "replace")


class _HostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlparse(newurl)
        if parts.scheme != "https" or parts.hostname != _OUI_HOST:
            raise urllib.error.URLError("redirect left the IEEE OUI host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": "wifit3",
        "Accept": "text/plain",
        "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(_HostRedirect())
    chunks: list[bytes] = []
    total = 0
    with opener.open(request, timeout=_TIMEOUT_S) as response:
        while True:
            block = response.read(64 * 1024)
            if not block:
                break
            total += len(block)
            if total > _MAX_BYTES:
                raise ValueError("OUI download exceeded size limit")
            chunks.append(block)
    return b"".join(chunks)


def _vendor_name(org: str) -> str | None:
    short = _short_org(org)
    if short is None:
        return None
    name = canonical_vendor(short) or short
    if name.casefold() in _NOT_A_VENDOR:
        return None
    return name


def _short_org(org: str) -> str | None:
    name = org.strip().strip('"').strip()
    if not name or name.casefold() in _NOT_A_VENDOR:
        return None
    name = (
        name.replace("\u2014", "-").replace("\u2013", "-")
        .replace("\u00ae", "").replace("\u2122", "")
    )
    words = name.split()
    if len(words) > 1 and words[0].casefold() in _SKIP_START:
        name = " ".join(words[1:])
    prev = None
    while prev != name and name:
        prev = name
        name = _SUFFIX_RE.sub("", name).strip()
    name = _TRAILING_CO.sub("", name).strip()
    if not name:
        return None
    cleaned = name.title() if name.isupper() else name
    return _SPECIAL_CASE.get(cleaned, cleaned)
