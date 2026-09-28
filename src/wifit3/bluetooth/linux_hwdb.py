"""Resolve BlueZ Device ID modaliases through the local Linux hardware database."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from functools import lru_cache


_MODALIAS_RE = re.compile(
    r"^bluetooth:v(?P<vendor>[0-9a-f]{4})p(?P<product>[0-9a-f]{4})"
    r"d(?P<device>[0-9a-f]{4})$",
    re.IGNORECASE,
)
_HWDB_KEYS = {
    "ID_VENDOR_FROM_DATABASE": "hardware_vendor",
    "ID_MODEL_FROM_DATABASE": "hardware_product",
}


@lru_cache(maxsize=512)
def resolve_bluez_modalias(modalias: str) -> dict[str, str]:
    """Return bounded local hwdb identity data for a valid BlueZ modalias."""
    match = _MODALIAS_RE.fullmatch(modalias.strip())
    if match is None:
        return {}
    normalized = (
        f"bluetooth:v{match['vendor'].upper()}p{match['product'].upper()}"
        f"d{match['device'].upper()}"
    )
    result = {"modalias": normalized}
    if not sys.platform.startswith("linux"):
        return result
    command = _hwdb_command(normalized)
    if command is None:
        return result
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=1.0,
        )
    except (OSError, subprocess.SubprocessError):
        return result
    if completed.returncode != 0:
        return result
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        destination = _HWDB_KEYS.get(key.strip())
        value = value.strip()
        if separator and destination and value:
            result[destination] = value[:256]
    if len(result) > 1:
        result["hardware_source"] = "BlueZ Device ID / systemd hwdb"
    return result


def _hwdb_command(modalias: str) -> list[str] | None:
    systemd_hwdb = shutil.which("systemd-hwdb")
    if systemd_hwdb:
        return [systemd_hwdb, "query", modalias]
    udevadm = shutil.which("udevadm")
    if udevadm:
        return [udevadm, "hwdb", f"--query={modalias}"]
    return None
