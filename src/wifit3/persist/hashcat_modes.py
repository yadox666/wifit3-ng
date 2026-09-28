"""Hashcat mode selection per on-disk capture format."""
from __future__ import annotations

from pathlib import Path

# Hashcat mode 4800 is iSCSI CHAP (MD5), not NetNTLMv2. NetNTLMv2-SSP uses 5600.
HASHCAT_MODE_MSCHAPV2 = "5500"
HASHCAT_MODE_NETNTLMV2 = "5600"
HASHCAT_MODE_WPA = "22000"


def hashcat_mode_for_path(path: str | Path) -> str:
    name = Path(path).name.lower()
    if name.endswith(".netntlmv2"):
        return HASHCAT_MODE_NETNTLMV2
    if name.endswith(".mschapv2"):
        return HASHCAT_MODE_MSCHAPV2
    if name.endswith(".hc22000"):
        return HASHCAT_MODE_WPA
    return HASHCAT_MODE_WPA
