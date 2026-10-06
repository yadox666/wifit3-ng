"""Shared persistence helpers: filename parsing, regexes, and Hashcat 22000 lines."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_SSID_SAFE_RE = re.compile(r"[^A-Za-z0-9_-]")
_SSID_MAX = 32

# Filename stand-in for a WPA passphrase that applies to every AP of one SSID.
SSID_SCOPED_BSSID_TOKEN = "ess"
SSID_SCOPE_PREFIX = "ssid:"

LEGACY_CAPTURE_RE = re.compile(
    r"^(?P<ssid>.+)_"
    r"(?P<bssid>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}|ess)_"
    r"(?P<epoch>\d+)_"
    r"(?P<kind>enterprise_report|eap_lab_report|handshake|pmkid|mschapv2|netntlmv2|packet_capture|wep_key|wps_pin|wps_pbc|wpa_psk)"
    r"\.(?P<ext>json|pcap|hc22000|mschapv2|netntlmv2|txt)$"
)

AGGREGATED_HC22000_RE = re.compile(
    r"^(?P<ssid>.+)_"
    r"(?P<bssid>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
    r"\.hc22000$"
)

WEP_KEY_HEX_RE = re.compile(r"WEP key \(hex\):\s*([0-9a-fA-F]+)")
WPS_PSK_RE = re.compile(r"^PSK:\s*(.+)$", re.MULTILINE)
WPS_PIN_RE = re.compile(r"^PIN:\s*(.+)$", re.MULTILINE)


def safe_ssid(ssid: Optional[str]) -> str:
    """Sanitize an SSID for filesystem path safety."""
    base = _SSID_SAFE_RE.sub("_", ssid or "")[:_SSID_MAX]
    return base or "hidden"


def bssid_to_dashed(bssid: str) -> str:
    """``aa:bb:cc:dd:ee:ff`` -> ``aa-bb-cc-dd-ee-ff``."""
    return bssid.replace(":", "-").lower()


def bssid_to_colon(dashed: str) -> str:
    """``aa-bb-cc-dd-ee-ff`` -> ``aa:bb:cc:dd:ee:ff``."""
    return dashed.replace("-", ":").lower()


def bssid_path_token(bssid: str | None) -> str:
    """Dashed BSSID, or the SSID-scoped token when the address was left blank."""
    if not (bssid or "").strip():
        return SSID_SCOPED_BSSID_TOKEN
    return bssid_to_dashed(bssid)


def is_ssid_scoped_token(token: str) -> bool:
    return token.lower() == SSID_SCOPED_BSSID_TOKEN


def ssid_scope_key(ssid: str | None) -> str:
    """Vault index key for a passphrase that is not tied to one access point."""
    return f"{SSID_SCOPE_PREFIX}{ssid or ''}"


def is_ssid_scope_key(key: str) -> bool:
    return key.startswith(SSID_SCOPE_PREFIX)


def capture_index_key(bssid: str | None, ssid: str | None) -> str:
    """Index a capture by BSSID, or by SSID when it covers every AP of that name."""
    if not (bssid or "").strip():
        return ssid_scope_key(ssid)
    return bssid or ""


@dataclass(frozen=True, slots=True)
class Hc22000Line:
    """Parsed Hashcat mode 22000 record (PMKID or EAPOL handshake)."""
    kind: str           # "01" (PMKID) or "02" (EAPOL)
    pmkid_or_mic: str   # field 2: PMKID hex (if 01) or MIC (if 02)
    mac_ap: str         # field 3
    mac_sta: str        # field 4
    essid: str          # field 5
    anonce: str = ""    # field 6 (EAPOL only)
    eapol: str = ""     # field 7 (EAPOL only)
    message_pair: str = ""  # field 8 (EAPOL only)


def parse_hc22000(line: str) -> Optional[Hc22000Line]:
    """Parse one ``WPA*01*…`` or ``WPA*02*…`` line into an Hc22000Line."""
    parts = line.strip().split("*")
    if len(parts) < 6 or parts[0] != "WPA":
        return None
    return Hc22000Line(
        kind=parts[1],
        pmkid_or_mic=parts[2].lower(),
        mac_ap=parts[3].lower(),
        mac_sta=parts[4].lower(),
        essid=parts[5],
        anonce=parts[6].lower() if len(parts) > 6 else "",
        eapol=parts[7] if len(parts) > 7 else "",
        message_pair=parts[8] if len(parts) > 8 else "",
    )
