"""802.11 Open-System Authentication + Association Request builders (pure spec).

The frame bytes only; the stateful auth+assoc exchange (retries, RX matching) lives in
the campaign that drives these, ``campaigns.auth_assoc``.
"""
import struct
from typing import Optional, Set

from wifit3.dot11.ie import ds_param_ie, ssid_ie, rates_ie, ext_rates_ie, ht_cap_ie

# STA WMM Information element (not the AP Parameter element).
WMM_INFO_IE = bytes.fromhex("dd070050f202000100")
from wifit3.dot11.mac import mac_header

_CAP_ESS = 0x0001
_CAP_PRIVACY = 0x0010
_CAP_SHORT_PREAMBLE = 0x0020
_CAP_SHORT_SLOT = 0x0400
_STA_SAFE_CAPS = _CAP_ESS | _CAP_PRIVACY | _CAP_SHORT_PREAMBLE | _CAP_SHORT_SLOT
_FLAG_BITS = {
    "ESS": _CAP_ESS,
    "Privacy": _CAP_PRIVACY,
    "Short Preamble": _CAP_SHORT_PREAMBLE,
    "Short Slot": _CAP_SHORT_SLOT,
}

# Standard 802.11 Authentication / Association response status codes.
STATUS_CODES = {
    0: "success",
    1: "unspecified-failure",
    10: "caps-unsupported",
    12: "assoc-denied-outside-standard",
    13: "rates-unsupported",
    14: "short-slot-unsupported",
    15: "dsss-ofdm-unsupported",
    17: "assoc-denied-ap-busy",
    18: "basic-rates-unsupported",
    19: "short-preamble-unsupported",
    27: "ht-caps-required",
    30: "pmf-required",
    34: "ht-caps-unsupported",
    40: "invalid-ie",
    41: "group-cipher-invalid",
    42: "pairwise-cipher-invalid",
    43: "akm-invalid",
    44: "rsne-version-unsupported",
    45: "rsne-caps-invalid",
    46: "cipher-suite-rejected",
    72: "vht-caps-unsupported",
}


def status_description(code: Optional[int]) -> str:
    """Human name for an 802.11 auth/assoc status code."""
    if code is None:
        return "none"
    return STATUS_CODES.get(code, f"unknown(0x{code:02x})")


def _hdr(fc: bytes, bssid: bytes, our_mac: bytes) -> bytes:
    """24-byte management header for a client->AP frame: addr1 = addr3 = bssid, addr2 =
    our forged STA. Duration and sequence are 0 (the chip fills the sequence)."""
    return mac_header(fc, bssid, our_mac, bssid)


def auth_req(bssid: bytes, our_mac: bytes) -> bytes:
    """Open-System Authentication Request (algorithm 0, sequence 1, status 0)."""
    return _hdr(b"\xb0\x00", bssid, our_mac) + b"\x00\x00\x01\x00\x00\x00"


def sta_capability(
    privacy: bool,
    channel: int = 1,
    capability_flags: Optional[Set[str]] = None,
) -> int:
    """STA Capability Info that AirOS and other ERP APs will accept.

    Status 10 (caps-unsupported) is the AP rejecting this field. Echo the
    beacon's ESS/Privacy/Short Preamble/Short Slot bits; if the AP flags are
    unknown, claim the 2.4 GHz ERP bits those APs require.
    """
    cap = _CAP_ESS | (_CAP_PRIVACY if privacy else 0)
    if capability_flags:
        for name, bit in _FLAG_BITS.items():
            if name != "Privacy" and name in capability_flags:
                cap |= bit
        return cap & _STA_SAFE_CAPS
    if channel <= 14:
        cap |= _CAP_SHORT_PREAMBLE | _CAP_SHORT_SLOT
    else:
        cap |= _CAP_SHORT_SLOT
    return cap


_HT_PAIRWISE = (
    b"\x00\x0f\xac\x04",  # CCMP
    b"\x00\x0f\xac\x08",  # GCMP-128
    b"\x00\x0f\xac\x09",  # GCMP-256
    b"\x00\x0f\xac\x0a",  # CCMP-256
)


def _clear_basic_rates(ie: bytes) -> bytes:
    """STA Supported Rates must not set the BSS-basic bit (0x80)."""
    if len(ie) < 2:
        return ie
    return bytes([ie[0], ie[1]]) + bytes(rate & 0x7F for rate in ie[2:])


def rsn_allows_ht(trailer_ies: bytes) -> bool:
    """HT Capabilities are invalid when the only pairwise cipher is TKIP."""
    if b"\x30" not in trailer_ies:
        return True
    return any(suite in trailer_ies for suite in _HT_PAIRWISE)


def assoc_req(bssid: bytes, our_mac: bytes, ssid: str, trailer_ies: bytes = b"",
              channel: int = 1, privacy: Optional[bool] = None,
              ht_capable: bool = True,
              capability_flags: Optional[Set[str]] = None,
              wmm: bool = False) -> bytes:
    """Association Request: band-aware rates, 20MHz HT caps, ESS+(auto)Privacy."""
    if privacy is None:
        has_rsn = b"\x30" in trailer_ies or b"\x00\x50\xf2\x01" in trailer_ies
        has_wps = b"\x00\x50\xf2\x04" in trailer_ies
        privacy = not (has_wps and not has_rsn)
    if ht_capable and not rsn_allows_ht(trailer_ies):
        ht_capable = False

    cap = struct.pack("<H", sta_capability(privacy, channel, capability_flags))
    listen = struct.pack("<H", 0x0001)
    ht = ht_cap_ie() if ht_capable else b""
    ies = (
        ssid_ie(ssid)
        + _clear_basic_rates(rates_ie(channel))
        + _clear_basic_rates(ext_rates_ie(channel))
        + ds_param_ie(channel)
        + ht
        + (WMM_INFO_IE if wmm else b"")
        + trailer_ies
    )
    return _hdr(b"\x00\x00", bssid, our_mac) + cap + listen + ies
