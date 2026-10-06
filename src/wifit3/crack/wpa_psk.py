"""WPA/WPA2-PSK key derivation + the 4-way EAPOL MIC (no I/O).

PMK = PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32). PTK = PRF-512 over the sorted MAC pair and
sorted nonce pair. The MIC (key descriptor version 2, plain PSK) is HMAC-SHA1-128 over the
EAPOL payload with its MIC field zeroed, keyed by the KCK (PTK[:16]). Version 3 (PSK-SHA256,
AES-CMAC) is not implemented.

This module also verifies a *candidate passphrase* against a captured 4-way handshake
(:func:`verify_passphrase`): an offline check that a typed password matches the real PSK.
It is the same math a cracker uses (PMK → PTK → MIC), just with one guess instead of a
wordlist.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from wifit3.models import Handshake

_KCK_LEN = 16


def pmk(psk: str, ssid: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid.encode(), 4096, 32)


def _prf(key: bytes, label: bytes, data: bytes, nbytes: int) -> bytes:
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def ptk(pmk_bytes: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes,
        nbytes: int = 48) -> bytes:
    """AA = AP MAC, SPA = client MAC. Both the MAC pair and the nonce pair enter sorted, so
    the two peers derive the same PTK regardless of who is addressed first."""
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return _prf(pmk_bytes, b"Pairwise key expansion", data, nbytes)


def kck(ptk_bytes: bytes) -> bytes:
    return ptk_bytes[:_KCK_LEN]


def eapol_mic(kck_bytes: bytes, eapol_payload_mic_zeroed: bytes) -> bytes:
    return hmac.new(kck_bytes, eapol_payload_mic_zeroed, hashlib.sha1).digest()[:16]


def mic_for(psk: str, ssid: str, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes,
            eapol_payload_mic_zeroed: bytes) -> bytes:
    """The M2 MIC a client with this PSK would produce over these EAPOL bytes."""
    k = kck(ptk(pmk(psk, ssid), aa, spa, anonce, snonce))
    return eapol_mic(k, eapol_payload_mic_zeroed)


# ----- Offline passphrase verification against a captured handshake ----------
_MIC_OFFSET = 81                 # MIC position inside the 802.1X payload (see crack.handshake)
_MIC_LEN = 16
_KEY_INFO_OFFSET = 5             # 802.1X: 4-byte header, then 2-byte Key Information
_KEYVER_SHA1 = 2                 # HMAC-SHA1 MIC (plain WPA2-PSK) - the version we verify


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", "").lower())


def verify_passphrase(hs: "Handshake", ssid: str, psk: str) -> Optional[bool]:
    """Is ``psk`` the real passphrase for this captured 4-way handshake?

    Recomputes the keystone (M2/M4) MIC from ``psk`` and compares it, in constant
    time, to the MIC the client actually transmitted. Returns:

    * ``True``  - the passphrase matches (the network's real PSK),
    * ``False`` - a usable handshake exists but the passphrase is wrong,
    * ``None``  - no verifiable handshake (no crackable pair, truncated EAPOL, or
      an AES-CMAC / PSK-SHA256 keystone this SHA-1 path can't check).

    No secret is logged or persisted here; the caller decides what to do with the
    verdict. The math is identical to :func:`mic_for`, applied to the captured
    ANonce/SNonce/EAPOL rather than a live exchange.
    """
    if not psk or not ssid:
        return None
    # Deferred import: crack.handshake imports models, which import nothing here.
    from wifit3.crack.handshake import crackable_pairs

    pairs = crackable_pairs(hs)
    if not pairs:
        return None
    aa = _mac_bytes(hs.bssid)
    spa = _mac_bytes(hs.client_mac)
    pmk_bytes = pmk(psk, ssid)
    verifiable = False
    for pair in pairs:
        mic_frame = pair.mic_frame
        payload = mic_frame.eapol_payload
        if len(payload) < _MIC_OFFSET + _MIC_LEN:
            continue
        # Only the HMAC-SHA1 key-descriptor version is verifiable here.
        if len(payload) >= _KEY_INFO_OFFSET + 1:
            keyver = payload[_KEY_INFO_OFFSET + 1] & 0x07
            if keyver and keyver != _KEYVER_SHA1:
                continue
        verifiable = True
        zeroed = bytearray(payload)
        zeroed[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN] = b"\x00" * _MIC_LEN
        derived = eapol_mic(
            kck(ptk(pmk_bytes, aa, spa, pair.anonce_frame.nonce, mic_frame.nonce)),
            bytes(zeroed),
        )
        if hmac.compare_digest(derived, mic_frame.mic[:_MIC_LEN]):
            return True
    return False if verifiable else None


_SNONCE_OFFSET = 17              # SNonce start inside the 802.1X payload (see crack.handshake)
_NONCE_LEN = 32


def verify_hc22000_line(line: str, psk: str, ssid: str | None = None) -> Optional[bool]:
    """Verify ``psk`` against a persisted hashcat ``WPA*02*…`` line (a Vault capture).

    Confirms a typed password against a handshake saved in a prior session without
    re-capturing one. ``ssid`` overrides the line's ESSID field for
    the PMK salt (use the real target SSID). Returns True/False/None like
    :func:`verify_passphrase`. PMKID (``WPA*01``) lines return None (unhandled).
    """
    if not psk or not line:
        return None
    parts = line.strip().split("*")
    if len(parts) < 8 or parts[0].upper() != "WPA" or parts[1] != "02":
        return None
    try:
        mic = bytes.fromhex(parts[2])
        aa = bytes.fromhex(parts[3])
        spa = bytes.fromhex(parts[4])
        essid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
        anonce = bytes.fromhex(parts[6])
        eapol = bytes.fromhex(parts[7])            # MIC field already zeroed by the writer
    except ValueError:
        return None
    salt = ssid or essid
    if not salt or len(eapol) < _MIC_OFFSET + _MIC_LEN or len(anonce) != _NONCE_LEN:
        return None
    if len(eapol) >= _KEY_INFO_OFFSET + 1:
        keyver = eapol[_KEY_INFO_OFFSET + 1] & 0x07
        if keyver and keyver != _KEYVER_SHA1:
            return None
    snonce = eapol[_SNONCE_OFFSET:_SNONCE_OFFSET + _NONCE_LEN]
    zeroed = bytearray(eapol)
    zeroed[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN] = b"\x00" * _MIC_LEN
    derived = eapol_mic(kck(ptk(pmk(psk, salt), aa, spa, anonce, snonce)), bytes(zeroed))
    return hmac.compare_digest(derived, mic[:_MIC_LEN])
