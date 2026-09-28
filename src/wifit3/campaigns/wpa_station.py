"""Minimal WPA2-PSK supplicant for Fake-Connect's protected data path."""
from __future__ import annotations

import asyncio
import hmac
import os
import struct
import time
from dataclasses import dataclass, field

from wifit3.crack.wpa_psk import eapol_mic, pmk, ptk
from wifit3.dot11.ie import iter_information_elements
from wifit3.dot11.wsc.crypto import aes128_key_unwrap
from wifit3.dot11.eapol import (
    LLC_SNAP_EAPOL,
    data_header,
    eapol_key,
    set_mic,
)
from wifit3.dot11.parser import WlanFrameParser


_PAIRWISE = 0x0008
_MIC = 0x0100
_SECURE = 0x0200
_ENCRYPTED_KEY_DATA = 0x1000        # Key Info bit 12 (Encrypted Key Data)
_CCMP_KEY_LEN = 16


@dataclass(frozen=True, slots=True)
class WpaStationKeys:
    temporal_key: bytes
    kck: bytes
    kek: bytes
    group_keys: dict[int, bytes] = field(default_factory=dict)


def _eapol_key_data_field(payload: bytes) -> bytes:
    if len(payload) < 99:
        return b""
    kd_len = struct.unpack(">H", payload[97:99])[0]
    end = 99 + kd_len
    if end > len(payload):
        return b""
    return payload[99:end]


def _decrypt_eapol_key_data(payload: bytes, kek: bytes, key_info: int) -> bytes:
    """Return the plaintext EAPOL Key Data. For WPA2 (key descriptor version 2)
    the field is NIST-AES-key-wrapped (RFC 3394) under the KEK; unwrapping also
    authenticates it (wrong KEK -> None -> empty)."""
    key_data = _eapol_key_data_field(payload)
    if not key_data:
        return b""
    if not (key_info & _ENCRYPTED_KEY_DATA):
        return key_data
    unwrapped = aes128_key_unwrap(kek, key_data)
    return unwrapped if unwrapped is not None else b""


def _parse_gtk_kdes(key_data: bytes) -> dict[int, bytes]:
    """GTK KDEs from decrypted WPA2 message 3 Key Data."""
    keys: dict[int, bytes] = {}
    for kde_type, val, _raw in iter_information_elements(key_data):
        # GTK KDE: OUI(3) + DataType(1=GTK) + KeyID/Tx(1) + Reserved(1) + GTK(16/32).
        if kde_type != 0xDD or len(val) < 22:
            continue
        if val[:3] != b"\x00\x0f\xac" or val[3] != 0x01:
            continue
        key_id = val[4] & 0x03
        gtk = val[6:]
        if len(gtk) not in (16, 32):
            continue
        keys[key_id] = bytes(gtk[:16])
    return keys


class WpaHandshakeError(RuntimeError):
    pass


class WpaPskSupplicant:
    """Complete the WPA2-PSK 4-way handshake and return the pairwise CCMP key."""

    def __init__(
        self,
        iface,
        *,
        bssid: bytes,
        client_mac: bytes,
        ssid: str,
        passphrase: str,
        rsn_ie: bytes,
        should_stop=None,
        timeout: float = 8.0,
    ) -> None:
        self.iface = iface
        self.bssid = bssid
        self.client_mac = client_mac
        self.ssid = ssid
        self.passphrase = passphrase
        self.rsn_ie = rsn_ie
        self.should_stop = should_stop or (lambda: False)
        self.timeout = timeout
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._loop = asyncio.get_running_loop()

    def _rx(self, packet) -> None:
        raw = bytes(getattr(packet, "raw", b""))
        if len(raw) < 24 or raw[4:10] != self.client_mac or raw[10:16] != self.bssid:
            return
        parsed = WlanFrameParser.parse_80211_frame(raw, getattr(packet, "rssi", -50))
        if getattr(parsed, "type", None) == "eapol":
            self._loop.call_soon_threadsafe(self._put, parsed)

    def _put(self, packet) -> None:
        if not self._queue.full():
            self._queue.put_nowait(packet)

    async def _next(self, msg_num: int, deadline: float):
        while not self.should_stop():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                packet = await asyncio.wait_for(self._queue.get(), remaining)
            except asyncio.TimeoutError:
                return None
            if packet.msg_num == msg_num:
                return packet
        return None

    async def run(self) -> WpaStationKeys:
        self.iface.register_rx_callback(self._rx)
        try:
            deadline = time.monotonic() + self.timeout
            m1 = await self._next(1, deadline)
            if m1 is None:
                raise WpaHandshakeError("no WPA2 message 1 received")
            descriptor_version = (m1.key_info or 0) & 0x0007
            if descriptor_version != 2:
                raise WpaHandshakeError(
                    f"unsupported WPA key descriptor version {descriptor_version}",
                )
            if not m1.nonce or not m1.replay_counter:
                raise WpaHandshakeError("WPA2 message 1 omitted nonce or replay counter")
            anonce = m1.nonce
            replay = int.from_bytes(m1.replay_counter, "big")
            snonce = os.urandom(32)
            pairwise = ptk(
                pmk(self.passphrase, self.ssid),
                self.bssid,
                self.client_mac,
                anonce,
                snonce,
            )
            kck, kek, temporal_key = pairwise[:16], pairwise[16:32], pairwise[32:48]
            m2_info = descriptor_version | _PAIRWISE | _MIC
            m2 = eapol_key(
                key_info=m2_info,
                key_len=_CCMP_KEY_LEN,
                replay=replay,
                nonce=snonce,
                key_data=self.rsn_ie,
            )
            m2 = set_mic(m2, eapol_mic(kck, m2))
            m2_frame = (
                data_header(to_ds=True, bssid=self.bssid, client=self.client_mac)
                + LLC_SNAP_EAPOL
                + m2
            )
            await self.iface.send_no_wait(m2_frame)

            m3 = await self._next(3, deadline)
            if m3 is None:
                raise WpaHandshakeError("no WPA2 message 3 received; captured key may be wrong")
            if m3.nonce != anonce:
                raise WpaHandshakeError("WPA2 message 3 changed the authenticator nonce")
            m3_replay = int.from_bytes(m3.replay_counter or b"", "big")
            if m3_replay < replay or not m3.payload or not m3.mic:
                raise WpaHandshakeError("invalid WPA2 message 3")
            unsigned_m3 = set_mic(m3.payload, bytes(16))
            if not hmac.compare_digest(m3.mic, eapol_mic(kck, unsigned_m3)):
                raise WpaHandshakeError("WPA2 message 3 MIC rejected; captured key is invalid")

            m4_info = descriptor_version | _PAIRWISE | _MIC | _SECURE
            m4 = eapol_key(
                key_info=m4_info,
                key_len=_CCMP_KEY_LEN,
                replay=m3_replay,
                nonce=bytes(32),
            )
            m4 = set_mic(m4, eapol_mic(kck, m4))
            m4_frame = (
                data_header(to_ds=True, bssid=self.bssid, client=self.client_mac)
                + LLC_SNAP_EAPOL
                + m4
            )
            await self.iface.send_no_wait(m4_frame)
            plain_kd = _decrypt_eapol_key_data(m3.payload, kek, m3.key_info or 0)
            return WpaStationKeys(
                temporal_key, kck, kek, _parse_gtk_kdes(plain_kd),
            )
        finally:
            self.iface.unregister_rx_callback(self._rx)
