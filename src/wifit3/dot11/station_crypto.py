"""Software WEP and CCMP protection for Fake-Connect station traffic."""
from __future__ import annotations

import hmac
import secrets
import struct
import zlib

from wifit3.wlan.quic import AES128


def _header_length(frame: bytes) -> int:
    if len(frame) < 24:
        raise ValueError("802.11 frame is shorter than its MAC header")
    fc0, fc1 = frame[0], frame[1]
    length = 30 if fc1 & 0x03 == 0x03 else 24
    if ((fc0 >> 4) & 0x08) != 0:
        length += 2
        if fc1 & 0x80:
            length += 4
    return length


def _is_data(frame: bytes) -> bool:
    return len(frame) >= 24 and frame[0] & 0x0C == 0x08


def _rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


class WepStationCodec:
    """Protect and open ordinary three-address WEP data frames."""

    def __init__(self, key: bytes, *, initial_iv: int | None = None) -> None:
        if len(key) not in (5, 13, 16):
            raise ValueError("WEP key must contain 5, 13, or 16 bytes")
        self.key = bytes(key)
        self._tx_iv = (
            secrets.randbelow(1 << 24) if initial_iv is None else initial_iv & 0xFFFFFF
        )

    def protect(self, frame: bytes) -> bytes:
        if not _is_data(frame) or frame[1] & 0x40:
            return frame
        header_len = _header_length(frame)
        header = bytearray(frame[:header_len])
        header[1] |= 0x40
        self._tx_iv = (self._tx_iv + 1) & 0xFFFFFF
        iv = self._tx_iv.to_bytes(3, "big")
        plaintext = frame[header_len:]
        icv = struct.pack("<I", zlib.crc32(plaintext) & 0xFFFFFFFF)
        ciphertext = _rc4(iv + self.key, plaintext + icv)
        return bytes(header) + iv + b"\x00" + ciphertext

    def open(self, frame: bytes) -> bytes | None:
        if not _is_data(frame) or not frame[1] & 0x40:
            return frame
        header_len = _header_length(frame)
        if len(frame) < header_len + 8:
            return None
        iv = frame[header_len:header_len + 3]
        key_id = frame[header_len + 3]
        if key_id & 0x20:
            return None
        plaintext_icv = _rc4(iv + self.key, frame[header_len + 4:])
        if len(plaintext_icv) < 4:
            return None
        plaintext, received_icv = plaintext_icv[:-4], plaintext_icv[-4:]
        expected_icv = struct.pack("<I", zlib.crc32(plaintext) & 0xFFFFFFFF)
        if not hmac.compare_digest(received_icv, expected_icv):
            return None
        header = bytearray(frame[:header_len])
        header[1] &= ~0x40
        return bytes(header) + plaintext


def _xor_block(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _ccm_mac(aes: AES128, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    b0 = b"\x59" + nonce + len(plaintext).to_bytes(2, "big")
    blocks = bytearray(b0)
    encoded_aad = len(aad).to_bytes(2, "big") + aad
    encoded_aad += b"\x00" * (-len(encoded_aad) % 16)
    blocks += encoded_aad
    blocks += plaintext + b"\x00" * (-len(plaintext) % 16)
    state = b"\x00" * 16
    for offset in range(0, len(blocks), 16):
        state = aes.encrypt_block(_xor_block(state, blocks[offset:offset + 16]))
    return state


def _ccm_crypt(aes: AES128, nonce: bytes, data: bytes) -> bytes:
    output = bytearray()
    for block_number, offset in enumerate(range(0, len(data), 16), start=1):
        stream = aes.encrypt_block(
            b"\x01" + nonce + block_number.to_bytes(2, "big"),
        )
        output += _xor_block(data[offset:offset + 16], stream)
    return bytes(output)


def _ccmp_aad(frame: bytes, header_len: int) -> tuple[bytes, int]:
    fc0, fc1 = frame[0], frame[1]
    aad = bytearray((fc0 & 0x8F, fc1 & 0xC7))
    aad += frame[4:22]
    sequence = int.from_bytes(frame[22:24], "little") & 0x000F
    aad += sequence.to_bytes(2, "little")
    priority = 0
    if header_len >= 26 and ((fc0 >> 4) & 0x08):
        priority = frame[24] & 0x0F
        aad += bytes((priority, 0))
    return bytes(aad), priority


def _ccmp_nonce(frame: bytes, priority: int, packet_number: int) -> bytes:
    return (
        bytes((priority,))
        + frame[10:16]
        + packet_number.to_bytes(6, "little")[::-1]
    )


class CcmpStationCodec:
    """CCMP-128 data protection with replay checks and optional group keys."""

    def __init__(self, pairwise_key: bytes, *, initial_pn: int = 0) -> None:
        if len(pairwise_key) != 16:
            raise ValueError("CCMP temporal key must contain 16 bytes")
        self.pairwise_key = bytes(pairwise_key)
        self.group_keys: dict[int, bytes] = {}
        self._tx_pn = initial_pn
        self._rx_pn: dict[tuple[bytes, int], int] = {}

    def install_group_key(self, key_id: int, key: bytes) -> None:
        if len(key) != 16 or key_id not in range(4):
            raise ValueError("invalid CCMP group key")
        self.group_keys[key_id] = bytes(key)

    def protect(self, frame: bytes) -> bytes:
        if not _is_data(frame) or frame[1] & 0x40:
            return frame
        header_len = _header_length(frame)
        header = bytearray(frame[:header_len])
        header[1] |= 0x40
        self._tx_pn += 1
        pn = self._tx_pn
        pn_bytes = pn.to_bytes(6, "little")
        ccmp_header = bytes((
            pn_bytes[0], pn_bytes[1], 0, 0x20,
            pn_bytes[2], pn_bytes[3], pn_bytes[4], pn_bytes[5],
        ))
        aad, priority = _ccmp_aad(bytes(header), header_len)
        nonce = _ccmp_nonce(bytes(header), priority, pn)
        plaintext = frame[header_len:]
        aes = AES128(self.pairwise_key)
        ciphertext = _ccm_crypt(aes, nonce, plaintext)
        s0 = aes.encrypt_block(b"\x01" + nonce + b"\x00\x00")
        mic = _xor_block(_ccm_mac(aes, nonce, aad, plaintext)[:8], s0[:8])
        return bytes(header) + ccmp_header + ciphertext + mic

    def open(self, frame: bytes) -> bytes | None:
        if not _is_data(frame) or not frame[1] & 0x40:
            return frame
        header_len = _header_length(frame)
        if len(frame) < header_len + 16:
            return None
        ccmp = frame[header_len:header_len + 8]
        if not ccmp[3] & 0x20:
            return None
        key_id = (ccmp[3] >> 6) & 0x03
        pn_bytes = bytes((ccmp[0], ccmp[1], ccmp[4], ccmp[5], ccmp[6], ccmp[7]))
        pn = int.from_bytes(pn_bytes, "little")
        replay_key = (bytes(frame[10:16]), key_id)
        if pn <= self._rx_pn.get(replay_key, -1):
            return None
        key = self.group_keys.get(key_id) if key_id else self.pairwise_key
        if key is None:
            return None
        aad, priority = _ccmp_aad(frame, header_len)
        nonce = _ccmp_nonce(frame, priority, pn)
        ciphertext, received_mic = frame[header_len + 8:-8], frame[-8:]
        aes = AES128(key)
        plaintext = _ccm_crypt(aes, nonce, ciphertext)
        s0 = aes.encrypt_block(b"\x01" + nonce + b"\x00\x00")
        expected_mic = _xor_block(
            _ccm_mac(aes, nonce, aad, plaintext)[:8], s0[:8],
        )
        if not hmac.compare_digest(received_mic, expected_mic):
            return None
        self._rx_pn[replay_key] = pn
        header = bytearray(frame[:header_len])
        header[1] &= ~0x40
        return bytes(header) + plaintext
