"""Passive QUIC Initial SNI extraction (RFC 9000 / RFC 9001 / RFC 9369).

A QUIC client's first flight carries the TLS ClientHello inside CRYPTO frames of an
Initial packet.  Those frames are AEAD-protected, but the Initial keys are derived from
the *public* Destination Connection ID with a version-specific salt, so a passive
observer can decrypt them without any secret.  This module reproduces that derivation
(HKDF-SHA256), removes QUIC header protection (AES-128-ECB sample), decrypts the payload
(AES-128-GCM), reassembles the CRYPTO stream, and returns the ClientHello ``server_name``.

Only the (bounded, validated) SNI hostname is ever returned; no keys, connection IDs, or
payload bytes are retained or logged.  The AES/GHASH/HKDF primitives are hand-rolled here
to avoid a native ``cryptography`` dependency (the project bundles via PyInstaller and
already hand-rolls its WPA crypto); Initial packets are small and infrequent, so pure
Python is fast enough for live capture.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# Version-specific Initial salts.
_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")   # RFC 9001 §5.2
_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")   # RFC 9369 §3.3.1
_VERSION_V1 = 0x00000001
_VERSION_V2 = 0x6B3343CF

# Per-version HKDF-Expand-Label labels + the Initial packet long-header type value.
_PARAMS = {
    _VERSION_V1: (_SALT_V1, b"quic key", b"quic iv", b"quic hp", 0),
    _VERSION_V2: (_SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp", 1),
}

_MAX_COALESCED = 4          # long-header packets to walk within one datagram
_MAX_CRYPTO_BYTES = 16384   # cap on reassembled ClientHello

# ----- AES-128 (encrypt-only core) ------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


class AES128:
    """Minimal AES-128 block encryption (the only direction QUIC key removal needs)."""

    __slots__ = ("_rk",)

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 key must be 16 bytes")
        w = bytearray(key)
        for i in range(16, 176, 4):
            t = list(w[i - 4:i])
            if i % 16 == 0:
                t = [_SBOX[t[1]] ^ _RCON[i // 16 - 1], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            w += bytes(w[i - 16 + j] ^ t[j] for j in range(4))
        self._rk = bytes(w)

    def encrypt_block(self, block: bytes) -> bytes:
        s = list(block)
        rk = self._rk
        s = [s[i] ^ rk[i] for i in range(16)]
        for rnd in range(1, 10):
            s = [_SBOX[b] for b in s]
            s = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
            o = [0] * 16
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                o[4 * c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
                o[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
                o[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
                o[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
            base = 16 * rnd
            s = [o[i] ^ rk[base + i] for i in range(16)]
        s = [_SBOX[b] for b in s]
        s = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        return bytes(s[i] ^ rk[160 + i] for i in range(16))


# ----- AES-128-GCM -----------------------------------------------------------

def _gf_mult(x: int, y: int) -> int:
    """Multiply in GF(2^128) with the GCM reduction polynomial."""
    r = 0xE1 << 120
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        y = _gf_mult(y ^ int.from_bytes(block, "big"), h)
    return y


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + b"\x00" * (16 - rem)


def _gctr(aes: AES128, icb: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(icb, "big")
    for i in range(0, len(data), 16):
        keystream = aes.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
    return bytes(out)


def _gcm_tag(aes: AES128, h: int, iv12: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    lengths = struct.pack("!QQ", len(aad) * 8, len(ciphertext) * 8)
    s = _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths)
    j0 = iv12 + b"\x00\x00\x00\x01"
    return (s ^ int.from_bytes(aes.encrypt_block(j0), "big")).to_bytes(16, "big")


def gcm_decrypt(
    key: bytes, iv12: bytes, aad: bytes, ciphertext: bytes, tag: bytes,
) -> bytes | None:
    """AES-128-GCM open; returns plaintext only if the tag verifies."""
    aes = AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    if not hmac.compare_digest(_gcm_tag(aes, h, iv12, aad, ciphertext), tag):
        return None
    j0 = int.from_bytes(iv12 + b"\x00\x00\x00\x01", "big")
    icb = ((j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF)).to_bytes(16, "big")
    return _gctr(aes, icb, ciphertext)


def _gcm_encrypt(
    key: bytes, iv12: bytes, aad: bytes, plaintext: bytes,
) -> tuple[bytes, bytes]:
    """AES-128-GCM seal; returns (ciphertext, tag).  Used for round-trip tests."""
    aes = AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = int.from_bytes(iv12 + b"\x00\x00\x00\x01", "big")
    icb = ((j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF)).to_bytes(16, "big")
    ciphertext = _gctr(aes, icb, plaintext)
    return ciphertext, _gcm_tag(aes, h, iv12, aad, ciphertext)


# ----- HKDF (RFC 5869 / TLS 1.3 HKDF-Expand-Label) ---------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return hkdf_expand(secret, info, length)


def _client_initial_keys(dcid: bytes, version: int) -> tuple[bytes, bytes, bytes]:
    salt, key_label, iv_label, hp_label, _ = _PARAMS[version]
    initial_secret = hkdf_extract(salt, dcid)
    client_secret = hkdf_expand_label(initial_secret, b"client in", 32)
    return (
        hkdf_expand_label(client_secret, key_label, 16),
        hkdf_expand_label(client_secret, iv_label, 12),
        hkdf_expand_label(client_secret, hp_label, 16),
    )


# ----- QUIC packet parsing ---------------------------------------------------

def _varint(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise ValueError("varint out of range")
    length = 1 << (data[off] >> 6)
    if off + length > len(data):
        raise ValueError("varint truncated")
    value = data[off] & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[off + i]
    return value, length


def _client_hello_sni(handshake: bytes) -> bytes | None:
    """Return raw ``server_name`` bytes from a TLS ClientHello (no record layer)."""
    if len(handshake) < 4 or handshake[0] != 0x01:   # msg_type == client_hello
        return None
    length = int.from_bytes(handshake[1:4], "big")
    body = handshake[4:4 + length]
    off = 2 + 32                                     # client_version + random
    if off >= len(body):
        return None
    off += 1 + body[off]                             # legacy_session_id
    if off + 2 > len(body):
        return None
    off += 2 + int.from_bytes(body[off:off + 2], "big")   # cipher_suites
    if off + 1 > len(body):
        return None
    off += 1 + body[off]                             # compression_methods
    if off + 2 > len(body):
        return None
    ext_end = min(off + 2 + int.from_bytes(body[off:off + 2], "big"), len(body))
    off += 2
    while off + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", body[off:off + 4])
        off += 4
        if off + ext_len > ext_end:
            return None
        if ext_type == 0 and ext_len >= 5:           # server_name
            ext = body[off:off + ext_len]
            # server_name_list: list_len(2), then name_type(1) + name_len(2) + name
            if ext[2] == 0:                           # host_name
                name_len = int.from_bytes(ext[3:5], "big")
                if 5 + name_len <= len(ext):
                    return ext[5:5 + name_len]
            return None
        off += ext_len
    return None


def _collect_crypto(plaintext: bytes, chunks: dict[int, bytes]) -> None:
    """Walk decrypted QUIC frames, storing CRYPTO data by stream offset."""
    off = 0
    n = len(plaintext)
    while off < n:
        frame_type = plaintext[off]
        if frame_type == 0x00:                        # PADDING
            off += 1
            continue
        if frame_type == 0x01:                        # PING
            off += 1
            continue
        if frame_type in (0x02, 0x03):                # ACK
            off += 1
            try:
                for _ in range(3):                    # largest, delay, range_count seed
                    _, adv = _varint(plaintext, off)
                    off += adv
                _, adv = _varint(plaintext, off)      # first ack range
                off += adv
            except ValueError:
                return
            continue
        if frame_type == 0x06:                        # CRYPTO
            off += 1
            try:
                crypto_off, adv = _varint(plaintext, off)
                off += adv
                crypto_len, adv = _varint(plaintext, off)
                off += adv
            except ValueError:
                return
            if crypto_off < _MAX_CRYPTO_BYTES and 0 < crypto_len <= n - off:
                chunks[crypto_off] = plaintext[off:off + crypto_len]
            off += crypto_len
            continue
        return                                        # unknown frame: stop (can't skip safely)


def _assemble(chunks: dict[int, bytes]) -> bytes:
    out = bytearray()
    while True:
        chunk = chunks.get(len(out))
        if chunk is None:
            break
        out += chunk
        if len(out) >= _MAX_CRYPTO_BYTES:
            break
    return bytes(out)


def _open_initial(datagram: bytes, off: int) -> tuple[bytes | None, int]:
    """Decrypt one long-header packet at ``off``; return (plaintext_or_None, next_off)."""
    if off + 6 > len(datagram):
        return None, len(datagram)
    first = datagram[off]
    if first & 0xC0 != 0xC0:                          # long header + fixed bit
        return None, len(datagram)
    version = struct.unpack("!I", datagram[off + 1:off + 5])[0]
    params = _PARAMS.get(version)
    if params is None:
        return None, len(datagram)
    initial_type = params[4]
    pos = off + 5
    dcid_len = datagram[pos]
    pos += 1
    dcid = datagram[pos:pos + dcid_len]
    pos += dcid_len
    if pos >= len(datagram):
        return None, len(datagram)
    scid_len = datagram[pos]
    pos += 1 + scid_len
    is_initial = (first & 0x30) >> 4 == initial_type
    try:
        if is_initial:
            token_len, adv = _varint(datagram, pos)
            pos += adv + token_len
        length, adv = _varint(datagram, pos)
        pos += adv
    except (ValueError, IndexError):
        return None, len(datagram)
    pn_offset = pos
    packet_end = pn_offset + length
    if packet_end > len(datagram) or not is_initial or dcid_len > 20:
        return None, packet_end
    sample = datagram[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return None, packet_end
    key, iv, hp = _client_initial_keys(dcid, version)
    mask = AES128(hp).encrypt_block(sample)
    first_byte = first ^ (mask[0] & 0x0F)
    pn_len = (first_byte & 0x03) + 1
    pn_bytes = bytes(datagram[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    packet_number = int.from_bytes(pn_bytes, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    aad = bytes([first_byte]) + datagram[off + 1:pn_offset] + pn_bytes
    ct_and_tag = datagram[pn_offset + pn_len:packet_end]
    if len(ct_and_tag) < 16:
        return None, packet_end
    plaintext = gcm_decrypt(key, nonce, aad, ct_and_tag[:-16], ct_and_tag[-16:])
    return plaintext, packet_end


def extract_quic_sni(datagram: bytes) -> bytes | None:
    """Return the ClientHello ``server_name`` (raw bytes) from a QUIC Initial datagram.

    ``datagram`` is the UDP payload.  Returns ``None`` for anything that is not a
    decryptable v1/v2 Initial carrying a ClientHello SNI.  Never raises.
    """
    if len(datagram) < 6 or datagram[0] & 0xC0 != 0xC0:
        return None
    chunks: dict[int, bytes] = {}
    off = 0
    for _ in range(_MAX_COALESCED):
        if off >= len(datagram):
            break
        try:
            plaintext, off = _open_initial(datagram, off)
        except Exception:
            return None
        if plaintext is not None:
            _collect_crypto(plaintext, chunks)
            sni = _client_hello_sni(_assemble(chunks))
            if sni:
                return sni
    return None


def _seal_client_initial(
    dcid: bytes, client_hello: bytes, *, version: int = _VERSION_V1,
    packet_number: int = 0, pad_to: int = 0,
) -> bytes:
    """Build an encrypted client Initial carrying ``client_hello`` (round-trip test aid)."""
    key, iv, hp = _client_initial_keys(dcid, version)
    initial_type = _PARAMS[version][4]
    crypto = b"\x06\x00" + _encode_varint(len(client_hello)) + client_hello
    if pad_to:
        crypto += b"\x00" * max(0, pad_to - len(crypto))
    pn_bytes = packet_number.to_bytes(4, "big")
    header = (
        bytes([0xC0 | (initial_type << 4) | (len(pn_bytes) - 1)])
        + struct.pack("!I", version)
        + bytes([len(dcid)]) + dcid
        + b"\x00"                                     # zero-length SCID
        + b"\x00"                                     # zero-length token
        + _encode_varint(len(pn_bytes) + len(crypto) + 16)
        + pn_bytes
    )
    pn_offset = len(header) - len(pn_bytes)
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    ciphertext, tag = _gcm_encrypt(key, nonce, header, crypto)
    packet = bytearray(header + ciphertext + tag)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    mask = AES128(hp).encrypt_block(sample)
    packet[0] ^= mask[0] & 0x0F
    for i in range(len(pn_bytes)):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


def _encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)
