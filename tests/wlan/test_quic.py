"""Known-answer + round-trip tests for the hand-rolled QUIC Initial SNI extractor."""
import struct

from wifit3.wlan import quic


def _client_hello(host: bytes) -> bytes:
    """Minimal TLS 1.3 ClientHello (no record layer, as QUIC CRYPTO carries it)."""
    sni = b"\x00" + struct.pack("!H", len(host)) + host          # host_name entry
    sni_list = struct.pack("!H", len(sni)) + sni
    ext = struct.pack("!HH", 0, len(sni_list)) + sni_list        # server_name extension
    exts = struct.pack("!H", len(ext)) + ext
    body = (
        b"\x03\x03" + b"\x00" * 32                               # version + random
        + b"\x00"                                                # legacy_session_id
        + struct.pack("!H", 2) + b"\x13\x01"                     # cipher_suites
        + b"\x01\x00"                                            # compression_methods
        + exts
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def test_aes128_fips197_block_vector():
    aes = quic.AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    out = aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert out.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes128_gcm_mcgrew_test_case_3():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    )
    ciphertext = bytes.fromhex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
    )
    tag = bytes.fromhex("4d5c2af327cd64a62cf35abd2ba6fab4")
    assert quic.gcm_decrypt(key, iv, b"", ciphertext, tag) == plaintext
    # A wrong tag must be rejected (no plaintext leaked).
    assert quic.gcm_decrypt(key, iv, b"", ciphertext, bytes(16)) is None


def test_hkdf_rfc5869_test_case_1():
    prk = quic.hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("0b" * 22))
    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    okm = quic.hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_quic_v1_initial_round_trip_extracts_sni():
    packet = quic._seal_client_initial(
        bytes.fromhex("8394c8f03e515708"), _client_hello(b"example.com"), pad_to=1200,
    )
    assert quic.extract_quic_sni(packet) == b"example.com"


def test_quic_v2_initial_round_trip_extracts_sni():
    packet = quic._seal_client_initial(
        bytes.fromhex("8394c8f03e515708"), _client_hello(b"cdn.example.org"),
        version=quic._VERSION_V2, packet_number=1,
    )
    assert quic.extract_quic_sni(packet) == b"cdn.example.org"


def test_non_quic_payloads_return_none():
    assert quic.extract_quic_sni(b"") is None
    assert quic.extract_quic_sni(b"\x00\x01\x02\x03\x04\x05") is None
    assert quic.extract_quic_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    # Long-header first byte but an unknown version: not decryptable, must not raise.
    assert quic.extract_quic_sni(b"\xc0\xde\xad\xbe\xef" + b"\x00" * 64) is None
