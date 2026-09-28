from wifit3.dot11.connectivity import build_arp_request
from wifit3.dot11.station_crypto import (
    CcmpStationCodec,
    WepStationCodec,
    _ccm_crypt,
    _ccm_mac,
    _xor_block,
)
from wifit3.wlan.quic import AES128


BSSID = bytes.fromhex("001122334455")
CLIENT = bytes.fromhex("66778899aabb")


def _frame() -> bytes:
    return build_arp_request(BSSID, CLIENT, "192.168.1.2", "192.168.1.1")


def test_wep_station_codec_round_trip_and_icv_rejection():
    codec = WepStationCodec(bytes.fromhex("0102030405"), initial_iv=0x010202)
    protected = codec.protect(_frame())

    assert protected[1] & 0x40
    assert codec.open(protected) == _frame()

    corrupted = protected[:-1] + bytes((protected[-1] ^ 1,))
    assert codec.open(corrupted) is None


def test_ccm_matches_rfc_3610_packet_vector_one():
    key = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    nonce = bytes.fromhex("00000003020100a0a1a2a3a4a5")
    aad = bytes.fromhex("0001020304050607")
    plaintext = bytes.fromhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
    aes = AES128(key)

    ciphertext = _ccm_crypt(aes, nonce, plaintext)
    s0 = aes.encrypt_block(b"\x01" + nonce + b"\x00\x00")
    tag = _xor_block(_ccm_mac(aes, nonce, aad, plaintext)[:8], s0[:8])

    assert ciphertext.hex() == "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"
    assert tag.hex() == "17e8d12cfdf926e0"


def test_ccmp_station_codec_round_trip_mic_and_replay_checks():
    codec = CcmpStationCodec(bytes(range(16)))
    protected = codec.protect(_frame())

    assert protected[1] & 0x40
    assert codec.open(protected) == _frame()
    assert codec.open(protected) is None

    second = codec.protect(_frame())
    corrupted = second[:-1] + bytes((second[-1] ^ 1,))
    assert codec.open(corrupted) is None
