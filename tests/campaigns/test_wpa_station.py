import asyncio
from types import SimpleNamespace

import pytest

from wifit3.campaigns.wpa_station import (
    WpaHandshakeError,
    WpaPskSupplicant,
    _decrypt_eapol_key_data,
    _parse_gtk_kdes,
)
from wifit3.crack.wpa_psk import eapol_mic, pmk, ptk
from wifit3.dot11.ap import eapol_m1
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header, eapol_key, set_mic
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.wsc.crypto import aes128_key_wrap


BSSID = bytes.fromhex("001122334455")
CLIENT = bytes.fromhex("66778899aabb")
ANONCE = bytes(range(32))


class _HandshakeIface:
    def __init__(self, actual_passphrase: str):
        self.callbacks = []
        self.actual_passphrase = actual_passphrase
        self.sent = []

    def register_rx_callback(self, callback):
        self.callbacks.append(callback)

    def unregister_rx_callback(self, callback):
        self.callbacks.remove(callback)

    def emit(self, raw):
        packet = SimpleNamespace(raw=raw, rssi=-40)
        for callback in list(self.callbacks):
            callback(packet)

    async def send_no_wait(self, frame):
        self.sent.append(frame)
        parsed = WlanFrameParser.parse_80211_frame(frame, -40)
        if parsed.msg_num == 2:
            pairwise = ptk(
                pmk(self.actual_passphrase, "TestNet"),
                BSSID,
                CLIENT,
                ANONCE,
                parsed.nonce,
            )
            payload = eapol_key(
                key_info=0x03CA,
                key_len=16,
                replay=2,
                nonce=ANONCE,
            )
            payload = set_mic(payload, eapol_mic(pairwise[:16], payload))
            self.emit(
                data_header(to_ds=False, bssid=BSSID, client=CLIENT)
                + LLC_SNAP_EAPOL
                + payload
            )
        return True


async def _run(supplied: str, actual: str):
    iface = _HandshakeIface(actual)
    supplicant = WpaPskSupplicant(
        iface,
        bssid=BSSID,
        client_mac=CLIENT,
        ssid="TestNet",
        passphrase=supplied,
        rsn_ie=GENERIC_RSN_IE,
        timeout=1,
    )
    task = asyncio.create_task(supplicant.run())
    await asyncio.sleep(0)
    iface.emit(eapol_m1(BSSID, CLIENT, ANONCE, replay=1))
    return await task, iface


async def test_wpa2_supplicant_completes_four_way_and_returns_ccmp_key():
    keys, iface = await _run("correct horse 9", "correct horse 9")

    assert len(keys.temporal_key) == 16
    assert [
        WlanFrameParser.parse_80211_frame(frame, -40).msg_num
        for frame in iface.sent
    ] == [2, 4]


async def test_wpa2_supplicant_rejects_wrong_captured_key():
    with pytest.raises(WpaHandshakeError, match="captured key is invalid"):
        await _run("PLACEHOLDER", "correct horse 9")


def test_parse_gtk_kde_extracts_ccmp_group_key():
    gtk = bytes(range(16))
    # 0xDD, len=22, OUI(00-0F-AC), DataType=1(GTK), KeyID=1, Reserved=0, GTK(16).
    kde = b"\xdd\x16\x00\x0f\xac\x01\x01\x00" + gtk
    assert _parse_gtk_kdes(kde) == {1: gtk}


def test_decrypt_eapol_key_data_unwraps_gtk_kde():
    kek = bytes(range(16))
    gtk = bytes(range(32, 48))
    kde = b"\xdd\x16\x00\x0f\xac\x01\x02\x00" + gtk
    # RFC 3394 wants an 8-byte multiple; pad the KDE stream with 0xDD then zeros.
    padded = kde + b"\xdd" + b"\x00" * ((8 - (len(kde) + 1) % 8) % 8)
    wrapped = aes128_key_wrap(kek, padded)
    payload = eapol_key(
        key_info=0x13CA,          # descriptor v2, encrypted key data (0x0800) set
        key_len=16,
        replay=3,
        nonce=bytes(32),
        key_data=wrapped,
    )
    plain = _decrypt_eapol_key_data(payload, kek, 0x13CA)
    assert _parse_gtk_kdes(plain) == {2: gtk}
