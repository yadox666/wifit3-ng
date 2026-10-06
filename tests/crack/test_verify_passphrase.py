"""verify_passphrase: the offline PSK check run on a candidate password against a
captured handshake. Uses a synthetic but cryptographically real M1+M2 handshake
so the MIC is genuine, not a fixture constant."""
from wifit3.crack import wpa_psk
from wifit3.crack.wpa_psk import verify_hc22000_line, verify_passphrase
from wifit3.crack.hc22000_format import eapol_hashlines
from wifit3.models import Handshake, HandshakeMessage

SSID = "AuditLab"
PSK = "correct horse battery"          # >= 8 chars, valid WPA2 passphrase
WRONG = "wrong horse battery!!"
BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"
ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))


def _mac(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _handshake(psk: str = PSK, *, keyver: int = 2) -> Handshake:
    """A real M1+M2 pair whose M2 MIC is computed from ``psk`` (so a correct
    guess verifies and any other fails), keyed by ``keyver``."""
    payload = bytearray(99)                 # 802.1X payload reaching past the MIC (81+16)
    payload[0] = 2                          # 802.1X version
    payload[1] = 3                          # type: EAPOL-Key
    payload[6] = keyver                     # Key Information low bits = descriptor version
    payload[17:17 + 32] = SNONCE            # Key Nonce (SNonce) at offset 17, as in a real M2
    # MIC computed over the payload with its MIC field zeroed.
    mic = wpa_psk.mic_for(
        psk, SSID, _mac(BSSID), _mac(CLIENT), ANONCE, SNONCE, bytes(payload),
    )
    payload[81:81 + 16] = mic               # the transmitted frame carries the MIC
    m1 = HandshakeMessage(
        raw=b"", msg_num=1, replay_hex=(1).to_bytes(8, "big").hex(),
        nonce=ANONCE, mic=b"\x00" * 16, key_data_len=0, eapol_payload=b"",
    )
    m2 = HandshakeMessage(
        raw=b"", msg_num=2, replay_hex=(1).to_bytes(8, "big").hex(),
        nonce=SNONCE, mic=mic, key_data_len=0, eapol_payload=bytes(payload),
    )
    hs = Handshake(bssid=BSSID, client_mac=CLIENT, beacon_frame=b"B")
    hs.messages.extend([m1, m2])
    return hs


def test_correct_passphrase_verifies():
    assert verify_passphrase(_handshake(), SSID, PSK) is True


def test_wrong_passphrase_rejected():
    assert verify_passphrase(_handshake(), SSID, WRONG) is False


def test_wrong_ssid_rejected():
    # SSID is salt for the PMK, so the right PSK under the wrong SSID fails.
    assert verify_passphrase(_handshake(), "OtherNet", PSK) is False


def test_no_crackable_pair_is_none():
    hs = Handshake(bssid=BSSID, client_mac=CLIENT, beacon_frame=b"B")
    assert verify_passphrase(hs, SSID, PSK) is None


def test_sha256_keystone_not_verifiable_is_none():
    # keyver 3 (PSK-SHA256 / AES-CMAC) is outside this SHA-1 path.
    assert verify_passphrase(_handshake(keyver=3), SSID, PSK) is None


def test_empty_inputs_are_none():
    hs = _handshake()
    assert verify_passphrase(hs, SSID, "") is None
    assert verify_passphrase(hs, "", PSK) is None


# ----- verify_hc22000_line (Vault-persisted handshake) -----------------------
def test_hc22000_line_correct_and_wrong():
    line = eapol_hashlines(SSID, _handshake())[0]
    assert verify_hc22000_line(line, PSK) is True
    assert verify_hc22000_line(line, WRONG) is False


def test_hc22000_line_ssid_override_for_pmk_salt():
    # The line carries SSID, but an explicit ssid overrides it as the PMK salt.
    line = eapol_hashlines(SSID, _handshake())[0]
    assert verify_hc22000_line(line, PSK, ssid=SSID) is True
    assert verify_hc22000_line(line, PSK, ssid="WrongSalt") is False


def test_hc22000_line_rejects_non_eapol_and_garbage():
    assert verify_hc22000_line("WPA*01*deadbeef*aa*bb*cc***", PSK) is None
    assert verify_hc22000_line("not a hashline", PSK) is None
    assert verify_hc22000_line("", PSK) is None
