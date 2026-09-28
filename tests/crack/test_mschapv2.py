from wifit3.crack.mschapv2 import (
    attach_server_challenge,
    build_mschapv2_challenge,
    hashcat5500_line,
    hashcat5600_line,
    parse_mschapv2_eap_payload,
)


def test_mschapv2_hashcat_line_uses_mode_5500_format():
    server = bytes.fromhex("362DF946B8587DBEC3CAAFF838F48E5A")
    peer = bytes.fromhex("00000000000000000000000000000000")
    nt = bytes.fromhex("D4CA571A" * 6)
    payload = (
        b"\x02\x01\x00\x31"
        + peer
        + b"\x00" * 8
        + nt
        + b"\x00"
        + b"CORP\\user"
    )
    parsed = parse_mschapv2_eap_payload(payload)
    assert parsed is not None
    parsed = attach_server_challenge(parsed, server)
    line = hashcat5500_line(parsed)
    assert line.startswith("CORP\\user:$MSCHAPv2$CORP\\user$")
    assert server.hex().upper() in line
    assert nt.hex().upper() in line


def test_hashcat5600_line_includes_peer_challenge_blob():
    capture = attach_server_challenge(
        parse_mschapv2_eap_payload(
            b"\x02\x01\x00\x31"
            + b"\x22" * 16
            + b"\x00" * 8
            + b"\x33" * 24
            + b"\x00"
            + b"CORP\\alice",
        ),
        b"\x11" * 16,
    )
    assert capture is not None
    line = hashcat5600_line(capture)
    assert line.startswith("alice::CORP:")
    assert ("22" * 16) in line


def test_build_mschapv2_challenge_is_16_bytes():
    challenge = build_mschapv2_challenge(3, b"\x11" * 16)
    assert challenge[0] == 1
    assert challenge[1] == 3
