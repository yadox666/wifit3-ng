from wifit3.crack.mschapv2 import (
    attach_server_challenge,
    build_mschapv2_challenge,
    hashcat5500_challenge_line,
    hashcat5500_line,
    hashcat5600_line,
    is_complete_hashcat5500_line,
    is_complete_mschapv2_capture,
    mschapv2_challenge_hash,
    parse_mschapv2_challenge_payload,
    parse_mschapv2_eap_payload,
)


def test_hashcat5500_challenge_line_is_not_vault_complete():
    line = hashcat5500_challenge_line(
        "lab-probe@eap-lab.local",
        "bee8766b074f7aebed2e268e02d67173",
    )
    assert line.startswith("lab-probe@eap-lab.local:$MSCHAPv2$")
    assert "BEE8766B074F7AEBED2E268E02D67173" in line
    assert line.endswith("$")
    assert not is_complete_hashcat5500_line(line)


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
    assert line.startswith("CORP\\user::::")
    assert nt.hex() in line
    assert server.hex() not in line
    assert line.endswith(":" + mschapv2_challenge_hash(peer, server, "CORP\\user").hex())


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


def test_build_mschapv2_challenge_is_rfc2759():
    name = b"lab"
    body = build_mschapv2_challenge(3, b"\x11" * 16, name)
    assert body[0] == 1
    assert body[1] == 3
    assert int.from_bytes(body[2:4], "big") == 4 + 1 + 16 + len(name)
    assert body[4] == 16
    assert body[5:21] == b"\x11" * 16
    assert body[21:] == name


def test_parse_mschapv2_challenge_payload():
    server = bytes.fromhex("362DF946B8587DBEC3CAAFF838F48E5A")
    payload = build_mschapv2_challenge(2, server, b"CORP\\user")
    parsed = parse_mschapv2_challenge_payload(payload)
    assert parsed is not None
    assert parsed.mschap_id == 2
    assert parsed.server_challenge == server
    assert parsed.authenticator_name == "CORP\\user"


def test_parse_rfc_mschapv2_response():
    name = b"labuser"
    value = (b"\x22" * 16) + (b"\x00" * 8) + (b"\x33" * 24) + b"\x00"
    payload = (
        bytes([2, 1])
        + (4 + 1 + 49 + len(name)).to_bytes(2, "big")
        + bytes([49])
        + value
        + name
    )
    parsed = parse_mschapv2_eap_payload(payload)
    assert parsed is not None
    assert parsed.username == "labuser"
    assert parsed.peer_challenge == b"\x22" * 16
    assert parsed.nt_response == b"\x33" * 24


def test_parse_freeradius_rfc_mschapv2_challenge():
    server = bytes.fromhex("bee8766b074f7aebed2e268e02d67173")
    payload = bytes.fromhex(
        "01dd002610bee8766b074f7aebed2e268e02d67173667265657261646975732d332e322e3130"
    )
    parsed = parse_mschapv2_challenge_payload(payload)
    assert parsed is not None
    assert parsed.mschap_id == 0xDD
    assert parsed.server_challenge == server
    assert parsed.authenticator_name == "freeradius-3.2.10"


def test_rfc2759_challenge_hash_and_native_5500_line():
    server = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
    peer = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
    nt = bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
    assert mschapv2_challenge_hash(peer, server, "User") == bytes.fromhex(
        "D02E4386BCE91226"
    )
    capture = attach_server_challenge(
        parse_mschapv2_eap_payload(
            b"\x02\x01\x00\x31" + peer + b"\x00" * 8 + nt + b"\x00" + b"User"
        ),
        server,
    )
    assert capture is not None
    assert is_complete_mschapv2_capture(capture)
    line = hashcat5500_line(capture)
    assert line == f"User::::{nt.hex()}:d02e4386bce91226"
    assert is_complete_hashcat5500_line(line)


def test_empty_nt_response_is_not_complete():
    capture = attach_server_challenge(
        parse_mschapv2_eap_payload(
            b"\x02\x01\x00\x31" + b"\x22" * 16 + b"\x00" * 8 + b"\x00" * 24 + b"\x00" + b"labuser"
        ),
        b"\x11" * 16,
    )
    assert capture is not None
    assert not is_complete_mschapv2_capture(capture)
