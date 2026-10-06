import struct


from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.packet import (
    WepDataPacket, BeaconPacket, AuthPacket, AssocRespPacket, DeauthPacket, ProbeReqPacket,
)


# ---- Beacon builder for RSN-IE tests ---------------------------------------

def _build_beacon(
    *,
    ssid: str = "TestNet",
    timestamp_us: int = 0,
    rsn_ie: bytes = b"",
    wpa_vendor_ie: bytes = b"",
    privacy_bit: bool = False,
) -> bytes:
    """Build a minimally valid 802.11 beacon. Tag 0 (SSID) is always first;
    Tag 1 (Supported Rates) follows because _is_valid_frame requires it."""
    fc = b"\x80\x00"
    dur = b"\x00\x00"
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr2 = b"\x11\x22\x33\x44\x55\x66"
    addr3 = addr2
    seq = b"\x00\x00"
    mac_hdr = fc + dur + addr1 + addr2 + addr3 + seq

    # Fixed params: 8 B timestamp + 2 B beacon interval + 2 B capabilities.
    cap_info = 0x0001  # ESS (bit 0)
    if privacy_bit:
        cap_info |= 0x0010  # Privacy (bit 4)
    fixed = struct.pack("<Q", timestamp_us) + b"\x64\x00" + struct.pack("<H", cap_info)

    ssid_bytes = ssid.encode("utf-8")
    tag_ssid = bytes([0x00, len(ssid_bytes)]) + ssid_bytes
    tag_rates = b"\x01\x04\x82\x84\x8b\x96"  # 1, 2, 5.5, 11

    return mac_hdr + fixed + tag_ssid + tag_rates + rsn_ie + wpa_vendor_ie


def _rsn_ie(
    *,
    group_cipher: int = 0x04,       # CCMP
    pairwise_ciphers=(0x04,),       # CCMP
    akms=(0x02,),                   # PSK
    rsn_caps: int = 0,
) -> bytes:
    """Build a tag-48 RSN IE (incl. the 2-byte tag header)."""
    body = b"\x01\x00"  # Version = 1
    body += b"\x00\x0f\xac" + bytes([group_cipher])
    body += struct.pack("<H", len(pairwise_ciphers))
    for c in pairwise_ciphers:
        body += b"\x00\x0f\xac" + bytes([c])
    body += struct.pack("<H", len(akms))
    for a in akms:
        body += b"\x00\x0f\xac" + bytes([a])
    body += struct.pack("<H", rsn_caps)
    return bytes([48, len(body)]) + body


def _wps_ie(*, locked: bool = False, version2: bool = False,
            configured: bool = True, manufacturer: bytes = b"",
            model_name: bytes = b"", model_number: bytes = b"",
            device_name: bytes = b"", serial_number: bytes = b"") -> bytes:
    """Build a WPS vendor IE (tag 221, OUI 00:50:F2, OUI-type 4) with the
    nested big-endian TLVs. AP Setup Locked is always emitted (as real APs
    do) so both the locked and unlocked decode paths are exercised."""
    def tlv(attr: int, val: bytes) -> bytes:
        return struct.pack(">HH", attr, len(val)) + val

    body = tlv(0x104A, b"\x10")                                   # Version 1.0
    body += tlv(0x1044, b"\x02" if configured else b"\x01")      # Setup State
    body += tlv(0x1057, b"\x01" if locked else b"\x00")          # AP Setup Locked
    body += tlv(0x1008, b"\x00\x84")                             # Config Methods
    body += tlv(0x1012, b"\x00\x00")                             # Device Password ID (PIN)
    body += tlv(0x1047, bytes(range(16)))                         # UUID-E
    body += tlv(0x103C, b"\x03")                                 # RF bands
    body += tlv(0x102D, b"\x80\x00\x00\x01")                     # OS version
    body += tlv(0x103B, b"\x03")                                 # Response type
    if manufacturer:
        body += tlv(0x1021, manufacturer)
    if model_name:
        body += tlv(0x1023, model_name)
    if model_number:
        body += tlv(0x1024, model_number)
    if device_name:
        body += tlv(0x1011, device_name)
    if serial_number:
        body += tlv(0x1042, serial_number)
    if version2:
        body += tlv(0x1049, b"\x00\x37\x2a" + b"\x00\x01\x20")  # Vendor Ext → Version2
    payload = b"\x00\x50\xf2\x04" + body
    return bytes([0xDD, len(payload)]) + payload


def test_wps_open_beacon():
    r = WlanFrameParser.parse_80211_frame(
        _build_beacon(wpa_vendor_ie=_wps_ie(locked=False)), -50)
    assert r.wps is True
    assert r.wps_locked is False
    assert r.wps_version == "1.0"
    assert r.wps_state == 2
    assert r.wps_uuid_e == bytes(range(16)).hex()
    assert r.wps_rf_bands == 3
    assert r.wps_os_version == 0x80000001
    assert r.wps_response_type == 3


def test_beacon_timestamp_is_parsed_as_ap_uptime_microseconds():
    r = WlanFrameParser.parse_80211_frame(
        _build_beacon(timestamp_us=3_723_000_000), -50,
    )
    assert r.timestamp_us == 3_723_000_000


def test_beacon_advertised_country_is_parsed():
    country_ie = b"\x07\x06US " + bytes([1, 11, 20])
    r = WlanFrameParser.parse_80211_frame(_build_beacon() + country_ie, -50)
    assert r.country_code == "US"
    assert r.capabilities.country_environment == "any"


def test_malformed_country_code_is_ignored():
    country_ie = b"\x07\x06u1 " + bytes([1, 11, 20])
    r = WlanFrameParser.parse_80211_frame(_build_beacon() + country_ie, -50)
    assert r.country_code is None


def test_beacon_extracts_advertised_radio_load_roaming_and_discovery_fields():
    tim = bytes([5, 4, 0, 3, 0, 0])
    bss_load = bytes([11, 5]) + struct.pack("<HBH", 12, 128, 300)
    power = bytes([32, 1, 4])
    ht = bytes([45, 26]) + b"\x02\x00\x00\xff\xff" + b"\x00" * 21
    mobility = bytes([54, 3, 1, 2, 3])
    rm = bytes([70, 1, 1])
    multi_bssid = bytes([71, 1, 2])
    vht_map = sum(0 if stream < 2 else 3 << (stream * 2) for stream in range(8))
    vht = bytes([191, 12]) + struct.pack("<IH", 0x04, vht_map) + b"\x00" * 6
    ext = bytes([127, 11]) + b"\x00\x00\x08" + b"\x00" * 7 + b"\x10"
    rnr = bytes([201, 1, 0])
    wmm = bytes.fromhex("DD060050F2020101")
    he = bytes([255, 1, 35])
    eht = bytes([255, 1, 108])
    mlo = bytes([255, 1, 107])
    frame = (
        _build_beacon(timestamp_us=1_000_000) + tim + bss_load + power + ht
        + mobility + rm + multi_bssid + vht + ext + rnr + wmm + he + eht + mlo
    )
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    caps = parsed.capabilities
    assert caps.beacon_interval_tu == 100
    assert caps.capability_flags == {"ESS"}
    assert caps.dtim_period == 3
    assert (caps.station_count, caps.channel_utilization, caps.admission_capacity) == (12, 128, 300)
    assert caps.power_constraint_db == 4
    assert caps.phy_modes == {"802.11n", "802.11ac", "802.11ax", "802.11be"}
    assert caps.channel_widths_mhz == {20, 40, 80, 160}
    assert caps.max_spatial_streams == 2
    assert caps.fast_transition and caps.radio_measurement and caps.bss_transition
    assert caps.wmm and caps.multi_bssid and caps.reduced_neighbor_report and caps.multi_link
    assert "00:50:F2" in caps.vendor_ouis


def test_wps_locked_beacon():
    r = WlanFrameParser.parse_80211_frame(
        _build_beacon(wpa_vendor_ie=_wps_ie(locked=True)), -50)
    assert r.wps is True
    assert r.wps_locked is True


def test_wps_version2_beacon():
    r = WlanFrameParser.parse_80211_frame(
        _build_beacon(wpa_vendor_ie=_wps_ie(version2=True)), -50)
    assert r.wps is True
    assert r.wps_version == "2.0"


def test_wps_identity_fields_beacon():
    r = WlanFrameParser.parse_80211_frame(_build_beacon(wpa_vendor_ie=_wps_ie(
        manufacturer=b"MikroTik", model_name=b"RouterBOARD", model_number=b"RB951",
        device_name=b"Office AP\x00", serial_number=b"SERIAL-1",
    )), -50)
    assert r.wsc_manufacturer == "MikroTik"
    assert r.wsc_model_name == "RouterBOARD"
    assert r.wsc_model_number == "RB951"
    assert r.wsc_device_name == "Office AP"
    assert r.wsc_serial_number == "SERIAL-1"


def test_no_wps_ie_absent():
    r = WlanFrameParser.parse_80211_frame(
        _build_beacon(rsn_ie=_rsn_ie()), -50)
    assert not r.wps

def test_wlan_frame_parser_validates():
    # A random bunch of bytes too small to be a frame
    assert WlanFrameParser.parse_80211_frame(b'\x00\x01\x02', -50) is None

def test_wlan_frame_parser_ignores_second_ssid_ie():
    """Spec: SSID IE is mandatory and FIRST. Any later tag-0 we encounter
    while walking IEs is malformed-frame OR (more commonly) the walker
    straying into trailing bytes (unstripped FCS, hw metadata). Either way
    we must NOT overwrite the canonical SSID with that junk.

    Regression for the AR9271-FCS-leak bug: a hidden beacon would
    occasionally "decloak" to short random strings like "F" / "7" / "/:"
    because the trailing CRC32 bytes happened to look like `00 02 2f 3a`.
    """
    fc = b"\x80\x00"
    dur = b"\x00\x00"
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr2 = b"\x11\x22\x33\x44\x55\x66"
    mac_hdr = fc + dur + addr1 + addr2 + addr2 + b"\x00\x00"
    fixed = b"\x00" * 12

    legit_hidden_ssid = b"\x00\x00"       # SSID IE: length 0 → hidden
    rates = b"\x01\x04\x82\x84\x8b\x96"
    bogus_late_ssid = b"\x00\x02/:"       # exactly the bytes that bit us

    frame = mac_hdr + fixed + legit_hidden_ssid + rates + bogus_late_ssid

    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed is not None
    # Stays "<hidden>". The late tag-0 must be ignored.
    assert parsed.ssid == "<hidden>"


def test_wlan_frame_parser_extracts_ssid():
    # Construct a minimal fake beacon frame to test tag parsing
    # MAC Header (24 bytes)
    fc = b'\x80\x00' # Beacon
    dur = b'\x00\x00'
    addr1 = b'\xff\xff\xff\xff\xff\xff'
    addr2 = b'\x11\x22\x33\x44\x55\x66'
    addr3 = b'\x11\x22\x33\x44\x55\x66'
    seq = b'\x00\x00'
    mac_hdr = fc + dur + addr1 + addr2 + addr3 + seq
    
    # Fixed Params (12 bytes)
    fixed = b'\x00' * 12
    
    # Tag 0 (SSID): "Test"
    tag_ssid = b'\x00\x04Test'
    
    frame = mac_hdr + fixed + tag_ssid
    
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed is not None
    assert parsed.type == "beacon"
    assert parsed.bssid == "11:22:33:44:55:66"
    assert parsed.ssid == "Test"


# ---- WPA3 / PMF / encryption-label tests -----------------------------------

def test_wpa2_psk_ccmp_label():
    """Standard WPA2-PSK-CCMP: by far the most common consumer config."""
    frame = _build_beacon(rsn_ie=_rsn_ie(pairwise_ciphers=(0x04,), akms=(0x02,)))
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WPA2-PSK-CCMP"
    assert parsed.wpa3 is False
    assert parsed.transition_mode is False
    assert parsed.pairwise_cipher == "CCMP"
    assert parsed.akms == ["PSK"]


def test_wpa3_sae_label_and_flags():
    """Pure WPA3-SAE: PMF must be required (per WPA3 mandate)."""
    rsn = _rsn_ie(
        pairwise_ciphers=(0x04,),
        akms=(0x08,),
        rsn_caps=0x0080 | 0x0040,  # MFPC + MFPR
    )
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WPA3-SAE-CCMP"
    assert parsed.wpa3 is True
    assert parsed.transition_mode is False
    assert parsed.pmf_capable is True
    assert parsed.pmf_required is True
    assert parsed.akms == ["SAE"]


def test_wpa2_wpa3_transition_mode():
    """WPA2/WPA3 transition AP advertises both PSK and SAE AKMs.
    PMF is capable but not required (so legacy clients can still connect)."""
    rsn = _rsn_ie(
        pairwise_ciphers=(0x04,),
        akms=(0x02, 0x08),
        rsn_caps=0x0080,  # MFPC only
    )
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WPA2/WPA3-PSK+SAE-CCMP"
    assert parsed.wpa3 is True
    assert parsed.transition_mode is True
    assert parsed.pmf_capable is True
    assert parsed.pmf_required is False


def _extcap_ie(*, beacon_protection: bool) -> bytes:
    """Extended Capabilities IE (tag 127), 11 octets; bit 84 = octet 10 bit 4 = Beacon Protection."""
    field = bytearray(11)
    if beacon_protection:
        field[10] |= 0x10
    return bytes([0x7f, len(field)]) + bytes(field)


def test_beacon_protection_detected_from_ext_capabilities():
    frame = _build_beacon(rsn_ie=_rsn_ie(akms=(0x08,), rsn_caps=0x00c0),
                          wpa_vendor_ie=_extcap_ie(beacon_protection=True))
    assert WlanFrameParser.parse_80211_frame(frame, -50).beacon_protection is True


def test_beacon_protection_absent_when_bit_clear_or_ie_missing():
    with_ie = _build_beacon(wpa_vendor_ie=_extcap_ie(beacon_protection=False))
    without = _build_beacon()
    assert WlanFrameParser.parse_80211_frame(with_ie, -50).beacon_protection is False
    assert WlanFrameParser.parse_80211_frame(without, -50).beacon_protection is False


def test_wpa2_enterprise_eap():
    """WPA2-EAP (corporate / 802.1X): AKM 0x01."""
    rsn = _rsn_ie(pairwise_ciphers=(0x04,), akms=(0x01,))
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WPA2-EAP-CCMP"
    assert parsed.akms == ["EAP"]


def test_akm_suites_propagate_as_numbers():
    """The numeric AKM suites drive crackability gating, parallel to the names."""
    rsn = _rsn_ie(akms=(0x02, 0x08))
    parsed = WlanFrameParser.parse_80211_frame(_build_beacon(rsn_ie=rsn), -50)
    assert parsed.akm_suites == [0x02, 0x08]
    assert parsed.akms == ["PSK", "SAE"]


def test_wpa3_sae_ext_key_h2e_flags_as_wpa3():
    """WPA3-H2E uses SAE-EXT-KEY (00-0F-AC:24), not plain SAE(8). The wpa3 flag
    must still trip: it's keyed on the SAE *family*, not just suite 8."""
    rsn = _rsn_ie(akms=(0x18,), rsn_caps=0x00C0)   # SAE-EXT-KEY, MFPC+MFPR
    parsed = WlanFrameParser.parse_80211_frame(_build_beacon(rsn_ie=rsn), -50)
    assert parsed.akm_suites == [0x18]
    assert parsed.akms == ["SAE-EXT-KEY"]
    assert parsed.wpa3 is True
    assert parsed.transition_mode is False
    assert parsed.encryption == "WPA3-SAE-CCMP"   # label agrees with the flag


# ---- (Re)Assoc Request client-AKM extraction (Phase 2) ----------------------

def _build_assoc_req(
    rsn_ie: bytes, *, reassoc: bool = False, ssid: bytes = b"Net",
    extra_ies: bytes = b"",
) -> bytes:
    """An Assoc (or Reassoc) Request from a client carrying SSID + rates + the
    given RSN IE. Reassoc inserts a (non-zero) 6-byte Current AP Address, shifting
    the IE list from offset 28 to 34, so a wrong offset misparses, not silently
    lands on the same RSN IE."""
    subtype = 0x02 if reassoc else 0x00
    fc0 = subtype << 4                              # type = mgmt (0)
    bssid = bytes.fromhex("aabbccddeeff")
    client = bytes.fromhex("112233445566")
    hdr = bytes([fc0, 0x00]) + b"\x00\x00" + bssid + client + bssid + b"\x00\x00"
    fixed = b"\x11\x00" + b"\x01\x00"               # Capability Info + Listen Interval
    if reassoc:
        fixed += bytes.fromhex("998877665544")      # Current AP Address (non-zero)
    ssid_ie = bytes([0x00, len(ssid)]) + ssid
    rates_ie = bytes([0x01, 0x04]) + b"\x82\x84\x8b\x96"
    return hdr + fixed + ssid_ie + rates_ie + rsn_ie + extra_ies


def test_assoc_req_client_akm_extracted():
    parsed = WlanFrameParser.parse_80211_frame(_build_assoc_req(_rsn_ie(akms=(0x02,))), -50)
    assert parsed.type == "assoc_req"
    assert parsed.assoc_akm == 0x02


def test_reassoc_req_client_akm_extracted_past_current_ap_field():
    """Reassoc's extra 6-byte Current AP field shifts the IEs; the SAE AKM only
    reads back if the +6 offset is honored (the non-zero field misparses at 28)."""
    parsed = WlanFrameParser.parse_80211_frame(
        _build_assoc_req(_rsn_ie(akms=(0x08,)), reassoc=True), -50)
    assert parsed.type == "reassoc_req"
    assert parsed.assoc_akm == 0x08


def test_assoc_req_without_rsn_has_no_akm():
    parsed = WlanFrameParser.parse_80211_frame(_build_assoc_req(b""), -50)
    assert parsed.type == "assoc_req"
    assert parsed.assoc_akm is None


def test_assoc_req_extracts_ssid():
    """The assoc-req SSID IE (offset 28) is what decloaks a hidden AP."""
    parsed = WlanFrameParser.parse_80211_frame(_build_assoc_req(b"", ssid=b"HiddenNet"), -50)
    assert parsed.type == "assoc_req"
    assert parsed.ssid == "HiddenNet"


def test_assoc_req_extracts_client_radio_power_and_feature_capabilities():
    ht = bytes([45, 26]) + b"\x02\x00\x00\xff\xff" + b"\x00" * 21
    power = bytes([33, 2, 0xF6, 20])
    channels = bytes([36, 4, 1, 11, 36, 4])
    rm = bytes([70, 1, 1])
    mobility = bytes([54, 3, 1, 2, 3])
    ext = bytes([127, 3, 0, 0, 0x08])
    wmm = bytes.fromhex("DD060050F2020101")
    he_cap = bytes([255, 7, 35, 1, 2, 3, 4, 5, 6])
    parsed = WlanFrameParser.parse_80211_frame(
        _build_assoc_req(
            _rsn_ie(akms=(0x08,), rsn_caps=0x0080),
            extra_ies=(
                ht + power + channels + rm + mobility + ext + wmm + he_cap
            ),
        ),
        -50,
    )
    caps = parsed.capabilities
    assert caps.phy_modes == {"802.11ax", "802.11n"}
    assert caps.channel_widths_mhz == {20, 40}
    assert caps.max_spatial_streams == 2
    assert (caps.power_min_dbm, caps.power_max_dbm) == (-10, 20)
    assert caps.supported_channel_ranges == [(1, 11), (36, 4)]
    assert caps.radio_measurement and caps.fast_transition and caps.bss_transition and caps.wmm
    assert caps.pmf_capable and not caps.pmf_required
    assert caps.listen_interval == 1
    assert {"ESS", "Privacy"} <= caps.capability_flags
    assert {
        "ht_cap", "rm_cap", "extended_cap", "he_mac_cap",
    } <= set(caps.client_ie_hashes)
    assert all(
        len(digest) == 64
        for digests in caps.client_ie_hashes.values()
        for digest in digests
    )
    assert "00:50:F2:02" in caps.client_vendor_tokens
    assert len(caps.client_ie_order_hashes) == 1


def test_assoc_req_extracts_client_wps_identity():
    parsed = WlanFrameParser.parse_80211_frame(
        _build_assoc_req(b"", extra_ies=_wps_ie(
            manufacturer=b"Acme", model_name=b"Phone X", device_name=b"Alice Phone",
        )),
        -50,
    )
    caps = parsed.capabilities
    assert caps.wps_manufacturer == "Acme"
    assert caps.wps_model == "Phone X"
    assert caps.wps_device_name == "Alice Phone"


def test_reassoc_req_extracts_ssid_past_current_ap_field():
    """Reassoc's +6 Current AP field shifts the SSID IE to offset 34."""
    parsed = WlanFrameParser.parse_80211_frame(
        _build_assoc_req(b"", reassoc=True, ssid=b"HiddenNet"), -50)
    assert parsed.type == "reassoc_req"
    assert parsed.ssid == "HiddenNet"


def test_wpa2_psk_tkip_legacy_cipher():
    """Some old routers still advertise TKIP for pairwise."""
    rsn = _rsn_ie(pairwise_ciphers=(0x02,), akms=(0x02,))
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WPA2-PSK-TKIP"
    assert parsed.pairwise_cipher == "TKIP"


def test_open_network():
    frame = _build_beacon(rsn_ie=b"")
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "OPEN"
    assert parsed.wpa3 is False


def test_wep_via_privacy_bit():
    frame = _build_beacon(rsn_ie=b"", privacy_bit=True)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.encryption == "WEP"


# ---- WEP Data-frame IV extraction ------------------------------------------

def _build_wep_data(
    *,
    iv: bytes = b"\x03\xff\x00",
    keyid: int = 0,
    ext_iv: bool = False,
    qos: bool = False,
    bssid: bytes = b"\x11\x22\x33\x44\x55\x66",
    client: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    body_len: int = 16,
) -> bytes:
    """Build a protected AP→client Data frame. ``ext_iv`` sets the Key ID
    byte's ExtIV bit (0x20) to emulate TKIP/CCMP; left clear it's WEP."""
    subtype = 0x08 if qos else 0x00
    fc0 = 0x08 | (subtype << 4)        # type=data, subtype
    fc1 = 0x02 | 0x40                  # from_ds + Protected
    mac = bytes([fc0, fc1]) + b"\x00\x00"
    # from_ds: addr1=dest(client), addr2=bssid(AP), addr3=source(client)
    mac += client + bssid + client + b"\x00\x00"   # ...+ seq
    if qos:
        mac += b"\x00\x00"            # QoS Control → header is 26 B
    keyid_byte = (keyid << 6) & 0xC0
    if ext_iv:
        keyid_byte |= 0x20
    return mac + iv + bytes([keyid_byte]) + b"\x00" * body_len


def test_wep_data_extracts_iv():
    frame = _build_wep_data(iv=b"\x03\xff\x00", keyid=1)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.type == "wep_data"
    assert parsed.iv == b"\x03\xff\x00"
    assert parsed.keyid == 1
    assert parsed.bssid == "11:22:33:44:55:66"


def test_wep_qos_data_iv_offset():
    """QoS Data has a 26-byte header; the IV must be read past the QoS
    Control field, not at the non-QoS offset 24."""
    frame = _build_wep_data(iv=b"\xde\xad\xbe", qos=True)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.type == "wep_data"
    assert parsed.iv == b"\xde\xad\xbe"


def test_ext_iv_data_is_not_wep():
    """TKIP/CCMP set the ExtIV bit: must NOT be tallied as a WEP IV."""
    frame = _build_wep_data(ext_iv=True)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.type == "data"
    assert not isinstance(parsed, WepDataPacket)


def test_unprotected_data_is_not_wep():
    """A cleartext Data frame (Protected bit clear) is never WEP."""
    frame = bytearray(_build_wep_data())
    frame[1] &= ~0x40  # clear Protected bit
    parsed = WlanFrameParser.parse_80211_frame(bytes(frame), -50)
    assert parsed.type == "data"
    assert not isinstance(parsed, WepDataPacket)


def test_tods_broadcast_arp_is_parsed_not_dropped():
    """Regression: a ToDS WEP ARP request has a BROADCAST addr3 (the DA).
    _is_valid_frame used to reject any broadcast addr3, silently dropping the
    only replayable ARP-replay seed before it could be parsed."""
    fc0 = 0x08
    fc1 = 0x01 | 0x40                    # ToDS + Protected
    bssid = b"\x11\x22\x33\x44\x55\x66"
    client = b"\xaa\xbb\xcc\xdd\xee\xff"
    bcast = b"\xff\xff\xff\xff\xff\xff"
    # ToDS: addr1=BSSID, addr2=client(SA), addr3=broadcast(DA).
    mac = bytes([fc0, fc1]) + b"\x00\x00" + bssid + client + bcast + b"\x00\x00"
    frame = mac + b"\x03\xff\x00" + b"\x00" + b"\x00" * 16
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed is not None
    assert parsed.type == "wep_data"
    assert parsed.to_ds is True
    assert parsed.dest == "ff:ff:ff:ff:ff:ff"
    assert parsed.bssid == "11:22:33:44:55:66"


def test_wpa3_keys_propagate_through_parse_80211_frame():
    """Regression: pre-fix these keys were set on the tags dict but dropped
    in parse_80211_frame, never reaching _on_frame_parsed."""
    rsn = _rsn_ie(akms=(0x08,), rsn_caps=0x00C0)
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)

    # Each must carry its PARSED value, not the BeaconPacket field default: a key
    # dropped on the tags->result copy would silently fall back to that default.
    assert parsed.wpa3 is True
    assert parsed.transition_mode is False
    assert parsed.pmf_capable is True
    assert parsed.pmf_required is True
    assert parsed.akms == ["SAE"]
    assert parsed.pairwise_cipher is not None
    assert parsed.rsn_ie_raw is not None


def test_rsn_ie_raw_round_trip():
    """The harvester echoes rsn_ie_raw into its Assoc Req. The bytes must be
    exactly the IE as advertised, including the 2-byte tag header."""
    rsn = _rsn_ie(akms=(0x02,))
    frame = _build_beacon(rsn_ie=rsn)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.rsn_ie_raw == rsn


# ---- Channel parsing (2.4 GHz DS Param + 5 GHz HT Op + VHT Op) -------------

def _ds_param_ie(channel: int) -> bytes:
    """Tag 3 (DS Parameter Set): 1-byte channel. Present on 2.4 GHz
    beacons; vendor-optional on 5 GHz (most APs omit it there)."""
    return bytes([3, 1, channel])


def _ht_op_ie(primary_channel: int, *, secondary_offset: int = 0) -> bytes:
    """Tag 61 (HT Operation): 22-byte body, first byte = primary channel.
    Present on every 802.11n/ac AP regardless of band."""
    raw_offset = {0: 0, 1: 1, -1: 3}[secondary_offset]
    info = raw_offset | (0x04 if secondary_offset else 0)
    body = bytes([primary_channel, info]) + b"\x00" * 20
    return bytes([61, len(body)]) + body


def _vht_op_ie(center_seg0: int, *, width_code: int = 0, center_seg1: int = 0) -> bytes:
    """Tag 192 (VHT Operation): width plus center-frequency segments."""
    body = bytes([width_code, center_seg0, center_seg1, 0x00, 0x00])
    return bytes([192, len(body)]) + body


def test_channel_from_ds_param_ie_2ghz():
    """2.4 GHz beacon → DS Param IE present, sets channel."""
    frame = _build_beacon() + _ds_param_ie(6)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel == 6


def test_channel_from_ht_op_ie_when_ds_param_missing():
    """5 GHz beacon with HT Op IE but no DS Param IE → channel from HT Op."""
    frame = _build_beacon() + _ht_op_ie(153)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel == 153


def test_conflicting_primary_channel_ies_are_not_trusted():
    """Contradictory DS/HT primary channels defer to the receiving radio."""
    # HT Op IE before DS Param IE in tag order.
    frame = _build_beacon() + _ht_op_ie(36) + _ds_param_ie(40)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel is None
    assert parsed.capabilities.channel_conflict is True
    # And the other way round: DS Param IE first.
    frame2 = _build_beacon() + _ds_param_ie(40) + _ht_op_ie(36)
    parsed2 = WlanFrameParser.parse_80211_frame(frame2, -50)
    assert parsed2.channel is None
    assert parsed2.capabilities.channel_conflict is True


def test_vht_center_segment_is_never_used_as_primary_channel():
    """Center CH 42 for an 80 MHz BSS is not a valid primary-channel claim."""
    frame = _build_beacon() + _vht_op_ie(42, width_code=1)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel is None
    assert parsed.capabilities.operating_width_mhz == 80
    assert parsed.capabilities.center_channel_0 == 42


def test_ht_primary_and_vht_center_are_kept_separate():
    frame = _build_beacon() + _ht_op_ie(36) + _vht_op_ie(42, width_code=1)
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel == 36
    assert parsed.capabilities.operating_width_mhz == 80
    assert parsed.capabilities.center_channel_0 == 42


def test_ht40_operation_records_secondary_direction_and_center():
    above = WlanFrameParser.parse_80211_frame(
        _build_beacon() + _ht_op_ie(6, secondary_offset=1), -50,
    )
    below = WlanFrameParser.parse_80211_frame(
        _build_beacon() + _ht_op_ie(11, secondary_offset=-1), -50,
    )
    assert (
        above.capabilities.operating_width_mhz,
        above.capabilities.secondary_channel_offset,
        above.capabilities.center_channel_0,
    ) == (40, 1, 8)
    assert (
        below.capabilities.operating_width_mhz,
        below.capabilities.secondary_channel_offset,
        below.capabilities.center_channel_0,
    ) == (40, -1, 9)


def test_channel_absent_when_no_ie_provides_it():
    """Beacon without any channel-bearing IE → parser does NOT synthesise
    channel=1 (pre-fix behaviour that mis-tagged 5 GHz APs missing DS Param
    IE as channel 1). Caller falls back to chip's current_channel."""
    frame = _build_beacon()
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed.channel is None


# ---- Frame-type dispatch edge cases ----------------------------------------
# Behaviours the type-dispatch path relies on but the other tests never hit:
# WDS/ctrl rejection, probe-resp == beacon, the mgmt-subtype labels, corrupt-tag
# rejection, and the HT-Control header offset.

def test_wds_frame_is_ignored():
    """A 4-address WDS data frame (to_ds AND from_ds) is intentionally dropped:
    wifit3 has no use for repeater/mesh links. It passes _is_valid_frame (real
    addr2/addr3), so the rejection is the parser's own, not the validator's."""
    fc0 = 0x08                       # data, subtype 0
    fc1 = 0x01 | 0x02                # to_ds + from_ds = WDS
    a1 = b"\x11\x22\x33\x44\x55\x66"
    a2 = b"\xaa\xbb\xcc\xdd\xee\xff"
    a3 = b"\x77\x88\x99\xaa\xbb\xcc"
    frame = bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00" + b"\x00" * 8
    assert WlanFrameParser.parse_80211_frame(frame, -50) is None


def test_probe_response_parsed_like_beacon():
    """A probe response (subtype 5) carries the same IE layout as a beacon and
    must parse identically: same BeaconPacket type, SSID, and encryption."""
    frame = bytearray(_build_beacon(ssid="ProbeNet", rsn_ie=_rsn_ie(akms=(0x02,))))
    frame[0] = 0x50                  # mgmt subtype 5 = probe response (was 0x80 beacon)
    parsed = WlanFrameParser.parse_80211_frame(bytes(frame), -50)
    assert parsed is not None
    assert parsed.type == "probe_resp"
    assert isinstance(parsed, BeaconPacket)
    assert parsed.ssid == "ProbeNet"
    assert parsed.encryption == "WPA2-PSK-CCMP"


def _minimal_mgmt(fc0: int) -> bytes:
    """A 24-byte management frame with the given FC0 (type=mgmt + subtype), enough
    to pass _is_valid_frame for the subtypes that carry no mandatory IEs."""
    return bytes([fc0, 0x00]) + b"\x00\x00" + b"\x11" * 6 + b"\x22" * 6 + b"\x33" * 6 + b"\x00\x00"


def test_assoc_resp_labeled():
    parsed = WlanFrameParser.parse_80211_frame(_minimal_mgmt(0x10), -50)  # subtype 1
    assert parsed.type == "assoc_resp"


def test_unknown_mgmt_subtype_labeled_generic():
    parsed = WlanFrameParser.parse_80211_frame(_minimal_mgmt(0xA0), -50)  # subtype 0x0A (action)
    assert parsed.type == "mgmt_10"


def test_beacon_with_control_char_ssid_returns_none():
    """Passes the structural _is_valid_frame check (tag0=SSID, tag1=rates) but the
    SSID holds control bytes → _parse_tags rejects it as corrupt → parse None."""
    frame = _build_beacon(ssid="\x01\x02\x03")
    assert WlanFrameParser.parse_80211_frame(frame, -50) is None


def test_wep_data_with_ht_control_offset():
    """The Order/HT-Control bit (FC1 0x80) adds a 4-byte HT Control field to the
    MAC header. The WEP IV must be read past it (offset 28, not 24)."""
    fc0 = 0x08                       # data, subtype 0
    fc1 = 0x02 | 0x40 | 0x80         # from_ds + Protected + Order (HT Control present)
    bssid = b"\x11\x22\x33\x44\x55\x66"
    client = b"\xaa\xbb\xcc\xdd\xee\xff"
    mac = bytes([fc0, fc1]) + b"\x00\x00" + client + bssid + client + b"\x00\x00"
    ht_control = b"\x00\x00\x00\x00"
    iv = b"\xde\xad\xbe"
    frame = mac + ht_control + iv + b"\x00" + b"\x00" * 16   # keyid byte ExtIV clear → WEP
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert parsed is not None
    assert parsed.type == "wep_data"
    assert parsed.iv == iv


# ---- Auth / Assoc-resp / Deauth typed subclasses (status & reason) ----------

def _mgmt_frame(subtype: int, body: bytes) -> bytes:
    fc0 = (subtype << 4) & 0xF0
    return (bytes([fc0, 0x00]) + b"\x00\x00" + b"\xaa" * 6 + b"\xbb" * 6
            + b"\xcc" * 6 + b"\x00\x00" + body)


def test_assoc_resp_carries_status():
    p = WlanFrameParser.parse_80211_frame(_mgmt_frame(0x01, b"\x11\x00\x0d\x00\x01\xc0"), -50)
    assert isinstance(p, AssocRespPacket)
    assert p.status == 0x0d
    assert p.type == "assoc_resp"


def test_auth_carries_status():
    p = WlanFrameParser.parse_80211_frame(_mgmt_frame(0x0b, b"\x00\x00\x02\x00\x0e\x00"), -50)
    assert isinstance(p, AuthPacket)
    assert p.status == 0x0e


def test_deauth_and_disassoc_carry_reason():
    d = WlanFrameParser.parse_80211_frame(_mgmt_frame(0x0c, b"\x07\x00"), -50)
    assert isinstance(d, DeauthPacket) and d.reason == 7 and d.type == "deauth"
    dis = WlanFrameParser.parse_80211_frame(_mgmt_frame(0x0a, b"\x08\x00"), -50)
    assert isinstance(dis, DeauthPacket) and dis.reason == 8


def test_probe_req_is_typed():
    frame = _mgmt_frame(0x04, b"\x00\x03Foo\x01\x04\x82\x84\x8b\x96")
    p = WlanFrameParser.parse_80211_frame(frame, -50)
    assert isinstance(p, ProbeReqPacket)
    assert p.ssid == "Foo"
