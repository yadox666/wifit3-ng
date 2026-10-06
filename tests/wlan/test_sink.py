"""Tests for the session-wide 802.11 picture (wlan/sink.py).

WlanSink is pure: it takes parsed Packets plus the receiving card id and builds the AP/client
registry. These are the picture assertions that used to live on WlanInterface, re-driven through
``sink.update(pkt, card_id)``, plus the multicard-specific per-card signal behavior."""

import struct

from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.packet import EapPacket
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.wsc import messages as WSC
from wifit3.models import AccessPoint, AdvertisedCapabilities, IdKey, IdSource
from wifit3.persist.hidden_ssids import HiddenSsidStore
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.wlan.sink import WlanSink
from wifit3.wlan.packet_stats import PACKET_CLASSES

from tests.frames import pkt

BSSID = "aa:bb:cc:dd:ee:ff"
W0, W1 = "wlan0", "wlan1"
_LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


def _beacon(overrides=None):
    base = {
        "type": "beacon", "bssid": BSSID, "source": BSSID, "dest": "ff:ff:ff:ff:ff:ff",
        "rssi": -40, "ssid": "Test_SSID", "channel": 6, "encryption": "WPA2",
    }
    base.update(overrides or {})
    return pkt(base)


def _wps_m1_frame(bssid: bytes, client: bytes) -> bytes:
    attrs = (
        WSC.tlv_u8(WSC.ATTR_VERSION, 0x10)
        + WSC.tlv_u8(WSC.ATTR_MSG_TYPE, WSC.WPS_M1)
        + WSC.tlv(WSC.ATTR_MANUFACTURER, b"TP-Link")
        + WSC.tlv(WSC.ATTR_MODEL_NAME, b"Archer AX10")
        + WSC.tlv(WSC.ATTR_MODEL_NUMBER, b"AX10")
        + WSC.tlv(WSC.ATTR_DEV_NAME, b"Office AP\x00")
    )
    expanded = (
        bytes([WSC.EAP_TYPE_EXPANDED]) + WSC.WFA_VENDOR_ID
        + WSC.WFA_VENDOR_TYPE_SIMPLECONFIG + bytes([WSC.WSC_MSG, 0x00]) + attrs
    )
    eap_len = 4 + len(expanded)
    eap = struct.pack(">BBH", WSC.EAP_REQUEST, 1, eap_len) + expanded
    eapol = struct.pack(">BBH", WSC.DOT1X_VERSION, WSC.DOT1X_TYPE_EAP_PACKET, len(eap)) + eap
    return b"\x08\x02\x00\x00" + client + bssid + bssid + b"\x00\x00" + _LLC_SNAP_EAPOL + eapol


# ----- registry + per-card signal --------------------------------------------

def test_beacon_creates_ap_and_smooths_signal_per_card():
    s = WlanSink()
    s.update(_beacon({"timestamp_us": 3_723_000_000, "country_code": "US"}), W0)
    ap = s.get_access_points()[0]
    assert ap.bssid == BSSID and ap.ssid == "Test_SSID" and ap.channel == 6
    assert ap.encryption == "WPA2" and ap.beacons == 1
    assert ap.uptime_us == 3_723_000_000
    assert ap.country_code == "US"
    assert ap.signal == -40 and ap.signal_by_card == {W0: -40}

    s.update(_beacon({"rssi": -50, "timestamp_us": 3_724_000_000}), W0)
    ap = s.get_access_points()[0]
    assert ap.beacons == 2
    assert ap.uptime_us == 3_724_000_000
    assert ap.signal == -45                       # (-40 + -50) / 2, per-card
    assert ap.signal_by_card == {W0: -45}


def test_beacon_without_country_keeps_last_advertised_country():
    s = WlanSink()
    s.update(_beacon({"country_code": "DE"}), W0)
    s.update(_beacon(), W0)
    assert s.access_points[BSSID].country_code == "DE"


def test_signal_sliding_window_absorbs_spikes_and_evicts_old_samples():
    s = WlanSink()
    for _ in range(8):
        s.update(_beacon({"rssi": -70}), W0)
    ap = s.get_access_points()[0]
    assert ap.signal == -70
    assert len(ap.signal_history[W0]) == 8

    # A 16 dBm noisy drop is dampened to only 2 dBm across the 8-sample window
    s.update(_beacon({"rssi": -86}), W0)
    assert ap.signal == -72
    assert len(ap.signal_history[W0]) == 8


def test_signal_sliding_window_ignores_dummy_minus_100():
    s = WlanSink()
    s.update(_beacon({"rssi": -65}), W0)
    # A driver emitting -100 for a frame with missing RSSI report must not drag down signal
    s.update(_beacon({"rssi": -100}), W0)
    ap = s.get_access_points()[0]
    assert ap.signal == -65
    assert len(ap.signal_history[W0]) == 1


def test_signal_is_strongest_across_cards():
    s = WlanSink()
    s.update(_beacon({"rssi": -70}), W0)
    s.update(_beacon({"rssi": -55}), W1)          # a second card hears it stronger
    ap = s.get_access_points()[0]
    assert ap.signal_by_card == {W0: -70, W1: -55}
    assert ap.signal == -55                        # max() = strongest antenna


def test_record_signal_updates_per_card_on_duplicate():
    s = WlanSink()
    s.update(_beacon({"rssi": -70}), W0)           # novel: folded into the picture by card 0
    s.record_signal(W1, BSSID, -50)                # card 1's duplicate: only its signal
    ap = s.get_access_points()[0]
    assert ap.signal_by_card == {W0: -70, W1: -50}
    assert ap.signal == -50
    assert ap.beacons == 1                          # a duplicate never re-counts the frame


def test_record_signal_unknown_bssid_is_noop():
    s = WlanSink()
    s.record_signal(W0, "de:ad:be:ef:00:00", -30)
    assert s.get_access_points() == []


def test_channel_hint_used_only_when_beacon_lacks_channel():
    s = WlanSink()
    s.update(pkt({"type": "beacon", "bssid": BSSID, "rssi": -40, "ssid": "X"}), W0, channel_hint=11)
    assert s.access_points[BSSID].channel == 11


def test_wps_identity_fields_persist_on_ap():
    s = WlanSink()
    s.update(_beacon({
        "wps": True,
        "wsc_manufacturer": "MikroTik",
        "wsc_model_name": "RouterBOARD",
        "wsc_device_name": "Office AP",
        "wsc_serial_number": "SERIAL-1",
        "wps_state": 2,
        "wps_uuid_e": "00112233445566778899aabbccddeeff",
        "wps_rf_bands": 3,
        "wps_os_version": 0x80000001,
        "wps_response_type": 3,
    }), W0)
    ap = s.access_points[BSSID]
    assert ap.identity.manufacturer == "MikroTik"
    assert ap.identity.model_name == "RouterBOARD"
    assert ap.identity.device_name == "Office AP"
    assert ap.identity.serial_number == "SERIAL-1"
    assert ap.wps_state == 2
    assert ap.wps_uuid_e == "00112233445566778899aabbccddeeff"
    assert ap.wps_rf_bands == 3
    assert ap.wps_os_version == 0x80000001
    assert ap.wps_response_type == 3
    assert ap.identity.summary == "MikroTik RouterBOARD"


def test_wps_m1_identity_fields_are_applied_by_sink():
    s = WlanSink()
    s.update(_beacon(), W0)
    frame = _wps_m1_frame(str_to_mac(BSSID), str_to_mac("02:00:00:00:00:01"))
    s.update(pkt({
        "type": "eapol", "to_ds": False, "from_ds": True, "bssid": BSSID,
        "source": BSSID, "dest": "02:00:00:00:00:01", "rssi": -45, "raw": frame,
    }), W0)
    ap = s.access_points[BSSID]
    assert ap.wps is True
    assert ap.identity.get_source_value(IdKey.MANUFACTURER, IdSource.WSC_M1) == "TP-Link"
    assert ap.identity.get_source_value(IdKey.MODEL_NAME, IdSource.WSC_M1) == "Archer AX10"
    assert ap.identity.get_source_value(IdKey.MODEL_NUMBER, IdSource.WSC_M1) == "AX10"
    assert ap.identity.get_source_value(IdKey.DEVICE_NAME, IdSource.WSC_M1) == "Office AP"
    assert ap.identity.manufacturer == "TP-Link"
    assert ap.identity.model_name == "Archer AX10"
    assert ap.identity.model_number == "AX10"
    assert ap.identity.device_name == "Office AP"
    assert ap.identity.summary == "TP-Link Archer AX10"


def test_observed_hidden_ap_is_enriched_from_sqlite_history(tmp_path):
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    learned = AccessPoint(bssid=BSSID, ssid="Known network")
    learned.identity.set(IdSource.WSC_BEACON, IdKey.MODEL_NAME, "Known model")
    history.remember(learned, force=True)
    sink = WlanSink(ap_history=history)

    sink.update(_beacon({"ssid": "<hidden>", "wsc_model_name": None}), W0)

    ap = sink.access_points[BSSID]
    assert ap.ssid == "Known network"
    assert ap.identity.model_name == "Known model"


def test_live_wsc_beacon_identity_overrides_sqlite_history(tmp_path):
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    learned = AccessPoint(bssid=BSSID, ssid="AP")
    learned.identity.set(IdSource.WSC_BEACON, IdKey.MODEL_NAME, "Old model")
    history.remember(learned, force=True)
    sink = WlanSink(ap_history=history)

    sink.update(_beacon({"wps": True, "wsc_model_name": "Current model"}), W0)

    assert sink.access_points[BSSID].identity.model_name == "Current model"


def test_wps_m1_identity_is_immediately_persisted_to_history(tmp_path):
    path = tmp_path / "history.sqlite3"
    history = ApHistoryStore(path)
    sink = WlanSink(ap_history=history)
    sink.update(_beacon(), W0)
    frame = _wps_m1_frame(
        str_to_mac(BSSID), str_to_mac("02:00:00:00:00:01"),
    )

    sink.update(pkt({
        "type": "eapol", "to_ds": False, "from_ds": True, "bssid": BSSID,
        "source": BSSID, "dest": "02:00:00:00:00:01", "rssi": -45, "raw": frame,
    }), W0)
    history.close()

    reopened = ApHistoryStore(path)
    observed = AccessPoint(bssid=BSSID)
    reopened.enrich(observed)
    assert observed.identity.model_name == "Archer AX10"


def test_parsed_wps_m1_still_updates_identity_through_general_eap_path():
    sink = WlanSink()
    sink.update(_beacon(), W0)
    frame = _wps_m1_frame(
        str_to_mac(BSSID),
        str_to_mac("02:00:00:00:00:01"),
    )
    parsed = WlanFrameParser.parse_80211_frame(frame, -45)
    assert isinstance(parsed, EapPacket)

    sink.update(parsed, W0)

    assert sink.access_points[BSSID].identity.model_name == "Archer AX10"



# ----- encryption / decloak / clients ----------------------------------------

def test_encryption_keeps_strongest_evidence_not_latest():
    s = WlanSink()
    s.update(_beacon({"encryption": "WPA2-PSK-CCMP", "akms": ["PSK"]}), W0)
    s.update(_beacon({"encryption": "WEP", "akms": []}), W0)     # RSN-less flicker
    assert s.access_points[BSSID].encryption == "WPA2-PSK-CCMP"


def test_decloak_via_probe_resp():
    s = WlanSink()
    s.update(pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}), W0)
    assert s.access_points[BSSID].ssid is None
    s.update(pkt({"type": "probe_resp", "bssid": BSSID, "rssi": -60, "ssid": "Now_Visible"}), W0)
    ap = s.access_points[BSSID]
    assert ap.ssid == "Now_Visible" and ap.decloak_method == "probe_resp"


def test_hidden_ap_uses_previous_ssid_for_same_bssid(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.json")
    store.remember(BSSID, "Remembered Network", "assoc_req")
    sink = WlanSink(store)

    sink.update(
        pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}),
        W0,
    )

    ap = sink.access_points[BSSID]
    assert ap.ssid == "Remembered Network"
    assert ap.decloak_method == "history"


def test_visible_ap_name_is_remembered_for_a_later_hidden_session(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.json")
    first_session = WlanSink(store)
    first_session.update(
        pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "Seen Before"}),
        W0,
    )

    second_session = WlanSink(HiddenSsidStore(store.path))
    second_session.update(
        pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}),
        W0,
    )

    ap = second_session.access_points[BSSID]
    assert ap.ssid == "Seen Before"
    assert ap.decloak_method == "history"


def test_new_hidden_ssid_reveal_is_persisted(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.json")
    sink = WlanSink(store)
    sink.update(
        pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}),
        W0,
    )
    sink.update(
        pkt({"type": "probe_resp", "bssid": BSSID, "rssi": -60, "ssid": "Revealed"}),
        W0,
    )

    assert HiddenSsidStore(store.path).lookup(BSSID) == "Revealed"


def test_assoc_req_stamps_client_akm():
    s = WlanSink()
    client = "12:22:33:44:55:66"
    s.update(pkt({"type": "assoc_req", "bssid": BSSID, "source": client, "dest": BSSID,
                  "rssi": -45, "assoc_akm": 0x02}), W0)
    assert s.clients[client].akm_selected == 0x02


def test_association_is_persisted_for_ap_and_client_history(tmp_path):
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    sink = WlanSink(ap_history=history)
    client = "12:22:33:44:55:66"
    sink.update(_beacon(), W0)

    sink.update(pkt({
        "type": "assoc_req", "bssid": BSSID, "source": client, "dest": BSSID,
        "rssi": -45,
    }), W0)

    assert [record.client_mac for record in history.clients_for_ap(BSSID)] == [client]
    assert [record.bssid for record in history.aps_for_client(client)] == [BSSID]


def test_client_advertised_capabilities_merge_across_probe_and_assoc():
    s = WlanSink()
    client = "12:22:33:44:55:66"
    probe_caps = AdvertisedCapabilities(
        phy_modes={"802.11n"}, channel_widths_mhz={20, 40}, wmm=True,
    )
    assoc_caps = AdvertisedCapabilities(
        phy_modes={"802.11ac"}, channel_widths_mhz={80}, max_spatial_streams=2,
        pmf_capable=True,
    )
    s.update(pkt({
        "type": "probe_req", "source": client, "dest": "ff:ff:ff:ff:ff:ff",
        "bssid": "ff:ff:ff:ff:ff:ff", "rssi": -50, "capabilities": probe_caps,
    }), W0)
    s.update(pkt({
        "type": "assoc_req", "bssid": BSSID, "source": client, "dest": BSSID,
        "rssi": -45, "capabilities": assoc_caps,
    }), W0)
    caps = s.clients[client].capabilities
    assert caps.phy_modes == {"802.11n", "802.11ac"}
    assert caps.channel_widths_mhz == {20, 40, 80}
    assert caps.max_spatial_streams == 2
    assert caps.wmm and caps.pmf_capable


def test_directed_probe_tracks_latest_channel_time_and_count():
    sink = WlanSink()
    client = "12:22:33:44:55:66"
    probe = pkt({
        "type": "probe_req",
        "source": client,
        "dest": "ff:ff:ff:ff:ff:ff",
        "bssid": "ff:ff:ff:ff:ff:ff",
        "rssi": -50,
        "ssid": "DefaultSSID",
    })

    sink.update(probe, W0, channel_hint=1)
    sink.update(probe, W0, channel_hint=6)

    observation = sink.clients[client].probe_observations["DefaultSSID"]
    assert sink.clients[client].probed_ssids == {"DefaultSSID"}
    assert observation.channel == 6
    assert observation.last_seen >= observation.first_seen
    assert observation.count == 2


def test_randomized_probe_remains_live_but_is_not_saved(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.sqlite3")
    sink = WlanSink(store)
    client = "02:22:33:44:55:66"
    sink.update(pkt({
        "type": "probe_req",
        "source": client,
        "dest": "ff:ff:ff:ff:ff:ff",
        "bssid": "ff:ff:ff:ff:ff:ff",
        "rssi": -50,
        "ssid": "SessionOnly",
    }), W0)

    assert sink.clients[client].probed_ssids == {"SessionOnly"}
    assert store.probes_for_client(client) == []


def test_persisted_client_probe_is_restored_as_history(tmp_path):
    store = HiddenSsidStore(tmp_path / "hidden_ssids.json")
    store.remember_probe(
        "18:7f:88:44:55:66", "DefaultSSID", 11, now=100,
    )
    sink = WlanSink(HiddenSsidStore(store.path))
    sink.update(pkt({
        "type": "data",
        "source": "18:7f:88:44:55:66",
        "dest": BSSID,
        "bssid": BSSID,
        "to_ds": True,
        "rssi": -50,
    }), W0, channel_hint=6)

    observation = sink.clients["18:7f:88:44:55:66"].probe_observations["DefaultSSID"]
    assert observation.channel == 11
    assert observation.count == 1
    assert observation.historical


def test_decloak_via_assoc_req():
    """A client's assoc-req SSID IE decloaks the hidden AP it's joining."""
    s = WlanSink()
    s.update(pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}), W0)
    assert s.access_points[BSSID].ssid is None
    s.update(pkt({"type": "assoc_req", "bssid": BSSID, "source": "12:22:33:44:55:66",
                  "dest": BSSID, "rssi": -45, "ssid": "Real_Name"}), W0)
    ap = s.access_points[BSSID]
    assert ap.ssid == "Real_Name" and ap.decloak_method == "assoc_req"


def test_decloak_via_reassoc_req():
    """Reassoc-req carries the SSID too (PMF doesn't protect it), so it decloaks as well."""
    s = WlanSink()
    s.update(pkt({"type": "beacon", "bssid": BSSID, "rssi": -60, "ssid": "<hidden>"}), W0)
    assert s.access_points[BSSID].ssid is None
    s.update(pkt({"type": "reassoc_req", "bssid": BSSID, "source": "12:22:33:44:55:66",
                  "dest": BSSID, "rssi": -45, "ssid": "Real_Name"}), W0)
    ap = s.access_points[BSSID]
    assert ap.ssid == "Real_Name" and ap.decloak_method == "reassoc_req"


def test_from_ds_client_is_receiver_not_addr3_origin():
    s = WlanSink()
    client, upstream = "12:22:33:44:55:66", "de:ad:be:ef:00:01"
    s.update(pkt({"type": "data", "to_ds": False, "from_ds": True,
                  "bssid": BSSID, "dest": client, "source": upstream, "rssi": -50}), W0)
    assert client in s.clients and upstream not in s.clients
    assert s.clients[client].bssid == BSSID


def test_fake_client_is_explicitly_visible_but_still_marked_as_ours():
    sink = WlanSink()
    mac = "02:11:22:33:44:55"

    client = sink.register_fake_client(mac, BSSID)

    assert client.is_fake is True
    assert client.bssid == BSSID
    assert mac in sink.clients
    assert mac in sink.own_macs

    sink.unregister_fake_client(mac)
    assert mac not in sink.clients


# ----- siblings --------------------------------------------------------------

def test_siblings_last_byte_differs():
    s = WlanSink()
    s.update(pkt({"type": "beacon", "bssid": "aa:bb:cc:dd:ee:00", "rssi": -60,
                  "ssid": "TestSSID", "channel": 44}), W0)
    s.update(pkt({"type": "beacon", "bssid": "aa:bb:cc:dd:ee:02", "rssi": -60,
                  "ssid": "<hidden>", "channel": 44}), W0)
    assert s.access_points["aa:bb:cc:dd:ee:00"].siblings == ["aa:bb:cc:dd:ee:02"]
    assert s.access_points["aa:bb:cc:dd:ee:02"].siblings == ["aa:bb:cc:dd:ee:00"]


# ----- forged / self MAC -----------------------------------------------------

def test_forged_mac_does_not_create_client_or_append_eapol():
    s = WlanSink()
    s.update(_beacon({"channel": 1, "raw": b"\x00" * 36}), W0)
    forged = "02:aa:bb:cc:dd:ee"
    s.register_forged_mac(forged)
    pmkid = bytes.fromhex("ad2fad48da558cdfeb19cea25e2ce5af")
    s.update(pkt({
        "type": "eapol", "bssid": BSSID, "source": BSSID, "dest": forged, "rssi": -45,
        "raw": b"\x00" * 100, "eapol_msg_num": 1, "eapol_replay_counter": b"\x00" * 8,
        "eapol_nonce": b"\x01" * 32, "eapol_mic": b"\x00" * 16, "eapol_key_data_len": 22,
        "eapol_payload": b"\x00" * 121, "eapol_pmkid": pmkid,
    }), W0)
    assert forged not in s.clients
    hs = s.access_points[BSSID].handshakes[forged]
    assert hs.pmkid == pmkid and hs.messages == []


def test_register_and_unregister_own_mac():
    s = WlanSink()
    mac = s.register_own_mac(b"\x02\x00\x00\x00\x00\x01")
    assert mac == "02:00:00:00:00:01"
    assert mac in s.own_macs and mac not in s.clients   # our own MAC is never a client
    s.unregister_own_mac(mac)
    assert mac not in s.own_macs


def test_forged_alias_funnels_to_own_macs():
    s = WlanSink()
    s.register_forged_mac("aa:bb:cc:dd:ee:01")
    assert "aa:bb:cc:dd:ee:01" in s.own_macs
    assert s.forged_macs == s.own_macs                  # back-compat alias


def test_wep_ivs_tallied_onto_ap():
    s = WlanSink()
    bssid = "12:22:33:44:55:66"
    s.update(pkt({"type": "beacon", "bssid": bssid, "rssi": -40, "ssid": "WepAP",
                  "channel": 6, "encryption": "WEP", "raw": b"\x00" * 36}), W0)
    for iv in (b"\x01\x02\x03", b"\x01\x02\x03", b"\x04\x05\x06"):
        s.update(pkt({"type": "wep_data", "bssid": bssid, "source": "aa:bb:cc:dd:ee:01",
                      "dest": "aa:bb:cc:dd:ee:01", "rssi": -45, "wep_iv": iv,
                      "wep_keyid": 0, "raw": b"\x00" * 40}), W0)
    ap = s.access_points[bssid]
    assert ap.wep is not None and ap.wep.unique_ivs == 2 and ap.wep.total_frames == 3
    assert s.clients["aa:bb:cc:dd:ee:01"].bssid == bssid


# ----- TX stats --------------------------------------------------------------

def _mac(x):
    return bytes(int(p, 16) for p in x.split(":"))


def test_record_tx_classifies_deauth_vs_inject():
    s = WlanSink()
    bssid, client = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"
    deauth = b"\xc0\x00\x00\x00" + _mac(client) + _mac(bssid) + _mac(bssid) + b"\x00\x00" \
        + struct.pack("<H", 7)
    data = b"\x08\x01\x00\x00" + _mac(bssid) + _mac(client) + _mac(client) + b"\x00\x00"
    s.record_tx(deauth)
    s.record_tx(data)
    snap = s.packet_stats.snapshot(bssid)
    assert snap["deauth"] == 1 and snap["inject"] == 1


def test_record_tx_never_raises_on_garbage():
    s = WlanSink()
    s.record_tx(b"\x00\x01")           # unparseable: best-effort, no exception
    assert s.packet_stats._counts == {} or all(
        v == dict.fromkeys(PACKET_CLASSES, 0) for v in s.packet_stats._counts.values()
    )
