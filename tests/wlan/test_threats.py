"""Nearby Wi-Fi threat scoring, including frames this process transmitted."""
from wifit3.dot11.packet import BeaconPacket, EapolPacket
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models import AccessPoint
from wifit3.wlan.sink import WlanSink
from wifit3.wlan.threats import (
    ThreatWatcher,
    _CHANNEL_WARMUP_S,
    _SESSION_WARMUP_S,
)
from wifit3.wlan.tx_ledger import clear, is_own_transmission, note_own_transmission

BSSID = "00:1e:58:00:00:10"
OTHER = "00:1b:2f:00:00:11"
CLIENT = "02:00:00:00:00:22"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def setup_function() -> None:
    clear()


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _deauth(dest: str, seq: int, *, source: str = BSSID, reason: int = 7) -> bytes:
    sc = (seq & 0xFFF) << 4
    return (
        bytes((0xC0, 0x00, 0x00, 0x00))
        + _mac(dest) + _mac(source) + _mac(BSSID)
        + sc.to_bytes(2, "little")
        + reason.to_bytes(2, "little")
    )


def _parsed_deauth(dest: str, seq: int, *, source: str = BSSID):
    frame = _deauth(dest, seq, source=source)
    parsed = WlanFrameParser.parse_80211_frame(frame, -40)
    assert parsed is not None
    return parsed


def _beacon(bssid: str, ssid: str, seq: int, channel: int, rssi: int = -50, extra: bytes = b""):
    sc = (seq & 0xFFF) << 4
    ssid_bytes = ssid.encode()
    body = bytes((0, len(ssid_bytes))) + ssid_bytes + bytes((3, 1, channel)) + extra
    raw = (
        bytes((0x80, 0x00, 0x00, 0x00))
        + _mac(BROADCAST) + _mac(bssid) + _mac(bssid)
        + sc.to_bytes(2, "little")
        + b"\x00" * 8 + (100).to_bytes(2, "little") + b"\x01\x00"
        + body
    )
    return BeaconPacket(
        type="beacon",
        type_id=0,
        subtype_id=8,
        bssid=bssid,
        source=bssid,
        dest=BROADCAST,
        to_ds=False,
        from_ds=False,
        rssi=rssi,
        raw=raw,
        ssid=ssid,
        channel=channel,
    )


def test_exact_transmit_fingerprint_is_ours_and_expires():
    frame = _deauth(BROADCAST, 40)
    note_own_transmission(frame, now=10.0)
    assert is_own_transmission(frame, now=10.9)
    assert not is_own_transmission(frame, now=11.2)


def test_hardware_restamp_matches_only_briefly():
    sent = _deauth(BROADCAST, 0)
    heard = _deauth(BROADCAST, 90)
    note_own_transmission(sent, now=10.0)
    assert is_own_transmission(heard, now=10.2)
    assert not is_own_transmission(heard, now=10.5)


def test_broadcast_deauth_burst_is_high_and_one_frame_is_not():
    watcher = ThreatWatcher()
    watcher.observe(_parsed_deauth(BROADCAST, 1), ssid="Cafe", channel=6, now=50)
    assert watcher.drain() == []
    for seq in range(2, 11):
        watcher.observe(_parsed_deauth(BROADCAST, seq), ssid="Cafe", channel=6, now=50 + seq * 0.1)
    events = watcher.drain()
    assert len(events) == 1
    assert events[0].level == "high"
    assert events[0].kind == "deauth"
    assert events[0].severity == "error"
    watcher.observe(_parsed_deauth(BROADCAST, 9), ssid="Cafe", channel=6, now=51)
    assert watcher.drain() == []


def test_directed_ap_deauth_burst_below_threshold_is_ignored():
    watcher = ThreatWatcher()
    for seq in range(1, 6):
        watcher.observe(_parsed_deauth(CLIENT, seq), ssid="Cafe", channel=6, now=20 + seq * 0.1)
    assert watcher.drain() == []


def test_unprotected_deauth_on_a_protected_bss_is_high():
    watcher = ThreatWatcher()
    for seq in range(1, 11):
        watcher.observe(
            _parsed_deauth(CLIENT, seq),
            pmf_required=True,
            ssid="Cafe",
            channel=6,
            now=5 + seq * 0.1,
        )
    events = watcher.drain()
    assert events[0].level == "high"
    assert "protected" in events[0].body


def test_own_deauth_burst_is_not_a_threat():
    watcher = ThreatWatcher()
    for seq in range(1, 6):
        frame = _deauth(BROADCAST, seq)
        note_own_transmission(frame, now=30 + seq * 0.05)
        parsed = WlanFrameParser.parse_80211_frame(frame, -40)
        watcher.observe(parsed, ssid="Cafe", channel=6, now=30 + seq * 0.05)
    assert watcher.drain() == []


def test_deauth_then_handshake_is_a_forced_reconnect():
    watcher = ThreatWatcher()
    for seq in range(1, 11):
        watcher.observe(_parsed_deauth(BROADCAST, seq), ssid="Cafe", channel=6, now=80)
    watcher.drain()
    eapol = EapolPacket(
        type="eapol",
        type_id=2,
        subtype_id=0,
        bssid=BSSID,
        source=CLIENT,
        dest=BSSID,
        to_ds=True,
        from_ds=False,
        rssi=-45,
        raw=b"\x08\x01" + b"\x00" * 22,
    )
    watcher.observe(eapol, ssid="Cafe", channel=6, now=82)
    events = watcher.drain()
    assert events[0].kind == "forced_reconnect"
    assert events[0].level == "high"


def test_louder_second_bssid_for_the_same_name_is_a_rogue():
    watcher = ThreatWatcher()
    watcher.observe(_beacon(BSSID, "Cafe", 1, 6, rssi=-70), ssid="Cafe", channel=6, now=1)
    watcher.observe(
        _beacon(OTHER, "Cafe", 1, 6, rssi=-40),
        ssid="Cafe",
        channel=6,
        same_ssid_peer_count=1,
        now=2,
    )
    events = watcher.drain()
    assert events[0].kind == "rogue_ap"
    assert events[0].bssid == OTHER
    watcher.observe(_beacon(BSSID, "Cafe", 2, 6, rssi=-68), ssid="Cafe", channel=6, now=3)
    watcher.observe(_beacon("00:1e:58:00:00:12", "Cafe", 1, 6, rssi=-67), ssid="Cafe", channel=6, now=4)
    assert watcher.drain() == []


def test_many_new_names_on_one_channel_are_a_beacon_flood():
    watcher = ThreatWatcher()
    start = 1000.0
    watcher.observe(
        _beacon(BSSID, "Warmup", 1, 11),
        ssid="Warmup",
        channel=11,
        now=start,
    )
    watcher.drain()
    after_warmup = start + _SESSION_WARMUP_S + _CHANNEL_WARMUP_S + 1.0
    watcher.observe(
        _beacon(OTHER, "Prime", 1, 11),
        ssid="Prime",
        channel=11,
        now=after_warmup,
    )
    watcher.drain()
    t0 = after_warmup + _CHANNEL_WARMUP_S + 1.0
    for index in range(22):
        bssid = f"02:00:00:00:01:{index:02x}"
        watcher.observe(
            _beacon(bssid, f"Net{index}", 1, 11),
            ssid=f"Net{index}",
            channel=11,
            now=t0 + index * 0.1,
        )
    events = watcher.drain()
    assert events[-1].kind == "beacon_flood"
    assert events[-1].level == "medium"


def test_beacon_flood_is_suppressed_during_session_warmup():
    watcher = ThreatWatcher()
    start = 500.0
    for index in range(25):
        bssid = f"02:00:00:00:02:{index:02x}"
        watcher.observe(
            _beacon(bssid, f"Lab{index}", 1, 112),
            ssid=f"Lab{index}",
            channel=112,
            now=start + index * 0.05,
        )
    assert watcher.drain() == []


def test_adjacent_channel_beacon_does_not_prime_new_channel_flood_warmup():
    watcher = ThreatWatcher()
    start = 700.0
    watcher.observe(
        _beacon(BSSID, "Session", 1, 1),
        ssid="Session",
        channel=1,
        listening_channel=1,
        now=start,
    )
    leak_at = start + _SESSION_WARMUP_S + 1.0
    watcher.observe(
        _beacon(OTHER, "Bleed", 1, 112),
        ssid="Bleed",
        channel=112,
        listening_channel=108,
        now=leak_at,
    )
    first_real_scan = leak_at + _CHANNEL_WARMUP_S + 1.0
    for index in range(22):
        watcher.observe(
            _beacon(f"02:00:00:00:03:{index:02x}", f"Normal{index}", 1, 112),
            ssid=f"Normal{index}",
            channel=112,
            listening_channel=112,
            now=first_real_scan + index * 0.1,
        )
    assert watcher.drain() == []


def test_channel_switch_with_a_sequence_jump_is_high():
    watcher = ThreatWatcher()
    watcher.observe(_beacon(BSSID, "Cafe", 10, 6), ssid="Cafe", channel=6, now=1)
    switched = _beacon(
        BSSID, "Cafe", 200, 6,
        extra=bytes((0x25, 0x03, 0x01, 11, 0x00)),
    )
    watcher.observe(switched, ssid="Cafe", channel=6, now=1.2)
    events = watcher.drain()
    assert events[0].kind == "channel_switch"
    assert events[0].level == "high"
    assert "11" in events[0].body


def test_a_protected_deauth_and_a_quiet_sequence_jump():
    watcher = ThreatWatcher()
    protected = bytearray(_deauth(BROADCAST, 1))
    protected[1] = 0x40
    parsed = WlanFrameParser.parse_80211_frame(bytes(protected), -40)
    for _ in range(10):
        watcher.observe(parsed, pmf_required=True, ssid="Cafe", channel=6, now=5)
    assert watcher.drain() == []

    watcher.observe(_beacon(BSSID, "Cafe", 10, 6), ssid="Cafe", channel=6, now=1)
    quiet = _beacon(BSSID, "Cafe", 180, 6, extra=bytes((0x28, 0x01, 0x01)))
    watcher.observe(quiet, ssid="Cafe", channel=6, now=1.2)
    events = watcher.drain()
    assert events[0].title == "Quiet announcement"
    assert events[0].level == "medium"


def test_sink_scores_a_deauth_burst_for_a_known_ap():
    sink = WlanSink()
    sink.access_points[BSSID] = AccessPoint(bssid=BSSID, ssid="Cafe", channel=6)
    for seq in range(1, 11):
        parsed = _parsed_deauth(BROADCAST, seq)
        sink.update(parsed, "card", 6)
    events = sink.drain_threats()
    assert [event.kind for event in events] == ["deauth"]
    assert events[0].ssid == "Cafe"
