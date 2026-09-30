from wifit3.models import AccessPoint, Client
from wifit3.persist.targets import TargetStore
from wifit3.targeting import (
    is_target_entry,
    is_whitelisted_entry,
    iter_wifi_client_sightings,
    match_access_point,
    match_candidate,
    match_client,
)
from wifit3.targeting import TargetCandidate, ap_candidate


def _ap(ssid: str, bssid: str) -> AccessPoint:
    return AccessPoint(bssid=bssid, ssid=ssid, channel=6, encryption="WPA2")


def test_match_access_point_by_ssid_name(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    store.upsert(
        alias="Guest network",
        medium="wifi",
        kind="ap",
        identifier="GuestWiFi",
        details={"ssid": "GuestWiFi"},
        role="whitelist",
        match_mode="name",
    )
    ap = _ap("GuestWiFi", "aa:bb:cc:dd:ee:01")
    matched = match_access_point(store, ap)
    assert matched is not None
    assert is_whitelisted_entry(matched)


def test_match_client_by_directed_probe_and_ap_ssid_name(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    store.upsert(
        alias="Yago phone",
        medium="wifi",
        kind="client",
        identifier="YagoHansen",
        details={"probe_ssid": "YagoHansen"},
        match_mode="probe",
    )
    store.upsert(
        alias="Guest LAN",
        medium="wifi",
        kind="ap",
        identifier="GuestWiFi",
        details={"ssid": "GuestWiFi"},
        match_mode="name",
    )
    client = Client(mac="11:22:33:44:55:66")
    client.probed_ssids.add("YagoHansen")
    assert is_target_entry(match_client(store, client))
    client2 = Client(mac="aa:bb:cc:dd:ee:01")
    client2.probed_ssids.add("GuestWiFi")
    assert is_target_entry(match_client(store, client2))
    sightings = iter_wifi_client_sightings(store, client)
    assert any("probing YagoHansen" in where for _t, where in sightings)


def test_match_candidate_prefers_existing_bssid(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    saved = store.upsert(
        alias="Lab",
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        details={"ssid": "Lab"},
    )
    candidate = ap_candidate(_ap("Lab", "aa:bb:cc:dd:ee:ff"))
    assert match_candidate(store, candidate).id == saved.id
