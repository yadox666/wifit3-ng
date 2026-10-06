from wifit3.models import AccessPoint, BluetoothDevice, Client
from wifit3.persist.targets import TargetStore
from wifit3.targeting import (
    catalog_family_candidate,
    is_target_entry,
    is_whitelisted_entry,
    iter_wifi_client_sightings,
    match_access_point,
    match_candidate,
    match_bluetooth_device,
    match_client,
    target_matches_wifi_ap,
)
from wifit3.targeting import ap_candidate, client_candidate
from wifit3.ui.target_filter import ap_matches_target_filter


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


def test_bluetooth_target_matches_probable_dual_radio_counterpart(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    saved = store.upsert(
        alias="Speaker",
        medium="bluetooth",
        kind="device",
        identifier="AA:BB:CC:DD:EE:FF",
        details={
            "probable_links": [{
                "identifier": "11:22:33:44:55:66",
                "confidence": "high",
            }],
        },
    )
    counterpart = BluetoothDevice(
        identifier="11:22:33:44:55:66",
        name="<Unknown>",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1,
        last_seen=1,
    )

    assert match_bluetooth_device(store, counterpart) == saved


def test_grouped_target_matches_each_member_type(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    grouped = store.upsert(
        alias="yadox",
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        details={"ssid": "Home"},
    )
    store.upsert(
        alias="yadox",
        medium="wifi",
        kind="client",
        identifier="02:11:22:33:44:55",
        details={},
    )
    store.upsert(
        alias="yadox",
        medium="bluetooth",
        kind="device",
        identifier="ble-device-id",
        details={"name": "Phone BLE"},
    )
    bluetooth = BluetoothDevice(
        identifier="ble-device-id",
        name="Phone BLE",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1,
        last_seen=1,
    )

    assert match_access_point(
        store,
        _ap("Home", "aa:bb:cc:dd:ee:ff"),
    ) == grouped
    assert match_client(
        store,
        Client(mac="02:11:22:33:44:55"),
    ) == grouped
    assert match_bluetooth_device(store, bluetooth) == grouped


def test_catalog_family_member_matches_aps_by_stock_rules(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    grouped = store.upsert(
        alias="ISP routers",
        medium="catalog",
        kind="family",
        identifier="home-router-isp",
        details=catalog_family_candidate("home-router-isp").details,
        match_mode="id",
    )
    ap = _ap("MOVISTAR-WIFI6-A250", "11:22:33:44:55:66")
    assert match_access_point(store, ap) == grouped
    assert target_matches_wifi_ap(grouped, ap)
    assert ap_matches_target_filter(store, ap, grouped.id)
    other = _ap("RandomCafe", "aa:bb:cc:dd:ee:01")
    assert not target_matches_wifi_ap(grouped, other)
