from wifit3.models import AccessPoint, Client
from wifit3.persist.targets import TargetStore
from wifit3.ui.target_filter import (
    TARGET_ANY,
    ap_matches_target_filter,
    client_matches_target_filter,
)


def test_scan_target_filters(tmp_path):
    store = TargetStore(tmp_path / "targets.sqlite3")
    store.upsert(
        alias="Home",
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        details={},
    )
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="Home")
    other = AccessPoint(bssid="11:22:33:44:55:66", ssid="Other")
    assert ap_matches_target_filter(store, ap, TARGET_ANY)
    assert not ap_matches_target_filter(store, other, TARGET_ANY)
    client = Client(mac="de:ad:be:ef:00:01")
    client.probed_ssids.add("Home")
    store.upsert(
        alias="Home probe",
        medium="wifi",
        kind="ap",
        identifier="Home",
        details={"ssid": "Home"},
        match_mode="name",
    )
    assert client_matches_target_filter(store, client, TARGET_ANY)
