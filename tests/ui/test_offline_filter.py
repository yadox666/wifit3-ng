from wifit3.ui.screens.filter import EncryptionFilter
from wifit3.ui.screens.offline_filter import OfflineFilters, record_matches


def test_ap_text_and_encryption_filters():
    record = {
        "bssid": "aa:bb:cc:dd:ee:ff",
        "ssid": "CafeNet",
        "encryption": "WPA2",
        "channel": 6,
        "security": {"akms": ["PSK"]},
        "wps": {"enabled": True},
        "clients": [{"client_mac": "11:22:33:44:55:66"}],
        "positions": [{"latitude": 1.0, "longitude": 2.0, "accuracy_m": 5, "observed_at": 1}],
    }
    assert record_matches("aps", record, OfflineFilters(text="cafenet"))
    assert record_matches("aps", record, OfflineFilters(wps="yes"))
    assert not record_matches("aps", record, OfflineFilters(wps="no"))
    assert record_matches("aps", record, OfflineFilters(channel_band="2.4"))
    assert not record_matches("aps", record, OfflineFilters(channel_band="5"))
    assert record_matches(
        "aps", record, OfflineFilters(encryption=EncryptionFilter.WPA),
    )
    assert record_matches("aps", record, OfflineFilters(gps="yes"))
    assert record_matches("aps", record, OfflineFilters(ap_clients="yes"))


def test_client_and_bluetooth_filters():
    client = {
        "client_mac": "11:22:33:44:55:66",
        "access_point_count": 1,
        "access_points": [{"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:00"}],
        "positions": [],
    }
    assert record_matches("clients", client, OfflineFilters(text="home"))
    assert record_matches("clients", client, OfflineFilters(client_aps="yes"))
    assert not record_matches("clients", client, OfflineFilters(client_aps="no"))

    device = {
        "identifier": "aa:bb:cc:dd:ee:ff",
        "name": "Speaker",
        "radio_types": ["BLE", "BT"],
        "protocol": {"category": "Audio", "type": "A2DP"},
        "service_uuids": ["180f"],
    }
    assert record_matches("bluetooth", device, OfflineFilters(bt_category="Audio"))
    assert record_matches("bluetooth", device, OfflineFilters(bt_radio="both"))
    assert not record_matches("bluetooth", device, OfflineFilters(bt_radio="ble"))
    assert record_matches("bluetooth", device, OfflineFilters(text="180f"))
