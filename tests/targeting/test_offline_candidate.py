from wifit3.targeting import offline_record_candidate


def test_offline_ap_candidate_uses_bssid_and_ssid():
    candidate = offline_record_candidate(
        "aps",
        {
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "Lab",
            "channel": 6,
            "positions": [{"latitude": 1.0}],
        },
    )
    assert candidate is not None
    assert candidate.medium == "wifi"
    assert candidate.kind == "ap"
    assert candidate.identifier == "aa:bb:cc:dd:ee:ff"
    assert candidate.title == "Lab"
    assert "positions" not in candidate.details
    assert candidate.details["channel"] == 6


def test_offline_client_and_bluetooth_candidates():
    client = offline_record_candidate(
        "clients",
        {"client_mac": "11:22:33:44:55:66", "access_point_count": 2},
    )
    assert client is not None
    assert client.kind == "client"
    assert client.identifier == "11:22:33:44:55:66"

    device = offline_record_candidate(
        "bluetooth",
        {"identifier": "aa:bb:cc:dd:ee:ff", "name": "Sensor", "radio_types": ["ble"]},
    )
    assert device is not None
    assert device.medium == "bluetooth"
    assert device.kind == "device"
    assert device.title == "Sensor"
