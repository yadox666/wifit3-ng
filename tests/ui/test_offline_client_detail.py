from wifit3.ui.offline_client_detail import offline_client_detail_markup


def test_offline_client_detail_groups_focus_and_tail():
    record = {
        "client_mac": "02:11:22:33:44:55",
        "first_seen": 1_700_000_000.0,
        "last_seen": 1_700_000_200.0,
        "access_point_count": 1,
        "fingerprint_id": "aa" * 32,
        "fingerprint_completeness": 40,
        "radio_fingerprint_id": "bb" * 32,
        "radio_fingerprint_completeness": 55,
        "radio_fingerprint": {
            "payload": {
                "radio": {"phy_modes": ["802.11ax"], "vendor_ouis": ["00:50:F2"]},
                "association": {"akm_selected": 2},
                "dhcp": {"vendor_class": "android-dhcp-14"},
            },
        },
        "access_points": [
            {
                "bssid": "aa:bb:cc:dd:ee:ff",
                "ssid": "LabNet",
                "channel": 6,
                "encryption": "WPA2",
                "last_seen": 1_700_000_100.0,
            },
        ],
        "scan_sessions": [
            {
                "name": "Walk",
                "mode": "wifi",
                "first_seen": 1_700_000_000.0,
                "last_seen": 1_700_000_200.0,
                "sighting_count": 2,
            },
        ],
        "extra_note": "saved",
    }
    text = offline_client_detail_markup(record)
    assert "02:11:22:33:44:55" in text
    assert "Associated AP:" in text or "Radio:" in text
    assert "Associated access points" in text
    assert "LabNet" in text
    assert "Scan sessions" in text
    assert "Stored fields" in text
    assert "extra_note" in text
