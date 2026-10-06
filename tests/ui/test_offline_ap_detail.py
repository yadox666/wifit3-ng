from wifit3.ui.offline_ap_detail import offline_ap_detail_markup


def test_offline_ap_detail_groups_focus_sections_and_raw_tail():
    record = {
        "bssid": "b4:1e:52:10:20:30",
        "ssid": "Flock-ABC123",
        "channel": 6,
        "encryption": "WPA2",
        "first_seen": 1_700_000_000.0,
        "last_seen": 1_700_000_100.0,
        "capabilities": {
            "phy_modes": ["802.11ax"],
            "channel_widths_mhz": [20, 40],
            "catalog_class": "Surveillance",
            "catalog_labels": ["Flock Safety Cameras"],
            "custom_lab_note": "keep-me",
        },
        "security": {
            "akms": ["PSK"],
            "pmf_capable": True,
        },
        "fingerprint_id": "abcdef1234567890",
        "fingerprint_completeness": 72,
        "clients": [{"client_mac": "02:00:00:00:00:01", "last_seen": 1_700_000_050.0}],
        "scan_sessions": [
            {
                "name": "Morning scan",
                "mode": "passive",
                "first_seen": 1_700_000_000.0,
                "last_seen": 1_700_000_100.0,
                "sighting_count": 3,
            },
        ],
        "misc_blob": {"nested": True},
    }
    text = offline_ap_detail_markup(record)
    assert "Operating Channel:" in text
    assert "Product catalog" in text
    assert "History" in text
    assert "Scan sessions" in text
    assert "Associated clients" in text
    assert "Stored fields" in text
    assert "capabilities.custom_lab_note" in text
    assert "misc_blob.nested" in text
