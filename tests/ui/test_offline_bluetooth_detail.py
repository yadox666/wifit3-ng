from wifit3.ui.offline_bluetooth_detail import offline_bluetooth_detail_markup


def test_offline_bluetooth_detail_uses_device_detail_and_tail():
    record = {
        "identifier": "AA:BB:CC:DD:EE:FF",
        "name": "Apple Watch",
        "first_seen": 1_700_000_000.0,
        "last_seen": 1_700_000_100.0,
        "service_uuids": ["0000180f-0000-1000-8000-00805f9b34fb"],
        "manufacturer_ids": [0x004C],
        "radio_types": ["BLE"],
        "address_type": "random-static",
        "model_number": "Watch7,15",
        "analysis": {
            "signal": {"last_rssi": -55, "samples": 4, "trend": "stable"},
            "activity": {
                "advertisement_count": 10,
                "manufacturer_data_bytes": 8,
                "service_data_bytes": 0,
            },
            "baseline": {"status": "returning", "profile_changed": False},
        },
        "protocol": {"category": "Wearable", "type": "watch", "confidence": "high"},
        "catalog": {
            "labels": ["Apple Watch"],
            "class": "Wearable",
        },
        "fingerprint_id": "cafe" * 8,
        "fingerprint_completeness": 70,
        "scan_sessions": [
            {
                "name": "BT sweep",
                "mode": "bluetooth",
                "first_seen": 1_700_000_000.0,
                "last_seen": 1_700_000_100.0,
                "sighting_count": 1,
            },
        ],
        "internal_blob": "keep",
    }
    text = offline_bluetooth_detail_markup(record)
    assert "Apple Watch" in text
    assert "Manufacturer:" in text
    assert "Product catalog" in text
    assert "Scan sessions" in text
    assert "Stored fields" in text
    assert "internal_blob" in text
