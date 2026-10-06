from wifit3.ui.offline_bluetooth_panels import offline_bluetooth_use_secondary_panel


def test_secondary_panel_for_anonymous_apple():
    record = {
        "name": "<Unknown>",
        "manufacturer_ids": [0x004C],
        "identifier": "AA:BB:CC:DD:EE:FF",
        "address_type": "random",
    }
    assert offline_bluetooth_use_secondary_panel(record)


def test_main_panel_for_named_device_with_gatt():
    record = {
        "name": "Apple Watch",
        "identifier": "41C28AFD-7223-CCD1-6681-2C4127D8F06E",
        "address_type": "platform-opaque",
        "model_number": "Watch7,15",
        "manufacturer_ids": [0x004C],
    }
    assert not offline_bluetooth_use_secondary_panel(record)


def test_secondary_panel_for_opaque_uuid_without_enrichment():
    record = {
        "name": "<Unknown>",
        "identifier": "41C28AFD-7223-CCD1-6681-2C4127D8F06E",
        "address_type": "platform-opaque",
        "manufacturer_ids": [],
    }
    assert offline_bluetooth_use_secondary_panel(record)
