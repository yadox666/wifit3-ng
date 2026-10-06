from wifit3.ui.offline_bluetooth_table import (
    OFFLINE_BLUETOOTH_COLUMNS,
    offline_bluetooth_row_cells,
    short_offline_address_kind,
)


def test_offline_bluetooth_row_matches_scanner_columns():
    record = {
        "identifier": "AA:BB:CC:DD:EE:FF",
        "name": "Living Room TV",
        "address_type": "public",
        "radio_types": ["BLE"],
        "manufacturer_ids": [0x0075],
        "service_uuids": ["180f"],
        "model_number": "QN55",
        "last_seen": 1,
        "protocol": {"type": "television", "category": "Display"},
        "catalog": {"class": "Display", "labels": ["Samsung TV"]},
        "analysis": {
            "signal": {"last_rssi": -55},
            "activity": {"advertisement_count": 3},
            "baseline": {"status": "returning"},
        },
    }
    from rich.text import Text

    cells = offline_bluetooth_row_cells(
        record,
        location_cell=Text("·", style="dim"),
        target_cell=Text("·"),
    )
    assert len(cells) == len(OFFLINE_BLUETOOTH_COLUMNS)
    assert "Living Room TV" in str(cells[0])
    assert "QN55" in str(cells[1]) or "Samsung" in str(cells[1])
    assert str(cells[4]) == "BLE"
    assert "AA:BB:CC:DD:EE:FF" in str(cells[9])
    assert str(cells[10]) == "public"


def test_opaque_uuid_shows_kind_not_address():
    record = {
        "identifier": "41C28AFD-7223-CCD1-6681-2C4127D8F06E",
        "name": "Phone",
        "address_type": "platform-opaque",
        "radio_types": ["BLE"],
        "manufacturer_ids": [0x004C],
        "last_seen": 1,
        "analysis": {"signal": {"last_rssi": -60}, "activity": {}},
    }
    from rich.text import Text

    cells = offline_bluetooth_row_cells(
        record,
        location_cell=Text("·"),
        target_cell=Text("·"),
    )
    assert str(cells[9]).strip() == "·"
    assert short_offline_address_kind("platform-opaque") == "OS UUID"
    assert str(cells[10]) == "OS UUID"


def test_member_service_owner_replaces_unknown_manufacturer_id():
    record = {
        "identifier": "11111111-1111-1111-1111-111111111111",
        "name": "Sensor",
        "address_type": "platform-opaque",
        "radio_types": ["BLE"],
        "manufacturer_ids": [0x81DF],
        "service_uuids": ["fe03", "180f"],
        "last_seen": 1,
        "analysis": {"signal": {"last_rssi": -60}, "activity": {}},
    }
    from rich.text import Text

    cells = offline_bluetooth_row_cells(
        record,
        location_cell=Text("·"),
        target_cell=Text("·"),
    )
    assert "Amazon.com" in str(cells[6])
    assert "Battery" in str(cells[7])
    assert "Amazon" not in str(cells[7])
    assert "fe03" not in str(cells[7])
