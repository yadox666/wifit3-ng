import csv

from wifit3.models import BluetoothDevice
from wifit3.persist.config import Config
from wifit3.ui.bluetooth_export import export_bluetooth_snapshot


def test_bluetooth_export_writes_device_details(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Test Beacon",
        rssi=-42,
        service_uuids=("0000180f-0000-1000-8000-00805f9b34fb",),
        service_data_uuids=("180f",),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=8,
        service_data_bytes=2,
        tx_power=-8,
        advertisement_count=12,
        advertisement_interval=0.25,
        first_seen=1,
        last_seen=2,
    )

    path = export_bluetooth_snapshot([device])

    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert path.name.startswith("bluetooth_")
    assert rows[0]["name"] == "Test Beacon"
    assert rows[0]["radio"] == "BLE"
    assert rows[0]["discovery_source"] == "system"
    assert rows[0]["manufacturer"] == "Apple, Inc. (004C)"
    assert rows[0]["signal_dbm"] == "-42"
    assert rows[0]["advertised_services"] == "Battery Service (180f)"


def test_bluetooth_export_escapes_spreadsheet_formula_names(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    device = BluetoothDevice(
        identifier="id",
        name="=FORMULA()",
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
        last_seen=2,
    )

    path = export_bluetooth_snapshot([device])

    with path.open(encoding="utf-8", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["name"] == "'=FORMULA()"
