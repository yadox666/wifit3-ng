import csv
import json
import stat
import struct

from wifit3.models import BluetoothDevice
from wifit3.persist.config import Config
from wifit3.bluetooth.usb_hci import HciCaptureRecord
from wifit3.ui.bluetooth_export import (
    export_bluetooth_bundle,
    export_bluetooth_snapshot,
    export_btsnoop,
)


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


def test_bluetooth_bundle_writes_private_json_and_jsonl(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    device = BluetoothDevice(
        identifier="40:22:33:44:55:66",
        name="Tracker",
        rssi=-60,
        service_uuids=("180f",),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=4,
        advertisement_interval=0.5,
        first_seen=1,
        last_seen=2,
        address_type="resolvable-private",
        baseline_status="returning",
        rssi_average=-62.5,
        rssi_min=-70,
        rssi_max=-60,
        rssi_samples=4,
        rssi_trend="approaching",
        appearance=0x0943,
    )

    csv_path, json_path, jsonl_path = export_bluetooth_bundle([device])

    report = json.loads(json_path.read_text("utf-8"))
    record = report["devices"][0]
    assert record["address_type"] == "resolvable-private"
    assert record["signal_trend"] == "approaching"
    assert record["exact_type"] == "Headphones"
    assert record["classification_source"] == "Appearance"
    assert record["appearance"] == "0x0943"
    assert json.loads(jsonl_path.read_text("utf-8"))["identifier"] == device.identifier
    if hasattr(stat, "S_IMODE"):
        assert stat.S_IMODE(csv_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(json_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(jsonl_path.stat().st_mode) == 0o600


def test_btsnoop_export_contains_h4_packet_and_timestamp(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))

    path = export_btsnoop([
        HciCaptureRecord(1.0, 0x01, False, bytes.fromhex("030c00")),
    ])

    data = path.read_bytes()
    assert data[:16] == b"btsnoop\x00" + struct.pack(">II", 1, 1002)
    original, included, flags, drops, timestamp = struct.unpack_from(">IIIIQ", data, 16)
    assert (original, included, flags, drops) == (4, 4, 2, 0)
    assert timestamp == 0x00DC_DDB3_0F2F_8000 + 1_000_000
    assert data[40:] == bytes.fromhex("01030c00")
