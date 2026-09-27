import json

from wifit3.bluetooth.capture import BluetoothEventCapture
from wifit3.models import BluetoothDevice, BluetoothInspection
from wifit3.persist.config import Config


def _device(identifier="AA:BB:CC:DD:EE:FF"):
    return BluetoothDevice(
        identifier=identifier,
        name="Beacon",
        rssi=-50,
        service_uuids=("180f",),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=4,
        service_data_bytes=0,
        tx_power=-8,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1.0,
        last_seen=2.0,
    )


def test_bluetooth_capture_records_only_exact_target_events(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    capture = BluetoothEventCapture("AA:BB:CC:DD:EE:FF", "My Watch")
    capture.record_advertisement(_device("11:22:33:44:55:66"))
    capture.record_advertisement(_device())
    capture.record_inspection(BluetoothInspection(device=_device(), connected=True))
    capture.close()

    records = [
        json.loads(line) for line in capture.path.read_text("utf-8").splitlines()
    ]
    assert capture.count == 2
    assert [record["event"] for record in records] == ["advertisement", "gatt"]
    assert records[0]["data"]["identifier"] == "AA:BB:CC:DD:EE:FF"


def test_bluetooth_capture_rotates_and_stops_at_part_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    monkeypatch.setattr(Config, "target_capture_max_mb", 0)
    monkeypatch.setattr(Config, "target_capture_max_parts", 2)
    capture = BluetoothEventCapture("AA:BB:CC:DD:EE:FF", "Watch")

    capture.record_advertisement(_device())
    capture.record_advertisement(_device())
    capture.record_advertisement(_device())
    capture.close()

    assert len(capture.paths) == 2
    assert capture.count == 2
    assert capture.dropped == 1


def test_bluetooth_capture_rotates_without_part_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    monkeypatch.setattr(Config, "target_capture_max_mb", 0)
    monkeypatch.setattr(Config, "target_capture_max_parts", 0)
    capture = BluetoothEventCapture("AA:BB:CC:DD:EE:FF", "Watch")

    capture.record_advertisement(_device())
    capture.record_advertisement(_device())
    capture.record_advertisement(_device())
    capture.close()

    assert len(capture.paths) == 3
    assert capture.count == 3
    assert capture.dropped == 0
