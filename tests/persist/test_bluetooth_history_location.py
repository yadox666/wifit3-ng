import time

from wifit3.models import BluetoothDevice
from wifit3.models.location import SignalPosition
from wifit3.persist.bluetooth_history import BluetoothHistoryStore


def _device() -> BluetoothDevice:
    now = time.time()
    return BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="Tag",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(76,),
        manufacturer_data_bytes=2,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
    )


def test_location_digest_change_bypasses_write_throttle(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    device = _device()
    assert store.remember(device, force=True)

    device.last_seen += 0.5
    device.positions = [
        SignalPosition(
            latitude=40.4168,
            longitude=-3.7038,
            altitude_m=None,
            accuracy_m=8.0,
            observed_at=time.time(),
            source="test",
            rssi=-50,
        ),
    ]
    assert store.remember(device)

    analysis = store.offline_devices()[0]["analysis"]
    assert analysis["location"]["digest"]
