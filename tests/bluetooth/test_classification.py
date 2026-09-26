from dataclasses import replace

from wifit3.bluetooth.classification import device_category
from wifit3.models import BluetoothDevice


def _device(**changes) -> BluetoothDevice:
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="<Unknown>",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1.0,
        last_seen=1.0,
    )
    return replace(device, **changes)


def test_device_category_prefers_descriptive_name():
    assert device_category(_device(name="Living Room Headphones")) == "Audio"
    assert device_category(_device(name="Pixel Phone")) == "Phone"


def test_device_category_uses_standard_service():
    assert device_category(_device(service_uuids=("1812",))) == "Input"
    assert device_category(_device(service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",))) == "Health"


def test_device_category_keeps_unknown_inference_explicit():
    assert device_category(_device()) == "Unknown"
    assert device_category(_device(name="Acme Sensor")) == "Other"
