import struct

from wifit3.bluetooth.gatt_metadata import decode_pnp_id, display_model_label
from wifit3.bluetooth.microsoft_identifiers import format_pnp_label
from wifit3.models import BluetoothDevice


def test_microsoft_bt_pnp_product_0x0001_maps_to_windows_pc():
    raw = struct.pack("<BHHH", 0x01, 0x0006, 0x0001, 0x0A00)
    assert decode_pnp_id(raw) == "Windows PC (Bluetooth)"
    assert format_pnp_label(
        "Microsoft · product 0x0001 · v2560",
    ) == "Windows PC (Bluetooth)"


def test_display_model_label_formats_stored_microsoft_pnp():
    device = BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="DESKTOP-TEST",
        rssi=-80,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=1.0,
        pnp_id="Microsoft · product 0x0001 · v2560",
    )
    assert display_model_label(device) == "Windows PC (Bluetooth)"
