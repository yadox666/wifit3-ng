from wifit3.bluetooth.exposure import ExposureSeverity, assess_exposure, severity_counts
from wifit3.models import (
    BluetoothCharacteristic,
    BluetoothDevice,
    BluetoothInspection,
    BluetoothService,
)

_CUSTOM_SERVICE = "12345678-1234-5678-1234-56789abcdef0"


def _device():
    return BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Sensor",
        rssi=-45,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1.0,
        last_seen=2.0,
    )


def _characteristic(handle, properties, value=""):
    return BluetoothCharacteristic(
        handle=handle,
        uuid=f"0000{handle:04x}-0000-1000-8000-00805f9b34fb",
        name=f"Characteristic {handle}",
        properties=properties,
        value=value,
    )


def _inspection(*services):
    return BluetoothInspection(
        device=_device(),
        services=[
            BluetoothService(uuid=uuid, name=f"Service {uuid[:4]}", characteristics=list(chars))
            for uuid, chars in services
        ],
    )


def test_writable_characteristic_on_firmware_update_service_is_high():
    inspection = _inspection(
        ("0000fe59-0000-1000-8000-00805f9b34fb", [_characteristic(1, ("write", "notify"))])
    )

    [finding] = assess_exposure(inspection)

    assert finding.severity is ExposureSeverity.HIGH
    assert "firmware update" in finding.reason


def test_writable_serial_bridge_and_hid_are_high():
    inspection = _inspection(
        ("6e400001-b5a3-f393-e0a9-e50e24dcca9e", [_characteristic(1, ("write-without-response",))]),
        ("1812", [_characteristic(2, ("write",))]),
    )

    assert [finding.severity for finding in assess_exposure(inspection)] == [
        ExposureSeverity.HIGH,
        ExposureSeverity.HIGH,
    ]


def test_writable_characteristic_on_ordinary_service_is_medium():
    inspection = _inspection((_CUSTOM_SERVICE, [_characteristic(1, ("write",))]))

    [finding] = assess_exposure(inspection)

    assert finding.severity is ExposureSeverity.MEDIUM


def test_value_read_without_pairing_is_low():
    inspection = _inspection((_CUSTOM_SERVICE, [_characteristic(1, ("read",), value="Acme")]))

    [finding] = assess_exposure(inspection)

    assert finding.severity is ExposureSeverity.LOW


def test_notify_only_and_unread_characteristics_are_not_flagged():
    inspection = _inspection(
        (_CUSTOM_SERVICE, [_characteristic(1, ("notify",)), _characteristic(2, ("read",))])
    )

    assert assess_exposure(inspection) == []


def test_findings_are_ordered_most_serious_first_and_counted():
    inspection = _inspection(
        (_CUSTOM_SERVICE, [
            _characteristic(1, ("read",), value="Acme"),
            _characteristic(2, ("write",)),
        ]),
        ("0000fe59-0000-1000-8000-00805f9b34fb", [_characteristic(3, ("write",))]),
    )

    findings = assess_exposure(inspection)

    assert [finding.handle for finding in findings] == [3, 2, 1]
    assert severity_counts(findings) == {
        ExposureSeverity.LOW: 1,
        ExposureSeverity.MEDIUM: 1,
        ExposureSeverity.HIGH: 1,
    }
