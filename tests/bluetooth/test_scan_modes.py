from wifit3.bluetooth import scan_modes
from wifit3.bluetooth.usb_hci import UsbBluetoothController

DUAL = UsbBluetoothController(
    0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Adapter", 1, 2,
    supports_classic=True, supports_le=True,
)
CLASSIC_ONLY = UsbBluetoothController(
    0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 3,
    supports_classic=True, supports_le=False,
)
LE_ONLY = UsbBluetoothController(
    0x1234, 0x5678, "Generic", "Vendor", "BLE Dongle", 1, 4,
    supports_classic=False, supports_le=True,
)


def test_valid_modes_depend_on_capability():
    assert scan_modes.valid_modes(DUAL) == (
        scan_modes.AUTO,
        scan_modes.BT_BLE,
        scan_modes.BT,
        scan_modes.BLE,
    )
    assert scan_modes.valid_modes(CLASSIC_ONLY) == (scan_modes.AUTO, scan_modes.BT)
    assert scan_modes.valid_modes(LE_ONLY) == (scan_modes.AUTO, scan_modes.BLE)


def test_next_mode_cycles_within_valid_modes():
    assert scan_modes.next_mode(DUAL, scan_modes.AUTO) == scan_modes.BT_BLE
    assert scan_modes.next_mode(DUAL, scan_modes.BLE) == scan_modes.AUTO
    assert scan_modes.next_mode(CLASSIC_ONLY, scan_modes.BT) == scan_modes.AUTO
    # Unknown mode falls back to the first valid one.
    assert scan_modes.next_mode(LE_ONLY, "nonsense") == scan_modes.AUTO


def test_effective_auto_dual_defers_ble_to_os_when_active():
    assert scan_modes.effective_scan_radios(
        DUAL, scan_modes.AUTO, os_ble_active=True
    ) == (False, True)
    assert scan_modes.effective_scan_radios(
        DUAL, scan_modes.AUTO, os_ble_active=False
    ) == (True, True)


def test_effective_explicit_modes_respect_capability():
    assert scan_modes.effective_scan_radios(
        DUAL, scan_modes.BT, os_ble_active=False
    ) == (False, True)
    assert scan_modes.effective_scan_radios(
        DUAL, scan_modes.BLE, os_ble_active=False
    ) == (True, False)
    assert scan_modes.effective_scan_radios(
        DUAL, scan_modes.BT_BLE, os_ble_active=True
    ) == (True, True)
    # Capability caps the request: a Classic-only dongle can never do BLE.
    assert scan_modes.effective_scan_radios(
        CLASSIC_ONLY, scan_modes.AUTO, os_ble_active=False
    ) == (False, True)
    assert scan_modes.effective_scan_radios(
        LE_ONLY, scan_modes.AUTO, os_ble_active=True
    ) == (True, False)


def test_mode_label():
    assert scan_modes.mode_label(scan_modes.AUTO) == "Auto"
    assert scan_modes.mode_label(scan_modes.BT_BLE) == "BT+BLE"
    assert scan_modes.mode_label(scan_modes.BT) == "BT"
    assert scan_modes.mode_label(scan_modes.BLE) == "BLE"
