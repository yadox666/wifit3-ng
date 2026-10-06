"""Auto role assignment for enabled Bluetooth radios."""
from wifit3.bluetooth.roles import (
    BLE_LAB,
    BLE_SCAN,
    CLASSIC_LAB,
    CLASSIC_SCAN,
    auto_assign,
)
from wifit3.bluetooth.sources import OS_SOURCE_ID
from wifit3.bluetooth.usb_hci import UsbBluetoothController

SENA = UsbBluetoothController(
    0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 2,
    supports_classic=True, supports_le=False,
)
RTL1 = UsbBluetoothController(0x0BDA, 0x8771, "RTL8761BU", "Realtek", "A", 1, 3)
RTL2 = UsbBluetoothController(0x0BDA, 0x8771, "RTL8761BU", "Realtek", "A", 1, 4)


def test_os_plus_sena_plus_realtek_splits_roles():
    assignment = auto_assign([SENA, RTL1], os_ble_active=True)
    assert assignment.os_roles == (BLE_SCAN,)
    assert assignment.roles_for("usb:sena") == (CLASSIC_SCAN,)
    assert assignment.roles_for("usb:realtek") == (BLE_LAB, CLASSIC_LAB)


def test_os_plus_single_realtek():
    assignment = auto_assign([RTL1], os_ble_active=True)
    assert assignment.os_roles == (BLE_SCAN,)
    assert assignment.roles_for("usb:realtek") == (CLASSIC_SCAN, BLE_LAB, CLASSIC_LAB)


def test_os_only_keeps_ble_scan_and_lab():
    assignment = auto_assign([], os_ble_active=True)
    assert assignment.os_roles == (BLE_SCAN, BLE_LAB)


def test_sena_only_has_no_le_roles():
    assignment = auto_assign([SENA], os_ble_active=False)
    assert assignment.roles_for("usb:sena") == (CLASSIC_SCAN, CLASSIC_LAB)
    assert assignment.os_roles == ()


def test_realtek_only_covers_all_roles():
    assignment = auto_assign([RTL1], os_ble_active=False)
    assert assignment.roles_for("usb:realtek") == (
        BLE_SCAN, CLASSIC_SCAN, BLE_LAB, CLASSIC_LAB,
    )


def test_two_realteks_dedicate_second_to_ble():
    assignment = auto_assign([RTL1, RTL2], os_ble_active=True)
    assert assignment.os_roles == (BLE_SCAN,)
    assert assignment.roles_for("usb:realtek-1") == (CLASSIC_SCAN, CLASSIC_LAB)
    assert assignment.roles_for("usb:realtek-2") == (BLE_SCAN, BLE_LAB)
