"""USB Bluetooth controller capabilities for the lab layer (HCI/firmware path)."""
from __future__ import annotations

from dataclasses import dataclass

from wifit3.bluetooth.usb_hci import UsbBluetoothController


@dataclass(frozen=True, slots=True)
class UsbBluetoothCapabilities:
    chipset: str
    legacy_le_scan_only: bool
    classic_acl: bool
    le_connection: bool
    l2cap_lab: bool
    lmp_inject: bool
    notes: str

    @classmethod
    def for_controller(cls, controller: UsbBluetoothController) -> UsbBluetoothCapabilities:
        if controller.chipset == "RTL8761BU":
            return cls(
                chipset=controller.chipset,
                legacy_le_scan_only=True,
                classic_acl=controller.supports_classic,
                le_connection=controller.supports_le,
                l2cap_lab=controller.supports_classic,
                lmp_inject=False,
                notes="Legacy LE scan (0x200B/0x200C); no extended scan or stock LMP inject.",
            )
        if controller.chipset == "BlueCore4-ROM":
            return cls(
                chipset=controller.chipset,
                legacy_le_scan_only=False,
                classic_acl=True,
                le_connection=False,
                l2cap_lab=True,
                lmp_inject=False,
                notes="Classic-only USB HCI; no BLE connection on this dongle.",
            )
        return cls(
            chipset=controller.chipset,
            legacy_le_scan_only=controller.supports_le,
            classic_acl=controller.supports_classic,
            le_connection=controller.supports_le,
            l2cap_lab=controller.supports_classic,
            lmp_inject=False,
            notes="Capabilities inferred from USB interface flags.",
        )
