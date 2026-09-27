from types import SimpleNamespace

from wifit3.bluetooth.hci_protocol import HCI_READ_LOCAL_VERSION
from wifit3.bluetooth.rtl8761_firmware import RTL_DOWNLOAD_OPCODE, RTL_ROM_VERSION_OPCODE
from wifit3.bluetooth.usb_hci import (
    UsbBluetoothController,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)


def test_controller_discovery_only_lists_supported_rtl8761bu(monkeypatch):
    devices = [
        SimpleNamespace(idVendor=0x0BDA, idProduct=0x8771, bus=1, address=2),
        SimpleNamespace(idVendor=0x1234, idProduct=0x5678, bus=1, address=3),
    ]
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.usb.core.find",
        lambda **_kwargs: devices,
    )

    controllers = find_usb_bluetooth_controllers()

    assert controllers == [
        UsbBluetoothController(
            0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth 5 USB Adapter", 1, 2,
        )
    ]


def test_rtl8761bu_stock_rom_loads_verified_usb_patch():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    downloads = []

    def command(opcode, parameters=b"", timeout_ms=5000):
        del timeout_ms
        if opcode == RTL_ROM_VERSION_OPCODE:
            return b"\x00\x01"
        if opcode == RTL_DOWNLOAD_OPCODE:
            downloads.append(parameters)
            return bytes([0, parameters[0]])
        if opcode == HCI_READ_LOCAL_VERSION:
            return bytes.fromhex("000a01000a5d0022d9")
        raise AssertionError(f"unexpected opcode {opcode:#x}")

    scanner._command = command
    stock_version = bytes.fromhex("000a0b000a5d006187")

    scanner._load_realtek_firmware(stock_version)

    assert len(downloads) == 120
    assert downloads[0][0] == 0
    assert downloads[-1][0] & 0x80
