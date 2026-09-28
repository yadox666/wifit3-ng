from types import SimpleNamespace

from wifit3.bluetooth.hci_protocol import (
    HCI_INQUIRY,
    HCI_LE_SET_EVENT_MASK,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_READ_LOCAL_VERSION,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
)
from wifit3.bluetooth.rtl8761_firmware import RTL_DOWNLOAD_OPCODE, RTL_ROM_VERSION_OPCODE
from wifit3.bluetooth.usb_hci import (
    UsbBluetoothController,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)


def test_controller_discovery_lists_supported_csr_and_rtl8761bu(monkeypatch):
    devices = [
        SimpleNamespace(idVendor=0x0A12, idProduct=0x0001, bus=1, address=1),
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
            0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
            supports_classic=True, supports_le=False,
        ),
        UsbBluetoothController(
            0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth 5 USB Adapter", 1, 2,
            supports_classic=True, supports_le=True,
        )
    ]


def test_bluecore4_starts_classic_without_sending_le_commands():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
        supports_classic=True, supports_le=False,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    commands = []
    scanner._open = lambda: None
    scanner._load_realtek_firmware = lambda _version: None

    def command(opcode, parameters=b"", timeout_ms=5000):
        del timeout_ms
        commands.append((opcode, parameters))
        return bytes.fromhex("00035c0c030a005c0c") if opcode == HCI_READ_LOCAL_VERSION else b"\x00"

    scanner._command = command
    scanner._open_and_start()

    assert [opcode for opcode, _parameters in commands] == [
        HCI_RESET,
        HCI_READ_LOCAL_VERSION,
        HCI_SET_EVENT_MASK,
        HCI_WRITE_INQUIRY_MODE,
        HCI_INQUIRY,
    ]
    assert commands[2][1] == bytes.fromhex("fffffbff03000000")
    assert commands[3][1] == b"\x01"
    assert not {
        HCI_LE_SET_EVENT_MASK,
        HCI_LE_SET_SCAN_PARAMETERS,
        HCI_LE_SET_SCAN_ENABLE,
    } & {opcode for opcode, _parameters in commands}


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
