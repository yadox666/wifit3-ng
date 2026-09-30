from types import SimpleNamespace
import struct
import time

import pytest
import usb.core

from wifit3.bluetooth.classic_sdp import (
    L2CAP_CONFIGURATION_REQUEST,
    L2CAP_CONFIGURATION_RESPONSE,
    L2CAP_SIGNALING_CID,
    signaling_command,
)
from wifit3.bluetooth.hci_protocol import (
    HCI_INQUIRY,
    HCI_LE_SET_EVENT_MASK,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    HCI_READ_LOCAL_VERSION,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
    DiscoveryObservation,
)
from wifit3.bluetooth.rtl8761_firmware import RTL_DOWNLOAD_OPCODE, RTL_ROM_VERSION_OPCODE
from wifit3.bluetooth.usb_hci import (
    HCI_MAX_EVENT_SIZE,
    UsbBluetoothController,
    UsbBluetoothError,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)


def _hci_usb_device(**fields):
    hci = SimpleNamespace(
        bInterfaceClass=0xE0,
        bInterfaceSubClass=0x01,
        bInterfaceProtocol=0x01,
        bInterfaceNumber=0,
    )
    configuration = (hci,)
    return SimpleNamespace(
        get_active_configuration=lambda configuration=configuration: configuration,
        set_configuration=lambda: None,
        **fields,
    )


def test_controller_discovery_lists_supported_csr_and_rtl8761bu(monkeypatch):
    devices = [
        _hci_usb_device(idVendor=0x0A12, idProduct=0x0001, bus=1, address=1),
        _hci_usb_device(idVendor=0x0BDA, idProduct=0x8771, bus=1, address=2),
        _hci_usb_device(idVendor=0x0B05, idProduct=0x190E, bus=1, address=4),
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
        ),
        UsbBluetoothController(
            0x0B05, 0x190E, "RTL8761BU", "ASUS", "Bluetooth USB Adapter", 1, 4,
            supports_classic=True, supports_le=True,
        ),
    ]


def test_controller_discovery_ignores_supported_vid_pid_without_hci(monkeypatch):
    devices = [
        SimpleNamespace(
            idVendor=0x0BDA,
            idProduct=0x8771,
            bus=1,
            address=2,
            get_active_configuration=lambda: (_ for _ in ()).throw(usb.core.USBError("busy")),
            set_configuration=lambda: None,
        ),
    ]
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.usb.core.find",
        lambda **_kwargs: devices,
    )

    assert find_usb_bluetooth_controllers() == []


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


def test_event_read_requests_complete_hci_event_not_usb_packet_size():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
        supports_classic=True, supports_le=False,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    requested = []

    class Endpoint:
        bEndpointAddress = 0x81

    class Device:
        def read(self, endpoint, size, timeout):
            requested.append((endpoint, size, timeout))
            return bytes.fromhex("010100")

    scanner._event_endpoint = Endpoint()
    scanner._device = Device()

    assert scanner._read_event(750) == bytes.fromhex("010100")
    assert requested == [(0x81, HCI_MAX_EVENT_SIZE, 750)]


def test_remote_name_completion_updates_existing_classic_observation():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
        supports_classic=True, supports_le=False,
    )
    observed = []
    scanner = UsbHciScanner(controller, observed.append)
    identifier = "AA:BB:CC:DD:EE:FF"
    scanner._classic_observations[identifier] = DiscoveryObservation(
        identifier=identifier,
        radio_type="BT",
        rssi=-44,
        class_of_device=0x240404,
    )
    scanner._remote_name_pending = identifier

    scanner._handle_remote_name(
        b"\x00" + bytes.fromhex("FFEEDDCCBBAA") + b"Desk Speaker\x00"
    )

    assert observed[0].name == "Desk Speaker"
    assert observed[0].rssi == -44
    assert observed[0].class_of_device == 0x240404
    assert scanner.health.remote_name_successes == 1


def test_l2cap_send_fragments_to_controller_acl_mtu():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    writes = []

    class Device:
        def write(self, endpoint, packet, timeout):
            writes.append((endpoint, bytes(packet), timeout))

    scanner._device = Device()
    scanner._acl_out_endpoint = SimpleNamespace(bEndpointAddress=0x02)
    scanner._acl_mtu = 5
    scanner._acl_credits = 4
    scanner._acl_credit_limit = 4
    scanner._drain_hci_events = lambda _handle: None

    scanner._send_l2cap(0x0042, 0x0040, b"abcdefgh")

    assert len(writes) == 3
    assert [(int.from_bytes(packet[:2], "little") >> 12) & 3
            for _endpoint, packet, _timeout in writes] == [2, 1, 1]
    assert [int.from_bytes(packet[2:4], "little")
            for _endpoint, packet, _timeout in writes] == [5, 5, 2]
    assert scanner._acl_credits == 1


def test_l2cap_read_reassembles_split_usb_and_acl_fragments():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    handle = 0x0042
    l2cap = struct.pack("<HH", 8, 0x0040) + b"abcdefgh"
    first = struct.pack("<HH", handle | (2 << 12), 5) + l2cap[:5]
    second = struct.pack("<HH", handle | (1 << 12), 7) + l2cap[5:]
    chunks = [first[:3], first[3:] + second[:2], second[2:]]

    class Device:
        def read(self, endpoint, size, timeout):
            return chunks.pop(0)

    scanner._device = Device()
    scanner._acl_in_endpoint = SimpleNamespace(bEndpointAddress=0x82)

    cid, payload = scanner._read_l2cap(handle, time.monotonic() + 1)

    assert cid == 0x0040
    assert payload == b"abcdefgh"
    assert len(scanner.capture_records) == 2


def test_pairing_request_is_rejected_without_accepting_credentials():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    commands = []
    scanner._command = lambda opcode, parameters=b"", timeout_ms=5000: (
        commands.append((opcode, parameters)) or b"\x00"
    )

    assert scanner._handle_aux_hci_event(
        0x31, bytes.fromhex("FFEEDDCCBBAA"), 0x0042,
    )
    assert commands == [(
        HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
        bytes.fromhex("FFEEDDCCBBAA18"),
    )]


def test_l2cap_configuration_waits_for_both_directions():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    local_cid, remote_cid, request_id = 0x0040, 0x0041, 2
    packets = iter([
        (
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONFIGURATION_RESPONSE,
                request_id,
                struct.pack("<HHH", local_cid, 0, 0),
            ),
        ),
        (
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONFIGURATION_REQUEST,
                9,
                struct.pack("<HH", local_cid, 0),
            ),
        ),
    ])
    sent = []
    scanner._read_l2cap = lambda _handle, _deadline: next(packets)
    scanner._send_l2cap = lambda handle, cid, payload: sent.append(
        (handle, cid, payload)
    )

    scanner._complete_l2cap_configuration(
        0x0042, local_cid, remote_cid, request_id, time.monotonic() + 1,
    )

    assert sent == [(
        0x0042,
        L2CAP_SIGNALING_CID,
        signaling_command(
            L2CAP_CONFIGURATION_RESPONSE,
            9,
            struct.pack("<HHH", remote_cid, 0, 0),
        ),
    )]


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


def test_rtl8761bu_known_patched_identity_skips_download():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._command = lambda *_args, **_kwargs: pytest.fail(
        "patched controller must not download firmware"
    )

    scanner._load_realtek_firmware(bytes.fromhex("000a01000a5d0022d9"))


def test_rtl8761bu_rejects_unknown_controller_identity():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)

    with pytest.raises(UsbBluetoothError, match="Unsupported RTL8761BU"):
        scanner._load_realtek_firmware(bytes.fromhex("000a02000a5d003412"))


def test_rtl8761bu_requires_expected_identity_after_upload():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)

    def command(opcode, parameters=b"", timeout_ms=5000):
        del timeout_ms
        if opcode == RTL_ROM_VERSION_OPCODE:
            return b"\x00\x01"
        if opcode == RTL_DOWNLOAD_OPCODE:
            return bytes([0, parameters[0]])
        if opcode == HCI_READ_LOCAL_VERSION:
            return bytes.fromhex("000a0b000a5d006187")
        raise AssertionError(f"unexpected opcode {opcode:#x}")

    scanner._command = command

    with pytest.raises(UsbBluetoothError, match="identity was not active"):
        scanner._load_realtek_firmware(bytes.fromhex("000a0b000a5d006187"))
