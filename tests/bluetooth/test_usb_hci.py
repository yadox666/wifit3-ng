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
    HCI_INQUIRY_CANCEL,
    HCI_LE_SET_EVENT_MASK,
    HCI_LE_READ_BUFFER_SIZE,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    HCI_READ_BUFFER_SIZE,
    HCI_READ_LOCAL_VERSION,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
    DiscoveryObservation,
)
from wifit3.models.bluetooth_device import CLASSIC_RADIO, BluetoothDevice
from wifit3.bluetooth.rtl8761_firmware import RTL_DOWNLOAD_OPCODE, RTL_ROM_VERSION_OPCODE
from wifit3.bluetooth.usb_hci import (
    HCI_MAX_EVENT_SIZE,
    _LE_SCAN_DWELL_S,
    UsbBluetoothController,
    UsbBluetoothError,
    UsbHciScanner,
    find_usb_bluetooth_controllers,
)


def _usb_error(errno: int, message: str) -> usb.core.USBError:
    exc = usb.core.USBError(message)
    exc.errno = errno
    return exc


def _hci_usb_device(**fields):
    hci = SimpleNamespace(
        bInterfaceClass=0xE0,
        bInterfaceSubClass=0x01,
        bInterfaceProtocol=0x01,
        bInterfaceNumber=0,
    )
    configuration = [hci]
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


def test_macos_detach_permission_denied_still_claims(monkeypatch):
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Adapter", 0, 8,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    monkeypatch.setattr("wifit3.bluetooth.usb_hci.sys.platform", "darwin")

    intr = SimpleNamespace(bEndpointAddress=0x81, bmAttributes=0x03)
    bulk_in = SimpleNamespace(bEndpointAddress=0x82, bmAttributes=0x02)
    bulk_out = SimpleNamespace(bEndpointAddress=0x02, bmAttributes=0x02)

    class HciIface:
        bInterfaceClass = 0xE0
        bInterfaceSubClass = 0x01
        bInterfaceProtocol = 0x01
        bInterfaceNumber = 0

        def __iter__(self):
            return iter([intr, bulk_out, bulk_in])

    hci = HciIface()
    configuration = [hci]
    device = SimpleNamespace(
        get_active_configuration=lambda configuration=configuration: configuration,
        set_configuration=lambda: None,
        is_kernel_driver_active=lambda _iface: True,
        detach_kernel_driver=lambda _iface: (_ for _ in ()).throw(_usb_error(13, "Access denied")),
    )
    claimed = []

    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.usb.core.find",
        lambda **_kwargs: device,
    )
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_hci.usb.util.claim_interface",
        lambda _device, iface: claimed.append(iface),
    )

    scanner._open_once()

    assert claimed == [0]
    assert scanner._device is device


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


def test_hci_reset_timeout_retries_once(monkeypatch):
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    attempts = []
    monkeypatch.setattr("wifit3.bluetooth.usb_hci.time.sleep", lambda _delay: None)

    def command(opcode, parameters=b"", timeout_ms=5000):
        del parameters, timeout_ms
        assert opcode == HCI_RESET
        attempts.append(opcode)
        if len(attempts) == 1:
            raise UsbBluetoothError("HCI command 0x0c03 timed out")
        return b"\x00"

    scanner._command = command
    scanner._pending_events.append((0xFF, b"stale"))
    scanner._acl_stream.extend(b"stale")

    scanner._reset_controller()

    assert attempts == [HCI_RESET, HCI_RESET]
    assert not scanner._pending_events
    assert not scanner._acl_stream


def test_hci_reset_double_timeout_is_actionable(monkeypatch):
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    monkeypatch.setattr("wifit3.bluetooth.usb_hci.time.sleep", lambda _delay: None)
    scanner._command = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        UsbBluetoothError("HCI command 0x0c03 timed out"),
    )

    with pytest.raises(UsbBluetoothError, match="after 2 attempts.*unplug/replug"):
        scanner._reset_controller()


def test_prepare_le_acl_buffers_seeds_from_le_buffer_size():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._acl_credits = 0
    scanner._acl_mtu = 0

    def command(opcode, parameters=b"", timeout_ms=5000):
        if opcode == HCI_LE_READ_BUFFER_SIZE:
            # status, LE_ACL_Data_Packet_Length(2), Total_Num_LE_ACL_Data_Packets(1)
            return b"\x00" + struct.pack("<H", 251) + bytes((7,))
        pytest.fail(f"unexpected opcode 0x{opcode:04x}")

    scanner._command = command
    scanner.prepare_le_acl_buffers()

    assert scanner._acl_mtu == 251
    assert scanner._acl_credits == 7
    assert scanner._acl_credit_limit == 7


def test_prepare_le_acl_buffers_falls_back_to_shared_pool():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._acl_credits = 0
    scanner._acl_mtu = 0

    def command(opcode, parameters=b"", timeout_ms=5000):
        if opcode == HCI_LE_READ_BUFFER_SIZE:
            # Zero LE pool means the BR/EDR buffers are shared.
            return b"\x00" + struct.pack("<H", 0) + bytes((0,))
        if opcode == HCI_READ_BUFFER_SIZE:
            # status, ACL_len(2), SCO_len(1), Num_ACL(2), Num_SCO(2)
            return b"\x00" + struct.pack("<H", 1021) + b"\x00" + struct.pack(
                "<H", 4,
            ) + struct.pack("<H", 0)
        pytest.fail(f"unexpected opcode 0x{opcode:04x}")

    scanner._command = command
    scanner.prepare_le_acl_buffers()

    assert scanner._acl_mtu == 1021
    assert scanner._acl_credits == 4


def test_send_l2cap_uses_le_pb_flag_for_registered_handles():
    """LE-U links must use PB flag 0b00; BR/EDR uses the auto-flushable 0b10."""
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._acl_mtu = 27
    scanner._acl_credits = 8
    sent: list[tuple[int, int, bytes]] = []
    scanner._send_acl_fragment = lambda handle, boundary, fragment: sent.append(
        (handle, boundary, fragment),
    )

    # Classic handle: first fragment is auto-flushable (0b10).
    scanner._send_l2cap(0x000B, 0x0006, b"\x01")
    assert sent[-1][1] == 0x02

    # LE handle: first fragment must be non-flushable (0b00).
    scanner.register_le_acl_handle(0x0010)
    scanner._send_l2cap(0x0010, 0x0006, b"\x01")
    assert sent[-1][0] == 0x0010
    assert sent[-1][1] == 0x00

    # After disconnect, the handle reverts to the BR/EDR default.
    scanner.unregister_le_acl_handle(0x0010)
    scanner._send_l2cap(0x0010, 0x0006, b"\x01")
    assert sent[-1][1] == 0x02


@pytest.mark.asyncio
async def test_dual_mode_leaves_le_dwell_before_next_inquiry():
    """A dual-mode dongle must not re-arm inquiry immediately; LE needs airtime."""
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    commands = []
    scanner._command = lambda opcode, parameters=b"", timeout_ms=5000: (
        commands.append(opcode) or b"\x00"
    )
    scanner._device = object()
    scanner._running = True

    # Inquiry just completed: within the LE dwell, no new inquiry is issued.
    scanner._classic_inquiry_active = False
    scanner._last_inquiry_complete_at = time.monotonic()
    await scanner._service_classic_schedule()
    assert HCI_INQUIRY not in commands

    # Once the LE dwell has elapsed, inquiry is re-armed and marked active.
    scanner._last_inquiry_complete_at = time.monotonic() - (_LE_SCAN_DWELL_S + 1.0)
    await scanner._service_classic_schedule()
    assert commands == [HCI_INQUIRY]
    assert scanner._classic_inquiry_active is True


def test_os_ble_mode_uses_longer_classic_inquiry():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
        supports_classic=True, supports_le=True,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    assert scanner._classic_inquiry_length() == 0x05
    scanner.use_os_ble_for_le_discovery()
    assert scanner._classic_inquiry_length() == 0x0A
    parameters, timeout_ms = scanner._classic_inquiry_command()
    assert parameters[3] == 0x0A
    assert timeout_ms >= 14_000


@pytest.mark.asyncio
async def test_classic_only_adapter_rearms_inquiry_without_le_dwell():
    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
        supports_classic=True, supports_le=False,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    commands = []
    scanner._command = lambda opcode, parameters=b"", timeout_ms=5000: (
        commands.append(opcode) or b"\x00"
    )
    scanner._device = object()
    scanner._running = True
    scanner._classic_inquiry_active = False
    scanner._last_inquiry_complete_at = time.monotonic()

    await scanner._service_classic_schedule()

    assert commands == [HCI_INQUIRY]


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


@pytest.mark.asyncio
async def test_browse_sdp_uses_stored_device_when_usb_cache_is_empty():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    identifier = "AA:BB:CC:DD:EE:FF"
    device = BluetoothDevice(
        identifier=identifier,
        name="Desk Speaker",
        rssi=-50,
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
        radio_types=(CLASSIC_RADIO,),
        page_scan_repetition_mode=1,
        clock_offset=0x1234,
    )
    captured = []

    def fake_browse(observation):
        captured.append(observation)
        return ()

    scanner._browse_sdp = fake_browse
    scanner._device = object()
    scanner._running = False
    scanner._scan_task = None

    await scanner.browse_sdp(identifier, fallback_device=device)

    assert captured[0].identifier == identifier
    assert captured[0].clock_offset == 0x1234
    assert scanner._classic_observations[identifier].name == "Desk Speaker"


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
            # Linux btusb logs this as fw version 0xdfc6d922 after upload.
            return bytes.fromhex("000ac6df0a5d0022d9")
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


def test_rtl8761bu_linux_patched_identity_skips_download():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._command = lambda *_args, **_kwargs: pytest.fail(
        "patched controller must not download firmware"
    )

    scanner._load_realtek_firmware(bytes.fromhex("000ac6df0a5d0022d9"))


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


def test_discover_classic_target_finds_inquiry_result():
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    identifier = "AA:BB:CC:DD:EE:FF"
    inquiry_payload = bytes.fromhex("01FFEEDDCCBBAA01000404041234B0")
    events = [
        bytes([0x22, len(inquiry_payload)]) + inquiry_payload,
        bytes([0x01, 0x01, 0x00]),
    ]

    def command(opcode, parameters=b"", timeout_ms=5000):
        del parameters, timeout_ms
        if opcode == HCI_INQUIRY_CANCEL:
            return b"\x00"
        if opcode == HCI_INQUIRY:
            return b"\x00"
        raise AssertionError(f"unexpected opcode {opcode:#x}")

    def read_event(timeout_ms=500):
        del timeout_ms
        return events.pop(0) if events else None

    scanner._device = object()
    scanner._command = command
    scanner._read_event = read_event

    found = scanner._discover_classic_target(identifier, timeout_s=1.0)

    assert found is not None
    assert found.identifier == identifier
    assert found.page_scan_repetition_mode == 1


def test_classic_acl_connect_recovers_from_existing_link_0x0b():
    """HCI 0x0b (ACL already exists) tears down the stale link, then re-pages."""
    from wifit3.bluetooth.hci_protocol import (
        HCI_CREATE_CONNECTION,
        HCI_CREATE_CONNECTION_CANCEL,
        HCI_READ_BUFFER_SIZE,
    )

    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._acl_in_endpoint = SimpleNamespace(bEndpointAddress=0x82)
    scanner._acl_out_endpoint = SimpleNamespace(bEndpointAddress=0x02)
    identifier = "00:12:6F:FF:2A:F2"
    address = bytes.fromhex(identifier.replace(":", ""))[::-1]
    # A handle leaked from an earlier page that completed after we gave up.
    scanner._classic_acl_handles[identifier.casefold()] = 0x002A

    create_calls = []
    cancels = []
    disconnects = []

    def command(opcode, parameters=b"", timeout_ms=5000):
        del timeout_ms
        if opcode == HCI_READ_BUFFER_SIZE:
            return bytes.fromhex("0040000004000000")
        if opcode == 0x0402:  # INQUIRY_CANCEL
            return b"\x00"
        if opcode == HCI_CREATE_CONNECTION_CANCEL:
            cancels.append(parameters)
            return b"\x00"
        if opcode == 0x0406:  # DISCONNECT
            disconnects.append(parameters)
            return b"\x00"
        if opcode == HCI_CREATE_CONNECTION:
            create_calls.append(parameters)
            if len(create_calls) == 1:
                raise UsbBluetoothError(
                    "HCI command 0x0405 returned status 0x0b",
                    hci_status=0x0B,
                )
            return b"\x00"
        raise AssertionError(f"unexpected opcode {opcode:#x}")

    def wait_event(event_code, timeout_ms, *, handle=0):
        del timeout_ms, handle
        if event_code == 0x03:  # CONNECTION_COMPLETE
            return b"\x00" + struct.pack("<H", 0x000C) + address + b"\x01\x00"
        if event_code == 0x05:  # DISCONNECTION_COMPLETE
            return b"\x00" + struct.pack("<H", 0x002A) + b"\x16"
        raise AssertionError(f"unexpected event {event_code:#x}")

    scanner._command = command
    scanner._wait_event = wait_event
    scanner._read_event = lambda timeout_ms=500: None

    observation = DiscoveryObservation(
        identifier=identifier,
        radio_type=CLASSIC_RADIO,
        rssi=-50,
        page_scan_repetition_mode=1,
        clock_offset=0x028A,
    )
    handle = scanner._classic_acl_connect(observation)

    assert handle == 0x000C
    assert len(create_calls) == 2  # first 0x0b, recover, second succeeds
    assert disconnects  # stale tracked handle was torn down
    assert cancels  # create-connection-cancel issued during recovery
    assert scanner._classic_acl_handles[identifier.casefold()] == 0x000C
    # Recovery re-prepared the ACL buffers, so credits/MTU are valid (not zeroed).
    assert scanner._acl_mtu == 0x40
    assert scanner._acl_credits == 4


def test_classic_acl_connect_adopts_late_completed_link_on_0x0b():
    """HCI 0x0b with a live (late-completed) link adopts it instead of re-paging."""
    from wifit3.bluetooth.hci_protocol import (
        HCI_CREATE_CONNECTION,
        HCI_READ_BUFFER_SIZE,
    )

    controller = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 1,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._acl_in_endpoint = SimpleNamespace(bEndpointAddress=0x82)
    scanner._acl_out_endpoint = SimpleNamespace(bEndpointAddress=0x02)
    identifier = "00:12:6F:FF:2A:F2"
    address = bytes.fromhex(identifier.replace(":", ""))[::-1]
    # A page that completed late sits buffered as a Connection Complete event.
    scanner._pending_events.append(
        (0x03, b"\x00" + struct.pack("<H", 0x000C) + address + b"\x01\x00"),
    )

    create_calls = []

    def command(opcode, parameters=b"", timeout_ms=5000):
        del timeout_ms
        if opcode == HCI_READ_BUFFER_SIZE:
            return bytes.fromhex("0040000004000000")
        if opcode == 0x0402:  # INQUIRY_CANCEL
            return b"\x00"
        if opcode == HCI_CREATE_CONNECTION:
            create_calls.append(parameters)
            raise UsbBluetoothError(
                "HCI command 0x0405 returned status 0x0b",
                hci_status=0x0B,
            )
        raise AssertionError(f"unexpected opcode {opcode:#x}")

    scanner._command = command
    scanner._read_event = lambda timeout_ms=500: None

    observation = DiscoveryObservation(
        identifier=identifier,
        radio_type=CLASSIC_RADIO,
        rssi=-50,
        page_scan_repetition_mode=1,
        clock_offset=0x027E,
    )
    handle = scanner._classic_acl_connect(observation)

    assert handle == 0x000C  # adopted the live link
    assert len(create_calls) == 1  # no second page; no re-paging loop
    assert scanner._classic_acl_handles[identifier.casefold()] == 0x000C
    assert scanner._acl_credits == 4  # buffers remain valid


def _bonded_scanner(tmp_path):
    from wifit3.persist.bluetooth_bonds import BluetoothBondStore

    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Adapter", 0, 8,
    )
    store = BluetoothBondStore(tmp_path / "bonds.json")
    return UsbHciScanner(controller, lambda _observation: None, bond_store=store), store


def test_remember_session_link_key_persists_to_bond_store(tmp_path):
    scanner, store = _bonded_scanner(tmp_path)
    identifier = "00:12:6F:FF:2A:F2"
    link_key = bytes(range(16))

    scanner.remember_session_link_key(identifier, link_key, key_type=0, name="stonmore 2")

    assert scanner.has_session_link_key(identifier) is True
    bond = store.get(identifier)
    assert bond is not None
    assert bond.link_key == link_key


def test_new_scanner_loads_persisted_bond_for_reconnect(tmp_path):
    first, store = _bonded_scanner(tmp_path)
    identifier = "00:12:6F:FF:2A:F2"
    link_key = bytes(range(16))
    first.remember_session_link_key(identifier, link_key)

    # A fresh scanner in a future session reuses the same persistent store.
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Adapter", 0, 8,
    )
    second = UsbHciScanner(controller, lambda _observation: None, bond_store=store)

    assert second.has_session_link_key(identifier) is True
    assert second._session_link_keys[identifier.casefold()] == link_key


def test_forget_bond_removes_from_ram_and_store(tmp_path):
    scanner, store = _bonded_scanner(tmp_path)
    identifier = "00:12:6F:FF:2A:F2"
    scanner.remember_session_link_key(identifier, bytes(range(16)))

    assert scanner.forget_bond(identifier) is True
    assert scanner.has_session_link_key(identifier) is False
    assert store.get(identifier) is None


def test_remember_session_link_key_can_skip_persistence(tmp_path):
    scanner, store = _bonded_scanner(tmp_path)
    identifier = "00:12:6F:FF:2A:F2"

    scanner.remember_session_link_key(identifier, bytes(range(16)), persist=False)

    assert scanner.has_session_link_key(identifier) is True
    assert store.get(identifier) is None

