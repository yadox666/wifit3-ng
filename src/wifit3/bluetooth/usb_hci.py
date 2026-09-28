from __future__ import annotations

import asyncio
import logging
import struct
import time
from collections import deque
from dataclasses import dataclass, replace
from typing import Callable

import libusb_package
import usb.core
import usb.util

from wifit3.bluetooth.hci_protocol import (
    HCI_CREATE_CONNECTION,
    HCI_CREATE_CONNECTION_CANCEL,
    HCI_DISCONNECT,
    HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    HCI_LINK_KEY_REQUEST_NEG_REPLY,
    HCI_PIN_CODE_REQUEST_NEG_REPLY,
    EVENT_INQUIRY_COMPLETE,
    EVENT_REMOTE_NAME_REQUEST_COMPLETE,
    HCI_INQUIRY,
    HCI_INQUIRY_CANCEL,
    HCI_LE_SET_EVENT_MASK,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_READ_LOCAL_VERSION,
    HCI_READ_BUFFER_SIZE,
    HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY,
    HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY,
    HCI_USER_PASSKEY_REQUEST_NEG_REPLY,
    HCI_REMOTE_NAME_REQUEST,
    HCI_REMOTE_NAME_REQUEST_CANCEL,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
    DiscoveryObservation,
    command_packet,
    command_result,
    parse_discovery_event,
    parse_event,
    parse_remote_name_event,
)
from wifit3.bluetooth.classic_sdp import (
    L2CAP_CONFIGURATION_REQUEST,
    L2CAP_CONFIGURATION_RESPONSE,
    L2CAP_CONNECTION_REQUEST,
    L2CAP_CONNECTION_RESPONSE,
    L2CAP_DISCONNECTION_REQUEST,
    L2CAP_DISCONNECTION_RESPONSE,
    L2CAP_ECHO_REQUEST,
    L2CAP_ECHO_RESPONSE,
    L2CAP_INFORMATION_REQUEST,
    L2CAP_INFORMATION_RESPONSE,
    L2CAP_SIGNALING_CID,
    SDP_PSM,
    SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE,
    SdpProtocolError,
    SdpService,
    iter_signaling_commands,
    l2cap_packet,
    parse_service_records,
    parse_service_search_attribute_response,
    service_search_attribute_request,
    signaling_command,
)
from wifit3.bluetooth.rtl8761_firmware import (
    RTL_DOWNLOAD_OPCODE,
    RTL_ROM_VERSION_OPCODE,
    download_fragments,
    load_download_image,
)

logger = logging.getLogger(__name__)

HCI_MAX_EVENT_SIZE = 257
HCI_MAX_ACL_SIZE = 4096
EVENT_CONNECTION_COMPLETE = 0x03
EVENT_DISCONNECTION_COMPLETE = 0x05
EVENT_NUMBER_OF_COMPLETED_PACKETS = 0x13
EVENT_LINK_KEY_NOTIFICATION = 0x18

_PAIRING_NEGATIVE_REPLIES = {
    0x16: HCI_PIN_CODE_REQUEST_NEG_REPLY,
    0x17: HCI_LINK_KEY_REQUEST_NEG_REPLY,
    0x31: HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    0x33: HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY,
    0x34: HCI_USER_PASSKEY_REQUEST_NEG_REPLY,
    0x35: HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY,
}

_RTL8761BU_STOCK_IDENTITY = (0x8761, 0x000B, 0x0A, 0x005D)
_RTL8761BU_PATCHED_IDENTITY = (0xD922, 0x0001, 0x0A, 0x005D)

_SUPPORTED_CONTROLLERS = {
    (0x0A12, 0x0001): ("BlueCore4-ROM", "Sena", "Parani-UD100", True, False),
    (0x0BDA, 0x8771): ("RTL8761BU", "Realtek", "Bluetooth 5 USB Adapter", True, True),
    (0x0BDA, 0xA728): ("RTL8761BU", "Realtek", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0604): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0607): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x0B05, 0x190E): ("RTL8761BU", "ASUS", "Bluetooth USB Adapter", True, True),
    (0x2C4E, 0x0115): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2550, 0x8761): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x6655, 0x8771): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x7392, 0xC611): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x8761): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x6275): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
}


class UsbBluetoothError(RuntimeError):
    pass


@dataclass(slots=True)
class HciScannerHealth:
    event_packets: int = 0
    malformed_events: int = 0
    classic_observations: int = 0
    ble_observations: int = 0
    inquiry_completions: int = 0
    remote_name_requests: int = 0
    remote_name_successes: int = 0
    remote_name_failures: int = 0
    read_errors: int = 0
    last_event_at: float | None = None


@dataclass(frozen=True, slots=True)
class HciCaptureRecord:
    timestamp: float
    packet_type: int
    incoming: bool
    payload: bytes


@dataclass(frozen=True, slots=True)
class UsbBluetoothController:
    vid: int
    pid: int
    chipset: str
    vendor: str | None
    product_name: str
    bus: int | None
    address: int | None
    supports_classic: bool = True
    supports_le: bool = True

    @property
    def instance_key(self) -> tuple:
        return self.vid, self.pid, self.bus, self.address

    @property
    def label(self) -> str:
        brand = " ".join(part for part in (self.vendor, self.product_name) if part)
        return f"{self.chipset} · {brand}" if brand else self.chipset


def find_usb_bluetooth_controllers() -> list[UsbBluetoothController]:
    backend = libusb_package.get_libusb1_backend()
    try:
        devices = usb.core.find(find_all=True, backend=backend)
    except usb.core.NoBackendError:
        return []
    controllers = []
    for device in devices or ():
        identity = _SUPPORTED_CONTROLLERS.get((device.idVendor, device.idProduct))
        if identity is None:
            continue
        chipset, vendor, product, supports_classic, supports_le = identity
        controllers.append(UsbBluetoothController(
            vid=device.idVendor,
            pid=device.idProduct,
            chipset=chipset,
            vendor=vendor,
            product_name=product,
            bus=getattr(device, "bus", None),
            address=getattr(device, "address", None),
            supports_classic=supports_classic,
            supports_le=supports_le,
        ))
    return controllers


class UsbHciScanner:
    def __init__(
        self,
        controller: UsbBluetoothController,
        detection_callback: Callable[[DiscoveryObservation], None],
    ) -> None:
        self.controller = controller
        self._detection_callback = detection_callback
        self._device = None
        self._event_endpoint = None
        self._acl_in_endpoint = None
        self._acl_out_endpoint = None
        self._interface_number = 0
        self._detached_kernel_driver = False
        self._running = False
        self._scan_task: asyncio.Task | None = None
        self.health = HciScannerHealth()
        self._capture_records: deque[HciCaptureRecord] = deque(maxlen=50_000)
        self._classic_observations: dict[str, DiscoveryObservation] = {}
        self._remote_name_queue: deque[str] = deque()
        self._remote_name_queued: set[str] = set()
        self._remote_name_resolved: set[str] = set()
        self._remote_name_pending: str | None = None
        self._pending_events: deque[tuple[int, bytes]] = deque()
        self._acl_stream = bytearray()
        self._acl_mtu = 0
        self._acl_credits = 0
        self._acl_credit_limit = 0

    @property
    def is_scanning(self) -> bool:
        return self._running

    @property
    def capture_records(self) -> tuple[HciCaptureRecord, ...]:
        return tuple(self._capture_records)

    async def browse_sdp(self, identifier: str) -> tuple[SdpService, ...]:
        """Browse public SDP records without pairing or profile writes."""
        observation = self._classic_observations.get(identifier)
        if observation is None:
            raise UsbBluetoothError("Classic device is no longer available")
        was_running = self._running
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        try:
            return await asyncio.to_thread(self._browse_sdp, observation)
        finally:
            self._remote_name_pending = None
            self._remote_name_queue.clear()
            self._remote_name_queued.clear()
            if was_running and self._device is not None:
                try:
                    await asyncio.to_thread(
                        self._command, HCI_INQUIRY, b"\x33\x8b\x9e\x08\x00",
                    )
                except UsbBluetoothError:
                    logger.debug("Could not resume inquiry after SDP browse", exc_info=True)
                else:
                    self._running = True
                    self._scan_task = asyncio.create_task(self._scan_loop())

    async def start(self) -> None:
        if self._running:
            return
        try:
            await asyncio.to_thread(self._open_and_start)
        except Exception:
            await asyncio.to_thread(self._close)
            raise
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())

    def reserve(self) -> None:
        if self._device is None:
            self._open()

    async def stop(self) -> None:
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        await asyncio.to_thread(self._stop_and_close)

    async def pause(self) -> None:
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        await asyncio.to_thread(self._stop_and_close, False)

    def release(self) -> None:
        self._close()

    def _open_and_start(self) -> None:
        if self._device is None:
            self._open()
        self._remote_name_pending = None
        self._remote_name_queue.clear()
        self._remote_name_queued.clear()
        self._command(HCI_RESET)
        version = self._command(HCI_READ_LOCAL_VERSION)
        self._load_realtek_firmware(version)
        event_mask = (
            bytes.fromhex("fffffbff07f8bf3d")
            if self.controller.supports_le else
            bytes.fromhex("fffffbff03000000")
        )
        self._command(HCI_SET_EVENT_MASK, event_mask)
        if self.controller.supports_classic:
            inquiry_mode = b"\x02" if self.controller.supports_le else b"\x01"
            self._command(HCI_WRITE_INQUIRY_MODE, inquiry_mode)
        if self.controller.supports_le:
            self._command(HCI_LE_SET_EVENT_MASK, b"\x02" + b"\x00" * 7)
            self._command(
                HCI_LE_SET_SCAN_PARAMETERS,
                struct.pack("<BHHBB", 0x00, 0x0010, 0x0010, 0x00, 0x00),
            )
            self._command(HCI_LE_SET_SCAN_ENABLE, b"\x01\x00")
        if self.controller.supports_classic:
            self._command(HCI_INQUIRY, b"\x33\x8b\x9e\x08\x00")

    def _open(self) -> None:
        backend = libusb_package.get_libusb1_backend()
        device = usb.core.find(
            idVendor=self.controller.vid,
            idProduct=self.controller.pid,
            bus=self.controller.bus,
            address=self.controller.address,
            backend=backend,
        )
        if device is None:
            raise UsbBluetoothError("The selected Bluetooth USB controller was disconnected")
        try:
            configuration = device.get_active_configuration()
        except usb.core.USBError:
            device.set_configuration()
            configuration = device.get_active_configuration()
        interface = next(
            (
                candidate for candidate in configuration
                if candidate.bInterfaceClass == 0xE0
                and candidate.bInterfaceSubClass == 0x01
                and candidate.bInterfaceProtocol == 0x01
            ),
            None,
        )
        if interface is None:
            raise UsbBluetoothError(f"{self.controller.chipset} Bluetooth HCI interface was not found")
        self._interface_number = interface.bInterfaceNumber
        try:
            if device.is_kernel_driver_active(self._interface_number):
                device.detach_kernel_driver(self._interface_number)
                self._detached_kernel_driver = True
        except (AttributeError, NotImplementedError):
            pass
        except usb.core.USBError as exc:
            if getattr(exc, "errno", None) != 2:
                raise UsbBluetoothError(
                    f"Could not detach {self.controller.chipset} from the OS Bluetooth driver; "
                    "replug it after stopping OS use, or bind it to WinUSB on Windows"
                ) from exc
        try:
            usb.util.claim_interface(device, self._interface_number)
        except usb.core.USBError as exc:
            raise UsbBluetoothError(
                f"Could not claim {self.controller.chipset}; use a dedicated adapter and bind it "
                "to WinUSB "
                "on Windows"
            ) from exc
        endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR
            ),
            None,
        )
        if endpoint is None:
            raise UsbBluetoothError("RTL8761BU HCI event endpoint was not found")
        acl_in_endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            ),
            None,
        )
        acl_out_endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_OUT
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            ),
            None,
        )
        self._device = device
        self._event_endpoint = endpoint
        self._acl_in_endpoint = acl_in_endpoint
        self._acl_out_endpoint = acl_out_endpoint

    def _load_realtek_firmware(self, version_result: bytes) -> None:
        if self.controller.chipset != "RTL8761BU":
            return
        if len(version_result) < 9 or version_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU returned an invalid local-version response")
        identity = self._rtl8761bu_identity(version_result)
        if identity == _RTL8761BU_PATCHED_IDENTITY:
            return
        if identity != _RTL8761BU_STOCK_IDENTITY:
            lmp_subversion, hci_revision, hci_version, manufacturer = identity
            raise UsbBluetoothError(
                "Unsupported RTL8761BU controller identity "
                f"(HCI 0x{hci_version:02x}, revision 0x{hci_revision:04x}, "
                f"manufacturer {manufacturer}, LMP subversion "
                f"0x{lmp_subversion:04x})"
            )
        rom_result = self._command(RTL_ROM_VERSION_OPCODE)
        if len(rom_result) != 2 or rom_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU ROM-version command failed")
        image = load_download_image(rom_result[1])
        for fragment in download_fragments(image):
            response = self._command(RTL_DOWNLOAD_OPCODE, fragment)
            if len(response) != 2 or response[0] != 0:
                raise UsbBluetoothError("RTL8761BU rejected a firmware fragment")
        updated = self._command(HCI_READ_LOCAL_VERSION)
        if (
            len(updated) < 9
            or updated[0] != 0
            or self._rtl8761bu_identity(updated) != _RTL8761BU_PATCHED_IDENTITY
        ):
            raise UsbBluetoothError(
                "RTL8761BU firmware identity was not active after upload"
            )

    @staticmethod
    def _rtl8761bu_identity(version_result: bytes) -> tuple[int, int, int, int]:
        return (
            int.from_bytes(version_result[7:9], "little"),
            int.from_bytes(version_result[2:4], "little"),
            version_result[1],
            int.from_bytes(version_result[5:7], "little"),
        )

    def _command(self, opcode: int, parameters: bytes = b"", timeout_ms: int = 5000) -> bytes:
        if self._device is None:
            raise UsbBluetoothError("Bluetooth USB controller is not open")
        packet = command_packet(opcode, parameters)
        self._capture_records.append(HciCaptureRecord(time.time(), 0x01, False, packet))
        try:
            self._device.ctrl_transfer(
                0x20, 0, 0, 0, packet, timeout=timeout_ms,
            )
        except usb.core.USBError as exc:
            raise UsbBluetoothError(f"HCI command 0x{opcode:04x} failed") from exc
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            packet = self._read_event(remaining_ms)
            if packet is None:
                continue
            event_code, event_parameters = parse_event(packet)
            result = command_result(event_code, event_parameters)
            if result is None or result[0] != opcode:
                self._pending_events.append((event_code, event_parameters))
                continue
            if result[1] != 0:
                raise UsbBluetoothError(
                    f"HCI command 0x{opcode:04x} returned status 0x{result[1]:02x}"
                )
            return result[2]
        raise UsbBluetoothError(f"HCI command 0x{opcode:04x} timed out")

    def _read_event(self, timeout_ms: int = 500) -> bytes | None:
        try:
            packet = bytes(self._device.read(
                self._event_endpoint.bEndpointAddress,
                HCI_MAX_EVENT_SIZE,
                timeout=timeout_ms,
            ))
            self._capture_records.append(
                HciCaptureRecord(time.time(), 0x04, True, packet)
            )
            self.health.event_packets += 1
            self.health.last_event_at = time.time()
            return packet
        except usb.core.USBError as exc:
            if getattr(exc, "errno", None) in {60, 110} or "timed out" in str(exc).lower():
                return None
            self.health.read_errors += 1
            raise

    async def _scan_loop(self) -> None:
        while self._running:
            if self._pending_events:
                event_code, parameters = self._pending_events.popleft()
            else:
                try:
                    packet = await asyncio.to_thread(self._read_event)
                except usb.core.USBError:
                    logger.debug("Bluetooth USB event read failed", exc_info=True)
                    self._running = False
                    break
                if packet is None:
                    continue
                try:
                    event_code, parameters = parse_event(packet)
                except ValueError:
                    self.health.malformed_events += 1
                    continue
            observations = parse_discovery_event(event_code, parameters)
            for observation in observations:
                if observation.radio_type == "BT":
                    self.health.classic_observations += 1
                    previous = self._classic_observations.get(observation.identifier)
                    if (
                        observation.name == "<Unknown>"
                        and previous is not None
                        and previous.name != "<Unknown>"
                    ):
                        observation = replace(observation, name=previous.name)
                    self._classic_observations[observation.identifier] = observation
                    if observation.name == "<Unknown>":
                        self._queue_remote_name(observation.identifier)
                    else:
                        self._remote_name_resolved.add(observation.identifier)
                else:
                    self.health.ble_observations += 1
                self._detection_callback(observation)
            if event_code == EVENT_INQUIRY_COMPLETE:
                self.health.inquiry_completions += 1
                await self._advance_classic_discovery()
            elif event_code == EVENT_REMOTE_NAME_REQUEST_COMPLETE:
                self._handle_remote_name(parameters)
                await self._advance_classic_discovery()

    def _queue_remote_name(self, identifier: str) -> None:
        if (
            identifier in self._remote_name_resolved
            or identifier in self._remote_name_queued
            or identifier == self._remote_name_pending
            or len(self._remote_name_queue) >= 16
        ):
            return
        self._remote_name_queue.append(identifier)
        self._remote_name_queued.add(identifier)

    async def _advance_classic_discovery(self) -> None:
        if not self._running or not self.controller.supports_classic:
            return
        if self._remote_name_pending is not None:
            return
        while self._remote_name_queue:
            identifier = self._remote_name_queue.popleft()
            self._remote_name_queued.discard(identifier)
            observation = self._classic_observations.get(identifier)
            if observation is None:
                continue
            address = bytes.fromhex(identifier.replace(":", ""))[::-1]
            parameters = (
                address
                + bytes((observation.page_scan_repetition_mode, 0))
                + struct.pack("<H", observation.clock_offset | 0x8000)
            )
            try:
                await asyncio.to_thread(
                    self._command, HCI_REMOTE_NAME_REQUEST, parameters,
                )
            except UsbBluetoothError:
                self.health.remote_name_failures += 1
                self._remote_name_resolved.add(identifier)
                logger.debug(
                    "Could not request the Bluetooth remote name for %s",
                    identifier,
                    exc_info=True,
                )
                continue
            self.health.remote_name_requests += 1
            self._remote_name_pending = identifier
            return
        try:
            await asyncio.to_thread(
                self._command, HCI_INQUIRY, b"\x33\x8b\x9e\x08\x00",
            )
        except UsbBluetoothError:
            logger.debug("Could not restart Bluetooth inquiry", exc_info=True)
            self._running = False

    def _handle_remote_name(self, parameters: bytes) -> None:
        pending = self._remote_name_pending
        self._remote_name_pending = None
        if len(parameters) >= 7:
            identifier = ":".join(f"{part:02X}" for part in reversed(parameters[1:7]))
        else:
            identifier = pending
        if identifier:
            self._remote_name_resolved.add(identifier)
        result = parse_remote_name_event(parameters)
        if result is None:
            self.health.remote_name_failures += 1
            return
        identifier, name = result
        observation = self._classic_observations.get(identifier)
        if observation is None:
            self.health.remote_name_failures += 1
            return
        named = replace(observation, name=name)
        self._classic_observations[identifier] = named
        self.health.remote_name_successes += 1
        self._detection_callback(named)

    def _browse_sdp(
        self,
        observation: DiscoveryObservation,
    ) -> tuple[SdpService, ...]:
        if self._acl_in_endpoint is None or self._acl_out_endpoint is None:
            raise UsbBluetoothError("The Bluetooth controller has no ACL bulk endpoints")
        if self._remote_name_pending is not None:
            pending_address = bytes.fromhex(
                self._remote_name_pending.replace(":", ""),
            )[::-1]
            try:
                self._command(HCI_REMOTE_NAME_REQUEST_CANCEL, pending_address)
            except UsbBluetoothError:
                pass
            self._remote_name_pending = None
        try:
            self._command(HCI_INQUIRY_CANCEL)
        except UsbBluetoothError:
            pass
        address = bytes.fromhex(observation.identifier.replace(":", ""))[::-1]
        buffer_size = self._command(HCI_READ_BUFFER_SIZE)
        if len(buffer_size) < 8 or buffer_size[0] != 0:
            raise UsbBluetoothError("Controller returned an invalid ACL buffer size")
        self._acl_mtu = int.from_bytes(buffer_size[1:3], "little")
        self._acl_credits = int.from_bytes(buffer_size[4:6], "little")
        self._acl_credit_limit = self._acl_credits
        if self._acl_mtu <= 0 or self._acl_credits <= 0:
            raise UsbBluetoothError("Controller reported no usable ACL buffers")
        self._acl_stream.clear()
        self._pending_events.clear()
        parameters = (
            address
            + struct.pack("<H", 0xCC18)
            + bytes((observation.page_scan_repetition_mode, 0))
            + struct.pack("<H", observation.clock_offset | 0x8000)
            + b"\x01"
        )
        handle: int | None = None
        try:
            self._command(HCI_CREATE_CONNECTION, parameters, 10_000)
            try:
                connection = self._wait_event(EVENT_CONNECTION_COMPLETE, 10_000)
            except UsbBluetoothError:
                try:
                    self._command(HCI_CREATE_CONNECTION_CANCEL, address)
                    late = self._wait_event(EVENT_CONNECTION_COMPLETE, 2_000)
                    if len(late) >= 3 and late[0] == 0:
                        late_handle = int.from_bytes(late[1:3], "little") & 0x0FFF
                        self._command(
                            HCI_DISCONNECT,
                            struct.pack("<HB", late_handle, 0x13),
                        )
                except UsbBluetoothError:
                    pass
                raise
            if len(connection) < 11 or connection[0] != 0:
                status = connection[0] if connection else 0xFF
                raise UsbBluetoothError(
                    f"Classic connection failed with status 0x{status:02x}"
                )
            if connection[3:9] != address or connection[9] != 0x01:
                raise UsbBluetoothError("Unexpected Bluetooth connection completed")
            handle = int.from_bytes(connection[1:3], "little") & 0x0FFF
            return self._sdp_session(handle)
        finally:
            if handle is not None:
                try:
                    self._command(
                        HCI_DISCONNECT, struct.pack("<HB", handle, 0x13),
                    )
                    self._wait_event(
                        EVENT_DISCONNECTION_COMPLETE, 5_000, handle=handle,
                    )
                except UsbBluetoothError:
                    pass
            self._acl_stream.clear()
            self._acl_mtu = 0
            self._acl_credits = 0
            self._acl_credit_limit = 0

    def _sdp_session(self, handle: int) -> tuple[SdpService, ...]:
        session_deadline = time.monotonic() + 20
        local_cid = 0x0040
        signal_id = 1
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONNECTION_REQUEST,
                signal_id,
                struct.pack("<HH", SDP_PSM, local_cid),
            ),
        )
        remote_cid = self._wait_l2cap_connection(
            handle, signal_id, session_deadline,
        )
        signal_id += 1
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONFIGURATION_REQUEST,
                signal_id,
                struct.pack("<HH", remote_cid, 0),
            ),
        )
        self._complete_l2cap_configuration(
            handle, local_cid, remote_cid, signal_id, session_deadline,
        )

        fragments = bytearray()
        continuation = b""
        previous_continuation = None
        for transaction_id in range(1, 33):
            self._send_l2cap(
                handle,
                remote_cid,
                service_search_attribute_request(transaction_id, continuation),
            )
            response = self._wait_sdp_response(
                handle, local_cid, session_deadline,
            )
            if not response or response[0] != SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE:
                raise SdpProtocolError("Unexpected packet on the SDP channel")
            attributes, continuation = parse_service_search_attribute_response(
                response, transaction_id,
            )
            fragments.extend(attributes)
            if len(fragments) > 0xFFFF:
                raise SdpProtocolError("SDP attribute response is too large")
            if not continuation:
                break
            if continuation == previous_continuation:
                raise SdpProtocolError("SDP continuation state did not advance")
            previous_continuation = continuation
        else:
            raise SdpProtocolError("Too many SDP continuation responses")

        signal_id += 1
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_DISCONNECTION_REQUEST,
                signal_id,
                struct.pack("<HH", remote_cid, local_cid),
            ),
        )
        try:
            self._wait_l2cap_disconnect(
                handle, signal_id, remote_cid, local_cid,
            )
        except UsbBluetoothError:
            pass
        return parse_service_records(bytes(fragments))

    def _wait_l2cap_disconnect(
        self,
        handle: int,
        identifier: int,
        remote_cid: int,
        local_cid: int,
    ) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, response_id, body in iter_signaling_commands(payload):
                if (
                    code == L2CAP_DISCONNECTION_RESPONSE
                    and response_id == identifier
                    and body[:4] == struct.pack("<HH", remote_cid, local_cid)
                ):
                    return
                self._respond_aux_signaling(
                    handle, code, response_id, body,
                    local_cid=local_cid,
                    remote_cid=remote_cid,
                )
        raise UsbBluetoothError("SDP L2CAP disconnect timed out")

    def _wait_l2cap_connection(
        self,
        handle: int,
        identifier: int,
        deadline: float,
    ) -> int:
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, response_id, body in iter_signaling_commands(payload):
                if self._respond_aux_signaling(
                    handle, code, response_id, body,
                ):
                    continue
                if (
                    code != L2CAP_CONNECTION_RESPONSE
                    or response_id != identifier
                    or len(body) < 8
                ):
                    continue
                destination_cid, source_cid, result, _status = struct.unpack_from(
                    "<HHHH", body,
                )
                if source_cid != 0x0040:
                    raise UsbBluetoothError(
                        "SDP L2CAP response used an unexpected source CID"
                    )
                if result == 0:
                    return destination_cid
                if result != 1:
                    raise UsbBluetoothError(
                        f"SDP L2CAP connection rejected with result 0x{result:04x}"
                    )
        raise UsbBluetoothError("SDP L2CAP connection timed out")

    def _complete_l2cap_configuration(
        self,
        handle: int,
        local_cid: int,
        remote_cid: int,
        request_id: int,
        deadline: float,
    ) -> None:
        local_configured = False
        peer_configured = False
        while (
            time.monotonic() < deadline
            and not (local_configured and peer_configured)
        ):
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, identifier, body in iter_signaling_commands(payload):
                if self._respond_aux_signaling(
                    handle, code, identifier, body,
                    local_cid=local_cid,
                    remote_cid=remote_cid,
                ):
                    continue
                if code == L2CAP_CONFIGURATION_REQUEST and len(body) >= 4:
                    destination_cid = int.from_bytes(body[:2], "little")
                    if destination_cid == local_cid:
                        unknown_options = self._unknown_l2cap_config_options(
                            body[4:],
                        )
                        result = 0x0003 if unknown_options else 0
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_CONFIGURATION_RESPONSE,
                                identifier,
                                struct.pack(
                                    "<HHH", remote_cid,
                                    int.from_bytes(body[2:4], "little") & 0x0001,
                                    result,
                                ) + unknown_options,
                            ),
                        )
                        peer_configured = not unknown_options and not (
                            int.from_bytes(body[2:4], "little") & 0x0001
                        )
                elif (
                    code == L2CAP_CONFIGURATION_RESPONSE
                    and identifier == request_id
                    and len(body) >= 6
                ):
                    source_cid, flags, result = struct.unpack_from("<HHH", body)
                    if source_cid != local_cid or result != 0:
                        raise UsbBluetoothError(
                            f"SDP L2CAP configuration failed with result 0x{result:04x}"
                        )
                    local_configured = not (flags & 0x0001)
        if not (local_configured and peer_configured):
            raise UsbBluetoothError("SDP L2CAP configuration timed out")

    @staticmethod
    def _unknown_l2cap_config_options(options: bytes) -> bytes:
        offset = 0
        unknown = bytearray()
        supported = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
        while offset < len(options):
            if offset + 2 > len(options):
                raise UsbBluetoothError("Truncated L2CAP configuration option")
            option_type, length = options[offset], options[offset + 1]
            end = offset + 2 + length
            if end > len(options):
                raise UsbBluetoothError("Truncated L2CAP configuration option")
            if (option_type & 0x7F) not in supported and not (option_type & 0x80):
                unknown.extend(options[offset:end])
            offset = end
        return bytes(unknown)

    def _wait_sdp_response(
        self,
        handle: int,
        local_cid: int,
        deadline: float,
    ) -> bytes:
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid == local_cid:
                return payload
            if cid == L2CAP_SIGNALING_CID:
                for code, identifier, body in iter_signaling_commands(payload):
                    if self._respond_aux_signaling(
                        handle, code, identifier, body,
                        local_cid=local_cid,
                    ):
                        continue
                    if code == L2CAP_CONFIGURATION_REQUEST and len(body) >= 4:
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_CONFIGURATION_RESPONSE,
                                identifier,
                                struct.pack("<HHH", 0x0040, 0, 0),
                            ),
                        )
                    elif code == L2CAP_DISCONNECTION_REQUEST and len(body) >= 4:
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_DISCONNECTION_RESPONSE, identifier, body[:4],
                            ),
                        )
        raise UsbBluetoothError("SDP response timed out")

    def _respond_aux_signaling(
        self,
        handle: int,
        code: int,
        identifier: int,
        body: bytes,
        *,
        local_cid: int = 0x0040,
        remote_cid: int = 0,
    ) -> bool:
        if code == L2CAP_ECHO_REQUEST:
            response_code = L2CAP_ECHO_RESPONSE
            response_body = body
        elif code == L2CAP_INFORMATION_REQUEST and len(body) >= 2:
            response_code = L2CAP_INFORMATION_RESPONSE
            response_body = body[:2] + struct.pack("<H", 0x0001)
        elif code == L2CAP_DISCONNECTION_REQUEST and len(body) >= 4:
            response_code = L2CAP_DISCONNECTION_RESPONSE
            response_body = body[:4]
        else:
            return False
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(response_code, identifier, response_body),
        )
        if code == L2CAP_DISCONNECTION_REQUEST:
            raise UsbBluetoothError(
                f"Peer disconnected SDP channel 0x{remote_cid or local_cid:04x}"
            )
        return True

    def _send_l2cap(self, handle: int, cid: int, payload: bytes) -> None:
        body = l2cap_packet(cid, payload)
        mtu = self._acl_mtu or HCI_MAX_ACL_SIZE - 4
        for offset in range(0, len(body), mtu):
            boundary = 0x02 if offset == 0 else 0x01
            self._send_acl_fragment(handle, boundary, body[offset:offset + mtu])

    def _send_acl_fragment(
        self,
        handle: int,
        boundary: int,
        fragment: bytes,
    ) -> None:
        deadline = time.monotonic() + 5
        self._drain_hci_events(handle)
        while self._acl_credits <= 0:
            self._drain_hci_events(handle)
            if self._acl_credits > 0:
                break
            if time.monotonic() >= deadline:
                raise UsbBluetoothError("Bluetooth ACL transmit credits timed out")
            packet = self._read_event(100)
            if packet is not None:
                code, parameters = parse_event(packet)
                self._handle_aux_hci_event(code, parameters, handle)
        packet = (
            struct.pack("<HH", handle | (boundary << 12), len(fragment))
            + fragment
        )
        try:
            self._device.write(
                self._acl_out_endpoint.bEndpointAddress,
                packet,
                timeout=5_000,
            )
        except usb.core.USBError as exc:
            raise UsbBluetoothError("Could not write Bluetooth ACL data") from exc
        self._acl_credits -= 1
        self._capture_records.append(HciCaptureRecord(time.time(), 0x02, False, packet))

    def _read_l2cap(self, handle: int, deadline: float) -> tuple[int, bytes]:
        reassembly = bytearray()
        expected = 0
        while time.monotonic() < deadline:
            packet = self._next_acl_packet(deadline, handle)
            handle_flags, data_length = struct.unpack_from("<HH", packet)
            if (handle_flags & 0x0FFF) != handle:
                continue
            boundary = (handle_flags >> 12) & 0x03
            fragment = packet[4:4 + data_length]
            if boundary in {0, 2, 3}:
                if reassembly:
                    raise UsbBluetoothError("Interleaved Bluetooth ACL fragments")
                reassembly = bytearray(fragment)
                expected = (
                    4 + int.from_bytes(reassembly[:2], "little")
                    if len(reassembly) >= 4 else 0
                )
            elif boundary == 1 and reassembly:
                reassembly.extend(fragment)
            else:
                continue
            if expected and len(reassembly) >= expected:
                if len(reassembly) != expected:
                    raise UsbBluetoothError("Bluetooth ACL data exceeded L2CAP length")
                length, cid = struct.unpack_from("<HH", reassembly)
                return cid, bytes(reassembly[4:4 + length])
        raise UsbBluetoothError("Bluetooth ACL response timed out")

    def _next_acl_packet(self, deadline: float, handle: int) -> bytes:
        while time.monotonic() < deadline:
            if len(self._acl_stream) >= 4:
                data_length = int.from_bytes(self._acl_stream[2:4], "little")
                if data_length > HCI_MAX_ACL_SIZE - 4:
                    self._acl_stream.clear()
                    raise UsbBluetoothError("Bluetooth ACL packet length is invalid")
                packet_length = 4 + data_length
                if len(self._acl_stream) >= packet_length:
                    packet = bytes(self._acl_stream[:packet_length])
                    del self._acl_stream[:packet_length]
                    self._capture_records.append(
                        HciCaptureRecord(time.time(), 0x02, True, packet)
                    )
                    return packet
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            try:
                chunk = bytes(self._device.read(
                    self._acl_in_endpoint.bEndpointAddress,
                    HCI_MAX_ACL_SIZE,
                    timeout=min(remaining_ms, 100),
                ))
            except usb.core.USBError as exc:
                if getattr(exc, "errno", None) in {60, 110} or "timed out" in str(exc).lower():
                    self._drain_hci_events(handle)
                    continue
                raise UsbBluetoothError("Could not read Bluetooth ACL data") from exc
            self._acl_stream.extend(chunk)
        raise UsbBluetoothError("Bluetooth ACL packet timed out")

    def _drain_hci_events(self, handle: int) -> None:
        deferred = []
        while self._pending_events:
            code, parameters = self._pending_events.popleft()
            if not self._handle_aux_hci_event(code, parameters, handle):
                deferred.append((code, parameters))
        self._pending_events.extend(deferred)
        for _ in range(8):
            packet = self._read_event(1)
            if packet is None:
                return
            code, parameters = parse_event(packet)
            if not self._handle_aux_hci_event(code, parameters, handle):
                self._pending_events.append((code, parameters))

    def _handle_aux_hci_event(
        self,
        event_code: int,
        parameters: bytes,
        handle: int,
    ) -> bool:
        if event_code == EVENT_NUMBER_OF_COMPLETED_PACKETS and parameters:
            count = parameters[0]
            offset = 1
            for _ in range(count):
                if offset + 4 > len(parameters):
                    raise UsbBluetoothError(
                        "Malformed completed-packets HCI event"
                    )
                completed_handle, completed = struct.unpack_from(
                    "<HH", parameters, offset,
                )
                offset += 4
                if (completed_handle & 0x0FFF) == handle:
                    self._acl_credits = min(
                        self._acl_credit_limit,
                        self._acl_credits + completed,
                    )
            return True
        negative_opcode = _PAIRING_NEGATIVE_REPLIES.get(event_code)
        if negative_opcode is not None and len(parameters) >= 6:
            reply = parameters[:6]
            if event_code == 0x31:
                reply += b"\x18"
            self._command(negative_opcode, reply)
            return True
        if event_code == EVENT_LINK_KEY_NOTIFICATION:
            raise UsbBluetoothError(
                "Unexpected link key notification during read-only SDP browse"
            )
        if event_code == EVENT_DISCONNECTION_COMPLETE:
            raise UsbBluetoothError("Bluetooth ACL link disconnected")
        return False

    def _wait_event(
        self,
        event_code: int,
        timeout_ms: int,
        *,
        handle: int = 0,
    ) -> bytes:
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            if self._pending_events:
                code, parameters = self._pending_events.popleft()
            else:
                packet = self._read_event(
                    max(1, int((deadline - time.monotonic()) * 1000)),
                )
                if packet is None:
                    continue
                code, parameters = parse_event(packet)
            if code == event_code:
                return parameters
            self._handle_aux_hci_event(code, parameters, handle)
        raise UsbBluetoothError(f"HCI event 0x{event_code:02x} timed out")

    def _stop_and_close(self, close: bool = True) -> None:
        if self._device is not None:
            if self.controller.supports_classic:
                try:
                    self._command(HCI_INQUIRY_CANCEL)
                except Exception:
                    pass
            if self.controller.supports_le:
                try:
                    self._command(HCI_LE_SET_SCAN_ENABLE, b"\x00\x00")
                except Exception:
                    pass
        if close:
            self._close()

    def _close(self) -> None:
        device, self._device = self._device, None
        self._event_endpoint = None
        self._acl_in_endpoint = None
        self._acl_out_endpoint = None
        self._remote_name_pending = None
        self._remote_name_queue.clear()
        self._remote_name_queued.clear()
        if device is None:
            return
        try:
            usb.util.release_interface(device, self._interface_number)
        except Exception:
            pass
        if self._detached_kernel_driver:
            try:
                device.attach_kernel_driver(self._interface_number)
            except Exception:
                pass
        self._detached_kernel_driver = False
        usb.util.dispose_resources(device)
