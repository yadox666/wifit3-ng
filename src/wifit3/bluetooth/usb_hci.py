from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from typing import Callable

import libusb_package
import usb.core
import usb.util

from wifit3.bluetooth.hci_protocol import (
    EVENT_INQUIRY_COMPLETE,
    HCI_INQUIRY,
    HCI_INQUIRY_CANCEL,
    HCI_LE_SET_EVENT_MASK,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_READ_LOCAL_VERSION,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
    DiscoveryObservation,
    command_packet,
    command_result,
    parse_discovery_event,
    parse_event,
)
from wifit3.bluetooth.rtl8761_firmware import (
    RTL_DOWNLOAD_OPCODE,
    RTL_ROM_VERSION_OPCODE,
    download_fragments,
    load_download_image,
)

logger = logging.getLogger(__name__)

HCI_MAX_EVENT_SIZE = 257

_SUPPORTED_CONTROLLERS = {
    (0x0A12, 0x0001): ("BlueCore4-ROM", "Sena", "Parani-UD100", True, False),
    (0x0BDA, 0x8771): ("RTL8761BU", "Realtek", "Bluetooth 5 USB Adapter", True, True),
    (0x0BDA, 0xA728): ("RTL8761BU", "Realtek", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0604): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0607): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x2C4E, 0x0115): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2550, 0x8761): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x6655, 0x8771): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x7392, 0xC611): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x8761): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x6275): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
}


class UsbBluetoothError(RuntimeError):
    pass


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
        self._interface_number = 0
        self._detached_kernel_driver = False
        self._running = False
        self._scan_task: asyncio.Task | None = None

    @property
    def is_scanning(self) -> bool:
        return self._running

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
        self._device = device
        self._event_endpoint = endpoint

    def _load_realtek_firmware(self, version_result: bytes) -> None:
        if len(version_result) < 9 or version_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU returned an invalid local-version response")
        hci_version = version_result[1]
        hci_revision = int.from_bytes(version_result[2:4], "little")
        lmp_subversion = int.from_bytes(version_result[7:9], "little")
        if (lmp_subversion, hci_revision, hci_version) != (0x8761, 0x000B, 0x0A):
            return
        rom_result = self._command(RTL_ROM_VERSION_OPCODE)
        if len(rom_result) != 2 or rom_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU ROM-version command failed")
        image = load_download_image(rom_result[1])
        for fragment in download_fragments(image):
            response = self._command(RTL_DOWNLOAD_OPCODE, fragment)
            if len(response) != 2 or response[0] != 0:
                raise UsbBluetoothError("RTL8761BU rejected a firmware fragment")
        updated = self._command(HCI_READ_LOCAL_VERSION)
        if len(updated) < 9 or updated[0] != 0:
            raise UsbBluetoothError("RTL8761BU did not restart after firmware upload")

    def _command(self, opcode: int, parameters: bytes = b"", timeout_ms: int = 5000) -> bytes:
        if self._device is None:
            raise UsbBluetoothError("Bluetooth USB controller is not open")
        try:
            self._device.ctrl_transfer(
                0x20, 0, 0, 0, command_packet(opcode, parameters), timeout=timeout_ms,
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
                continue
            if result[1] != 0:
                raise UsbBluetoothError(
                    f"HCI command 0x{opcode:04x} returned status 0x{result[1]:02x}"
                )
            return result[2]
        raise UsbBluetoothError(f"HCI command 0x{opcode:04x} timed out")

    def _read_event(self, timeout_ms: int = 500) -> bytes | None:
        try:
            return bytes(self._device.read(
                self._event_endpoint.bEndpointAddress,
                HCI_MAX_EVENT_SIZE,
                timeout=timeout_ms,
            ))
        except usb.core.USBError as exc:
            if getattr(exc, "errno", None) in {60, 110} or "timed out" in str(exc).lower():
                return None
            raise

    async def _scan_loop(self) -> None:
        while self._running:
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
                continue
            for observation in parse_discovery_event(event_code, parameters):
                self._detection_callback(observation)
            if (
                event_code == EVENT_INQUIRY_COMPLETE
                and self._running
                and self.controller.supports_classic
            ):
                try:
                    await asyncio.to_thread(
                        self._command, HCI_INQUIRY, b"\x33\x8b\x9e\x08\x00",
                    )
                except UsbBluetoothError:
                    logger.debug("Could not restart Bluetooth inquiry", exc_info=True)
                    self._running = False

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
