"""Read-only USB discovery for operational HackRF One devices."""
from __future__ import annotations

import errno
from dataclasses import dataclass

import libusb_package
import usb.core
import usb.util

HACKRF_ONE_USB_ID = (0x1D50, 0x6089)
_BOARD_ID_READ = 14
_VERSION_STRING_READ = 15
_HACKRF_ONE_BOARD_ID = 2


@dataclass(frozen=True, slots=True)
class HackRfDevice:
    vid: int
    pid: int
    bus: int | None
    address: int | None
    vendor: str = "Great Scott Gadgets"
    product_name: str = "HackRF One"

    @property
    def instance_key(self) -> tuple[int, int, int | None, int | None]:
        return self.vid, self.pid, self.bus, self.address

    @property
    def label(self) -> str:
        return f"{self.product_name} · {self.vendor}"


@dataclass(frozen=True, slots=True)
class HackRfUsbHealth:
    status: str
    detail: str
    ready: bool


def find_hackrf_devices() -> list[HackRfDevice]:
    backend = libusb_package.get_libusb1_backend()
    try:
        devices = usb.core.find(find_all=True, backend=backend)
    except usb.core.NoBackendError:
        return []
    return [
        HackRfDevice(
            vid=device.idVendor,
            pid=device.idProduct,
            bus=getattr(device, "bus", None),
            address=getattr(device, "address", None),
        )
        for device in devices or ()
        if (device.idVendor, device.idProduct) == HACKRF_ONE_USB_ID
    ]


def probe_hackrf_usb(device: HackRfDevice) -> HackRfUsbHealth:
    """Read the board ID and firmware version without claiming or changing the radio."""
    backend = libusb_package.get_libusb1_backend()
    usb_device = None
    try:
        usb_device = usb.core.find(
            idVendor=device.vid,
            idProduct=device.pid,
            bus=device.bus,
            address=device.address,
            backend=backend,
        )
        if usb_device is None:
            return HackRfUsbHealth("DISCONNECTED", "Device is no longer present", False)
        board_result = bytes(usb_device.ctrl_transfer(
            0xC0, _BOARD_ID_READ, 0, 0, 1, timeout=1000,
        ))
        version_result = bytes(usb_device.ctrl_transfer(
            0xC0, _VERSION_STRING_READ, 0, 0, 255, timeout=1000,
        ))
    except usb.core.NoBackendError:
        return HackRfUsbHealth("UNAVAILABLE", "USB backend is unavailable", False)
    except usb.core.USBError as exc:
        if getattr(exc, "errno", None) in (errno.EACCES, errno.EPERM):
            return HackRfUsbHealth("NO ACCESS", "USB permission denied", False)
        return HackRfUsbHealth("USB ERROR", str(exc), False)
    finally:
        if usb_device is not None:
            try:
                usb.util.dispose_resources(usb_device)
            except Exception:
                pass
    if not board_result or board_result[0] != _HACKRF_ONE_BOARD_ID:
        return HackRfUsbHealth("FIRMWARE ERROR", "Unexpected HackRF board response", False)
    version = version_result.partition(b"\0")[0].decode("ascii", errors="replace").strip()
    if not version:
        return HackRfUsbHealth("FIRMWARE ERROR", "Firmware version was empty", False)
    return HackRfUsbHealth("USB READY", f"Firmware {version}", True)
