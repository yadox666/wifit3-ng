"""Read-only USB discovery for operational HackRF One devices."""
from __future__ import annotations

import errno
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import libusb_package
import usb.core
import usb.util

HACKRF_ONE_USB_ID = (0x1D50, 0x6089)
_BOARD_ID_READ = 14
_VERSION_STRING_READ = 15
_HACKRF_ONE_BOARD_ID = 2
_SYSFS_USB = Path("/sys/bus/usb/devices")


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


def _read_sysfs_text(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return ""


def _read_sysfs_int(path: Path) -> int | None:
    text = _read_sysfs_text(path)
    if not text:
        return None
    try:
        return int(text, 10)
    except ValueError:
        return None


def _linux_sysfs_hackrf(*, sysfs_usb: Path | None = None) -> list[HackRfDevice]:
    """List HackRF One devices from sysfs without opening usbfs."""
    if sysfs_usb is None:
        sysfs_usb = _SYSFS_USB
    if not sys.platform.startswith("linux") or not sysfs_usb.is_dir():
        return []
    found: list[HackRfDevice] = []
    for device_dir in sorted(sysfs_usb.iterdir()):
        if not (device_dir / "idVendor").is_file():
            continue
        try:
            vid = int(_read_sysfs_text(device_dir / "idVendor"), 16)
            pid = int(_read_sysfs_text(device_dir / "idProduct"), 16)
        except ValueError:
            continue
        if (vid, pid) != HACKRF_ONE_USB_ID:
            continue
        found.append(
            HackRfDevice(
                vid=vid,
                pid=pid,
                bus=_read_sysfs_int(device_dir / "busnum"),
                address=_read_sysfs_int(device_dir / "devnum"),
                vendor=_read_sysfs_text(device_dir / "manufacturer") or "Great Scott Gadgets",
                product_name=_read_sysfs_text(device_dir / "product") or "HackRF One",
            )
        )
    return found


def _enumerate_libusb_devices():
    backend = libusb_package.get_libusb1_backend()
    try:
        devices = usb.core.find(find_all=True, backend=backend)
    except (usb.core.NoBackendError, usb.core.USBError, OSError):
        return ()
    found = []
    try:
        for device in devices or ():
            found.append(device)
    except (usb.core.USBError, OSError):
        pass
    return found


def find_hackrf_devices() -> list[HackRfDevice]:
    found: dict[tuple, HackRfDevice] = {}
    for device in _enumerate_libusb_devices():
        try:
            vid = int(device.idVendor)
            pid = int(device.idProduct)
        except (AttributeError, TypeError, usb.core.USBError):
            continue
        if (vid, pid) != HACKRF_ONE_USB_ID:
            continue
        entry = HackRfDevice(
            vid=vid,
            pid=pid,
            bus=getattr(device, "bus", None),
            address=getattr(device, "address", None),
        )
        found[entry.instance_key] = entry
    for entry in _linux_sysfs_hackrf():
        found.setdefault(entry.instance_key, entry)
    return list(found.values())


def _hackrf_device_id(device: HackRfDevice):
    from wifit3.models import DeviceID

    return DeviceID(
        vid=device.vid,
        pid=device.pid,
        chipset="HACKRF",
        vendor=device.vendor,
        product_name=device.product_name,
        bus=device.bus,
        address=device.address,
    )


def ensure_hackrf_usb_access(device: HackRfDevice) -> None:
    """Grant this process write access to the HackRF usbfs node on Linux.

    Spectrum capture needs a writable ``/dev/bus/usb`` node. A one-shot pkexec
    chmod runs only when this session cannot write the node already. Other
    platforms return without changing permissions.
    """
    if not sys.platform.startswith("linux"):
        return
    from wifit3.setup.linux import session_grant_usb, session_prepare_usb, usb_node_writable

    device_id = _hackrf_device_id(device)
    if device.bus is not None and device.address is not None:
        node = f"/dev/bus/usb/{device.bus:03d}/{device.address:03d}"
        if os.access(node, os.W_OK):
            return
    if usb_node_writable(device_id):
        return
    session_prepare_usb(device_id)
    if usb_node_writable(device_id):
        return
    grant = session_grant_usb(device_id)
    if usb_node_writable(device_id) or grant.ok:
        return
    if grant.cancelled:
        raise PermissionError("Authorization dismissed. HackRF USB access was not granted.")
    raise PermissionError(
        grant.message or "USB access denied. HackRF needs a writable /dev/bus/usb node."
    )


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
