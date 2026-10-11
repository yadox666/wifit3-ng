"""Best-effort release of a USB Bluetooth HCI adapter from the host OS before libusb claim.

Wi-Fi dongles in wifit3 are usually unbound from the kernel driver (udev / WinUSB) or have no
in-tree driver on macOS, so ``claim_interface`` succeeds on START. Bluetooth HCI adapters are
claimed by bluetoothd (macOS), btusb (Linux), or the Windows Bluetooth stack - the same libusb
detach path often fails until the OS lets go. These helpers try a software release (no replug)
before retrying claim.
"""
from __future__ import annotations

import ctypes
import logging
import os
import shutil
import struct
import subprocess
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wifit3.bluetooth.usb_hci import UsbBluetoothController

logger = logging.getLogger(__name__)

# Same private C entry points blueutil links against. They live in the OS
# IOBluetooth framework, so the app does not ship or invoke an external binary.
_IOBLUETOOTH = "/System/Library/Frameworks/IOBluetooth.framework/IOBluetooth"


def claim_error_is_recoverable(message: str) -> bool:
    lowered = message.casefold()
    if "disconnected" in lowered:
        return False
    return (
        "could not detach" in lowered
        or "could not claim" in lowered
        or "resource busy" in lowered
        or "access denied" in lowered
    )


def release_os_bluetooth_for_usb_hci(
    controller: UsbBluetoothController,
    *,
    allow_radio_power_off: bool = True,
    allow_privilege: bool = False,
) -> list[str]:
    """Ask the OS to drop the HCI interface. Returns human-readable steps attempted."""
    steps: list[str] = []
    if sys.platform == "darwin":
        steps.extend(_macos_release(allow_radio_power_off=allow_radio_power_off))
    elif sys.platform.startswith("linux"):
        steps.extend(_linux_release(controller, allow_privilege=allow_privilege))
    else:
        steps.append("No automatic OS release helper on this platform; use WinUSB binding")
    if steps:
        logger.debug(
            "USB Bluetooth OS release for %s %04x:%04x: %s",
            controller.chipset,
            controller.vid,
            controller.pid,
            "; ".join(steps),
        )
    return steps


def _run_quiet(argv: list[str], timeout: float = 8.0) -> bool:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Command %s failed: %s", argv, exc)
        return False


def macos_controller_power_on() -> bool | None:
    """Read the macOS Bluetooth radio. ``None`` when the call is unavailable."""
    if sys.platform != "darwin":
        return None
    try:
        get_power, _set_power = _macos_power_api()
        return bool(int(get_power()))
    except (AttributeError, OSError):
        logger.debug("IOBluetooth power read unavailable", exc_info=True)
        return None


def _macos_power_api():
    library = ctypes.CDLL(_IOBLUETOOTH)
    get_power = library.IOBluetoothPreferenceGetControllerPowerState
    get_power.argtypes = []
    get_power.restype = ctypes.c_int
    set_power = library.IOBluetoothPreferenceSetControllerPowerState
    set_power.argtypes = [ctypes.c_int]
    set_power.restype = None
    return get_power, set_power


def _macos_set_controller_power(enabled: bool, *, timeout: float = 8.0) -> bool:
    """Power the macOS Bluetooth controller on or off via IOBluetooth.

    ``IOBluetoothPreferenceSetControllerPowerState`` is the call ``blueutil -p``
    uses. Poll until the getter matches, the same way that tool waits for
    bluetoothd to finish the transition.
    """
    get_power, set_power = _macos_power_api()
    want = 1 if enabled else 0
    if int(get_power()) == want:
        return True
    set_power(want)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if int(get_power()) == want:
            return True
        time.sleep(0.1)
    return False


def _macos_release(*, allow_radio_power_off: bool) -> list[str]:
    steps: list[str] = []
    if not allow_radio_power_off:
        return steps
    # bluetoothd keeps the HCI interface until the controller is powered off.
    powered_off = False
    try:
        powered_off = _macos_set_controller_power(False)
    except (AttributeError, OSError):
        logger.debug("IOBluetooth power-off unavailable", exc_info=True)
    if powered_off:
        steps.append("Turned macOS Bluetooth power off")
        time.sleep(0.6)
        return steps
    blueutil = shutil.which("blueutil")
    if blueutil is not None and _run_quiet([blueutil, "-p", "0"]):
        steps.append("Turned macOS Bluetooth power off (blueutil)")
        time.sleep(0.6)
        return steps
    steps.append(
        "Could not turn macOS Bluetooth off. Turn it off in System Settings, "
        "then click ↻ again."
    )
    return steps


# linux/rfkill.h - soft-block every Bluetooth radio without the rfkill(8) binary.
_RFKILL_TYPE_BLUETOOTH = 2
_RFKILL_OP_CHANGE_ALL = 3


def _rfkill_event(blocked: bool) -> bytes:
    """Pack one ``struct rfkill_event`` (8 bytes, protocol v1)."""
    return struct.pack(
        "<IBBBB",
        0,
        _RFKILL_TYPE_BLUETOOTH,
        _RFKILL_OP_CHANGE_ALL,
        1 if blocked else 0,
        0,
    )


def _linux_rfkill_write(blocked: bool) -> bool:
    try:
        descriptor = os.open("/dev/rfkill", os.O_WRONLY | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        os.write(descriptor, _rfkill_event(blocked))
    except OSError:
        return False
    finally:
        os.close(descriptor)
    return True


def linux_rfkill_set(blocked: bool) -> bool:
    """Soft-block or unblock Bluetooth. ``/dev/rfkill`` first, then the ``rfkill`` command."""
    if _linux_rfkill_write(blocked):
        return True
    binary = shutil.which("rfkill")
    if binary is None:
        return False
    action = "block" if blocked else "unblock"
    return _run_quiet([binary, action, "bluetooth"])


def _controller_device_id(controller: UsbBluetoothController):
    from wifit3.models import DeviceID

    return DeviceID(
        vid=controller.vid,
        pid=controller.pid,
        chipset=controller.chipset,
        vendor=controller.vendor,
        product_name=controller.product_name,
        bus=controller.bus,
        address=controller.address,
    )


def _linux_session_claim(controller: UsbBluetoothController, *, allow_privilege: bool) -> list[str]:
    """Detach btusb from this dongle. Privilege (pkexec) only when the user asked."""
    from wifit3.setup.linux import session_grant_usb, session_prepare_usb

    device_id = _controller_device_id(controller)
    prepared = session_prepare_usb(device_id)
    if prepared.ok:
        return [prepared.message]
    if not allow_privilege:
        return []
    granted = session_grant_usb(device_id)
    if granted.ok or granted.message:
        return [granted.message]
    return []


def _linux_release(
    controller: UsbBluetoothController | None = None,
    *,
    allow_privilege: bool = False,
) -> list[str]:
    steps: list[str] = []
    if shutil.which("bluetoothctl"):
        if _run_quiet(["bluetoothctl", "power", "off"]):
            steps.append("Bluetooth adapter powered off (bluetoothctl)")
            time.sleep(0.5)
        else:
            steps.append("bluetoothctl power off failed (DBus session?)")
    if linux_rfkill_set(True):
        steps.append("Blocked Bluetooth via rfkill")
        time.sleep(0.3)
    if controller is not None:
        try:
            steps.extend(_linux_session_claim(controller, allow_privilege=allow_privilege))
        except Exception:
            logger.debug("Linux Bluetooth USB session claim failed", exc_info=True)
    return steps
