"""Best-effort release of a USB Bluetooth HCI adapter from the host OS before libusb claim.

Wi-Fi dongles in wifit3 are usually unbound from the kernel driver (udev / WinUSB) or have no
in-tree driver on macOS, so ``claim_interface`` succeeds on START. Bluetooth HCI adapters are
claimed by bluetoothd (macOS), btusb (Linux), or the Windows Bluetooth stack — the same libusb
detach path often fails until the OS lets go. These helpers try a software release (no replug)
before retrying claim.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wifit3.bluetooth.usb_hci import UsbBluetoothController

logger = logging.getLogger(__name__)


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
) -> list[str]:
    """Ask the OS to drop the HCI interface. Returns human-readable steps attempted."""
    steps: list[str] = []
    if sys.platform == "darwin":
        steps.extend(_macos_release(allow_radio_power_off=allow_radio_power_off))
    elif sys.platform.startswith("linux"):
        steps.extend(_linux_release())
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


def _macos_release(*, allow_radio_power_off: bool) -> list[str]:
    steps: list[str] = []
    if not allow_radio_power_off:
        return steps
    blueutil = shutil.which("blueutil")
    if blueutil is None:
        steps.append(
            "Install blueutil (brew install blueutil) or turn Bluetooth off in "
            "System Settings, then retry claim"
        )
        return steps
    if _run_quiet([blueutil, "-p", "0"]):
        steps.append("Turned macOS Bluetooth power off (blueutil)")
        time.sleep(0.6)
    else:
        steps.append("blueutil could not turn Bluetooth off (try System Settings)")
    return steps


def _linux_release() -> list[str]:
    steps: list[str] = []
    if shutil.which("bluetoothctl"):
        if _run_quiet(["bluetoothctl", "power", "off"]):
            steps.append("Bluetooth adapter powered off (bluetoothctl)")
            time.sleep(0.5)
        else:
            steps.append("bluetoothctl power off failed (DBus session?)")
    if shutil.which("rfkill"):
        if _run_quiet(["rfkill", "block", "bluetooth"]):
            steps.append("Blocked Bluetooth via rfkill")
            time.sleep(0.3)
    return steps
