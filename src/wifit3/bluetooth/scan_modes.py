"""Per-controller scan-mode selection for the startup picker.

Each USB controller can be told *which radios to actively discover on*:

- :data:`AUTO` - let the manager decide (dual-mode dongles defer BLE discovery
  to the OS stack when it is active, and run Classic inquiry on USB);
- :data:`BT_BLE` - scan both Classic and BLE on this dongle;
- :data:`BT` - Classic inquiry only;
- :data:`BLE` - BLE advertisement discovery only.

The user cycles these by clicking the mode chip in the Bluetooth picker. The
resolved ``(le, classic)`` pair from :func:`effective_scan_radios` is applied to
the live scanner so the selection actually changes what the dongle does.
"""
from __future__ import annotations

from wifit3.bluetooth.usb_hci import UsbBluetoothController

AUTO = "auto"
BT_BLE = "bt_ble"
BT = "bt"
BLE = "ble"

_LABELS = {AUTO: "Auto", BT_BLE: "BT+BLE", BT: "BT", BLE: "BLE"}


def mode_label(mode: str) -> str:
    return _LABELS.get(mode, mode)


def valid_modes(controller: UsbBluetoothController) -> tuple[str, ...]:
    """Modes that make sense for a controller's radios (AUTO always first)."""
    le = controller.supports_le
    classic = controller.supports_classic
    if le and classic:
        return (AUTO, BT_BLE, BT, BLE)
    if classic:
        return (AUTO, BT)
    if le:
        return (AUTO, BLE)
    return (AUTO,)


def next_mode(controller: UsbBluetoothController, mode: str) -> str:
    """Cycle to the next valid mode for this controller."""
    modes = valid_modes(controller)
    try:
        index = modes.index(mode)
    except ValueError:
        return modes[0]
    return modes[(index + 1) % len(modes)]


def effective_scan_radios(
    controller: UsbBluetoothController,
    mode: str,
    *,
    os_ble_active: bool,
) -> tuple[bool, bool]:
    """Resolve a mode to ``(le, classic)`` discovery flags for this controller."""
    le = controller.supports_le
    classic = controller.supports_classic
    if mode == BT_BLE:
        return (le, classic)
    if mode == BT:
        return (False, classic)
    if mode == BLE:
        return (le, False)
    # AUTO: on a dual-mode dongle, defer BLE discovery to the OS when it is
    # active so the two radios don't fight; otherwise do everything the dongle
    # supports.
    if le and classic:
        return (not os_ble_active, True)
    return (le, classic)
