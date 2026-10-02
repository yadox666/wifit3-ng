#!/usr/bin/env python3
"""Probe USB Bluetooth controllers and attempt software reclaim (no TUI)."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from wifit3.bluetooth.manager import BluetoothManager
from wifit3.bluetooth.usb_hci import find_usb_bluetooth_controllers


def main() -> int:
    controllers = find_usb_bluetooth_controllers()
    if not controllers:
        print("No supported USB Bluetooth controllers found.")
        return 0
    manager = BluetoothManager()
    any_fail = False
    for controller in controllers:
        print(
            f"\n{controller.label} ({controller.chipset}) "
            f"bus={controller.bus} addr={controller.address}"
        )
        manager.available_usb_controllers()
        key = controller.instance_key
        if key in manager.usb_not_claimed_keys():
            print("  status: NOT-CLAIMED (before reclaim)")
            ok, message = manager.reclaim_usb_controller(controller)
            print(f"  reclaim: {'OK' if ok else 'FAIL'} — {message}")
            if not ok:
                any_fail = True
        else:
            print("  status: held by wifit3 (reserve OK)")
        if key in manager.usb_not_claimed_keys():
            print("  status: NOT-CLAIMED (after reclaim)")
            any_fail = True
        else:
            print("  status: claimed")
    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
