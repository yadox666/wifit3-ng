"""Auto role assignment for the Bluetooth radios chosen at startup.

Given the radios the user enabled (the operating-system BLE stack plus any
checked USB controllers), decide which radio should own each *role*:

- :data:`BLE_SCAN` - passive BLE advertisement discovery;
- :data:`CLASSIC_SCAN` - Classic BR/EDR inquiry;
- :data:`BLE_LAB` - direct BLE connect / GATT / LE lab work;
- :data:`CLASSIC_LAB` - Classic connect / SDP / Classic lab work.

This is the **Auto** recommendation shown in the startup picker. It mirrors the
hardware-role table in ``docs/planning/BLUETOOTH-RADIO-ROUTING.md``. The actual
per-device operation routing is done at runtime by :mod:`wifit3.bluetooth.routing`;
these roles are a human-facing summary of what each radio is expected to do.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from wifit3.bluetooth.sources import OS_SOURCE_ID, source_chip_label, usb_source_id
from wifit3.bluetooth.usb_hci import UsbBluetoothController

BLE_SCAN = "BLE scan"
CLASSIC_SCAN = "Classic scan"
BLE_LAB = "BLE lab"
CLASSIC_LAB = "Classic lab"

# Stable display order for role chips.
_ROLE_ORDER = (BLE_SCAN, CLASSIC_SCAN, BLE_LAB, CLASSIC_LAB)


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    """Auto role assignment keyed by source id."""

    os_roles: tuple[str, ...] = ()
    usb_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_ids: dict[tuple, str] = field(default_factory=dict)

    def roles_for(self, source_id: str) -> tuple[str, ...]:
        if source_id == OS_SOURCE_ID:
            return self.os_roles
        return self.usb_roles.get(source_id, ())

    def roles_for_controller(self, controller: UsbBluetoothController) -> tuple[str, ...]:
        source_id = self.source_ids.get(controller.instance_key, "")
        return self.usb_roles.get(source_id, ())


def _ordered(roles: set[str]) -> tuple[str, ...]:
    return tuple(role for role in _ROLE_ORDER if role in roles)


def auto_assign(
    controllers: Sequence[UsbBluetoothController],
    *,
    os_ble_active: bool,
) -> RoleAssignment:
    """Compute the Auto role assignment for the enabled radios."""
    controllers = list(controllers)
    source_ids = {c.instance_key: usb_source_id(c, controllers) for c in controllers}
    roles: dict[tuple, set[str]] = {c.instance_key: set() for c in controllers}
    os_roles: set[str] = set()

    le = [c for c in controllers if c.supports_le]
    classic = [c for c in controllers if c.supports_classic]
    classic_only = [c for c in classic if not c.supports_le]  # Sena/CSR
    dual = [c for c in le if c.supports_classic]  # Realtek

    # BLE discovery: OS Bleak is the preferred discovery radio; otherwise the
    # first LE-capable USB controller interleaves it with Classic.
    if os_ble_active:
        os_roles.add(BLE_SCAN)
    elif le:
        roles[le[0].instance_key].add(BLE_SCAN)

    # Classic discovery: keep a Classic-only dongle (Sena) busy on inquiry;
    # otherwise a dual-mode controller does it.
    classic_scanner = (
        classic_only[0] if classic_only
        else dual[0] if dual
        else classic[0] if classic else None
    )
    if classic_scanner is not None:
        roles[classic_scanner.instance_key].add(CLASSIC_SCAN)

    # BLE lab / connect: a dual-mode controller. With two of them, dedicate the
    # second to direct BLE address discovery + lab so the first keeps Classic.
    if len(dual) > 1:
        ble_lab = dual[1]
        roles[ble_lab.instance_key].add(BLE_SCAN)
    else:
        ble_lab = dual[0] if dual else (le[0] if le else None)
    if ble_lab is not None:
        roles[ble_lab.instance_key].add(BLE_LAB)
    elif os_ble_active:
        os_roles.add(BLE_LAB)

    # Classic lab: a dual-mode controller if present (leaves Sena on scan),
    # otherwise whatever Classic-capable controller exists.
    classic_lab = dual[0] if dual else (classic[0] if classic else None)
    if classic_lab is not None:
        roles[classic_lab.instance_key].add(CLASSIC_LAB)

    return RoleAssignment(
        os_roles=_ordered(os_roles),
        usb_roles={
            source_ids[c.instance_key]: _ordered(roles[c.instance_key])
            for c in controllers
        },
        source_ids=source_ids,
    )


def roles_summary(roles: Sequence[str]) -> str:
    """Compact chip string for a radio's roles, e.g. ``BLE lab · Classic lab``."""
    return " · ".join(roles) if roles else "idle"
