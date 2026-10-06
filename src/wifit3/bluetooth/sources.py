"""Stable, human-readable identifiers for Bluetooth observation sources.

Each radio that can observe a device gets a short, stable *source id*:

- the operating-system BLE stack (Bleak / CoreBluetooth / BlueZ / WinRT) is
  :data:`OS_SOURCE_ID` (``"os"``);
- a dedicated USB controller is ``usb:<slug>`` - e.g. ``usb:sena`` or
  ``usb:realtek``, disambiguated to ``usb:realtek-1`` / ``usb:realtek-2`` when
  several controllers of the same family are present.

These ids let the manager keep *per-source* observation records and route
operations (Focus, enrichment, labs) back to the controller that actually
observed a given device, instead of relying on the legacy combined
``discovery_source`` string.
"""
from __future__ import annotations

from typing import Iterable, Sequence

from wifit3.bluetooth.usb_hci import UsbBluetoothController

#: The operating-system BLE stack (whatever Bleak backend is in use).
OS_SOURCE_ID = "os"

# Legacy combined ``discovery_source`` tokens, kept for backward compatibility
# with persisted history, exports and the Focus views.
LEGACY_OS = "system"
LEGACY_USB = "usb-hci"

_BASE_CHIP_LABEL = {"sena": "Sena", "realtek": "RTL"}


def usb_source_base(controller: UsbBluetoothController) -> str:
    """Return the stable family slug for a USB controller (no ordinal)."""
    vendor = (controller.vendor or "").strip().lower()
    chipset = (controller.chipset or "").strip().lower()
    if "sena" in vendor or chipset.startswith("bluecore"):
        return "sena"
    if "realtek" in vendor or chipset.startswith("rtl"):
        return "realtek"
    token = chipset or vendor
    slug = "".join(ch if ch.isalnum() else "-" for ch in token).strip("-")
    return slug or f"{controller.vid:04x}-{controller.pid:04x}"


def _instance_sort_key(controller: UsbBluetoothController) -> tuple:
    vid, pid, bus, address = controller.instance_key
    return (vid, pid, -1 if bus is None else bus, -1 if address is None else address)


def usb_source_id(
    controller: UsbBluetoothController,
    controllers: Sequence[UsbBluetoothController] = (),
) -> str:
    """Return the ``usb:<slug>`` id for *controller*.

    *controllers* is the set of currently known controllers; when more than one
    shares the same family the id is disambiguated with a 1-based ordinal
    assigned deterministically by bus/address order.
    """
    base = usb_source_base(controller)
    pool: dict[tuple, UsbBluetoothController] = {
        c.instance_key: c for c in controllers
    }
    pool.setdefault(controller.instance_key, controller)
    siblings = sorted(
        (c for c in pool.values() if usb_source_base(c) == base),
        key=_instance_sort_key,
    )
    if len(siblings) <= 1:
        return f"usb:{base}"
    for index, sibling in enumerate(siblings, start=1):
        if sibling.instance_key == controller.instance_key:
            return f"usb:{base}-{index}"
    return f"usb:{base}"


def is_usb_source(source_id: str) -> bool:
    return source_id.startswith("usb:")


def source_chip_label(source_id: str) -> str:
    """Short UI chip label for a source id, e.g. ``OS BLE``, ``Sena``, ``RTL-A``."""
    if source_id == OS_SOURCE_ID:
        return "OS BLE"
    if not is_usb_source(source_id):
        return source_id
    slug = source_id[len("usb:"):]
    base, _, ordinal = slug.partition("-")
    name = _BASE_CHIP_LABEL.get(base, base.upper())
    if ordinal.isdigit():
        letter = chr(ord("A") + int(ordinal) - 1)
        return f"{name}-{letter}"
    return name


def sources_label(source_ids: Iterable[str]) -> str:
    """Join source chip labels for a row, e.g. ``OS BLE · RTL-A · Sena``."""
    ordered = sorted(set(source_ids), key=_source_sort_key)
    return " · ".join(source_chip_label(source_id) for source_id in ordered)


def _source_sort_key(source_id: str) -> tuple:
    # OS first, then USB controllers alphabetically for a stable chip order.
    return (0 if source_id == OS_SOURCE_ID else 1, source_id)


def merge_sources(previous: Iterable[str], *new: str) -> tuple[str, ...]:
    """Accumulate observation source ids, kept sorted and de-duplicated."""
    out = set(previous)
    out.update(s for s in new if s)
    return tuple(sorted(out, key=_source_sort_key))
