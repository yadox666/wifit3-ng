"""Deterministic routing of Bluetooth operations to a specific radio.

The manager can have several radios active at once: the operating-system BLE
stack (Bleak) plus one or more dedicated USB controllers. For any operation -
a manual Focus connect, a passive model-enrichment read, or a lab - we must
pick *which* radio performs it, deterministically, from where the device was
actually observed.

Routing rules (see ``docs/planning/BLUETOOTH-RADIO-ROUTING.md``):

- an OS-only UUID/row stays on Bleak;
- a BLE MAC that a USB controller observed goes back to that controller;
- a Classic row goes to the controller that observed it;
- fall back to another radio only when the identifier is compatible with it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from wifit3.bluetooth.analytics import device_lacks_usb_hci_bd_addr
from wifit3.bluetooth.sources import OS_SOURCE_ID, is_usb_source
from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO

# Transport tokens shared with the manager.
BLEAK = "bleak"
USB = "usb"
NONE = "none"


@dataclass(frozen=True, slots=True)
class UsbRadio:
    """A USB controller available to the router."""

    source_id: str
    supports_classic: bool
    supports_le: bool


@dataclass(frozen=True, slots=True)
class Route:
    """The chosen transport for one operation."""

    transport: str  # BLEAK | USB | NONE
    source_id: str  # source performing the operation ("" when NONE)
    reason: str

    @property
    def available(self) -> bool:
        return self.transport != NONE


def _device_sources(device) -> tuple[str, ...]:
    return tuple(getattr(device, "observation_sources", ()) or ())


def _usb_observed_sources(device) -> set[str]:
    return {s for s in _device_sources(device) if is_usb_source(s)}


def _os_observed(device) -> bool:
    return OS_SOURCE_ID in _device_sources(device)


def _usb_reachable(device) -> bool:
    """True when a USB HCI can derive a BD_ADDR for this row."""
    return not device_lacks_usb_hci_bd_addr(
        device.identifier, getattr(device, "related_identifiers", ()),
    )


def _pick_usb(
    radios: Sequence[UsbRadio],
    preferred: set[str],
    *,
    need_le: bool,
    need_classic: bool,
) -> UsbRadio | None:
    def usable(radio: UsbRadio) -> bool:
        if need_le and not radio.supports_le:
            return False
        if need_classic and not radio.supports_classic:
            return False
        return True

    # Prefer a controller that actually observed the device.
    for radio in radios:
        if radio.source_id in preferred and usable(radio):
            return radio
    # Otherwise the first capable controller.
    for radio in radios:
        if usable(radio):
            return radio
    return None


def route_le(
    device,
    *,
    os_active: bool,
    usb_radios: Sequence[UsbRadio] = (),
) -> Route:
    """Choose the transport for an LE GATT operation (connect or enrichment)."""
    bleak_ok = bool(getattr(device, "is_connectable_with_bleak", True))
    usb_le = [r for r in usb_radios if r.supports_le]
    usb_reachable = _usb_reachable(device)
    usb_sources = _usb_observed_sources(device)

    # 1. A BLE MAC that a USB controller observed → that controller.
    if usb_le and usb_reachable and usb_sources:
        radio = _pick_usb(usb_le, usb_sources, need_le=True, need_classic=False)
        if radio is not None:
            return Route(USB, radio.source_id, "BLE address observed by USB controller")

    # 2. An OS-observed row that USB never saw stays on Bleak.
    if os_active and bleak_ok and _os_observed(device) and not usb_sources:
        return Route(BLEAK, OS_SOURCE_ID, "OS BLE observation")

    # 3. Compatible fallbacks, USB first when the address is reachable.
    if usb_le and usb_reachable:
        radio = _pick_usb(usb_le, usb_sources, need_le=True, need_classic=False)
        if radio is not None:
            return Route(USB, radio.source_id, "USB HCI reachable BD_ADDR")
    if os_active and bleak_ok:
        return Route(BLEAK, OS_SOURCE_ID, "OS BLE fallback")
    return Route(NONE, "", "no compatible LE transport")


def route_classic(
    device,
    *,
    usb_radios: Sequence[UsbRadio] = (),
) -> Route:
    """Choose the USB controller for a Classic operation (SDP, name, labs)."""
    usb_classic = [r for r in usb_radios if r.supports_classic]
    if not usb_classic:
        return Route(NONE, "", "no Classic-capable USB controller")
    usb_sources = _usb_observed_sources(device)
    radio = _pick_usb(usb_classic, usb_sources, need_le=False, need_classic=True)
    if radio is None:
        return Route(NONE, "", "no Classic-capable USB controller")
    reason = (
        "Classic row observed by USB controller"
        if radio.source_id in usb_sources
        else "only Classic-capable USB controller"
    )
    return Route(USB, radio.source_id, reason)
