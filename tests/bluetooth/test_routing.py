"""Deterministic Bluetooth operation routing."""
from types import SimpleNamespace

from wifit3.bluetooth.routing import (
    BLEAK,
    NONE,
    USB,
    UsbRadio,
    route_classic,
    route_le,
)

SENA = UsbRadio("usb:sena", supports_classic=True, supports_le=False)
RTL = UsbRadio("usb:realtek", supports_classic=True, supports_le=True)
RTL_A = UsbRadio("usb:realtek-1", supports_classic=True, supports_le=True)
RTL_B = UsbRadio("usb:realtek-2", supports_classic=True, supports_le=True)


def _device(identifier, sources=(), *, connectable=True, related=()):
    return SimpleNamespace(
        identifier=identifier,
        observation_sources=tuple(sources),
        related_identifiers=tuple(related),
        is_connectable_with_bleak=connectable,
    )


def test_os_only_uuid_row_routes_to_bleak():
    device = _device("41C28AFD-7223-CCD1-6681-2C4127D8F06E", ("os",))
    route = route_le(device, os_active=True, usb_radios=[RTL])
    assert route.transport == BLEAK
    assert route.source_id == "os"


def test_usb_observed_ble_mac_routes_to_that_controller():
    device = _device("AA:BB:CC:DD:EE:FF", ("usb:realtek-2",))
    route = route_le(device, os_active=True, usb_radios=[RTL_A, RTL_B])
    assert route.transport == USB
    assert route.source_id == "usb:realtek-2"


def test_os_observed_mac_stays_on_bleak_when_usb_never_saw_it():
    # Linux-style: OS exposes a MAC, but a dedicated Realtek never observed it.
    device = _device("AA:BB:CC:DD:EE:FF", ("os",))
    route = route_le(device, os_active=True, usb_radios=[RTL])
    assert route.transport == BLEAK


def test_usb_only_uuid_row_has_no_le_transport():
    device = _device("41C28AFD-7223-CCD1-6681-2C4127D8F06E", ())
    route = route_le(device, os_active=False, usb_radios=[RTL])
    assert route.transport == NONE
    assert not route.available


def test_le_falls_back_to_usb_for_reachable_mac_without_os():
    device = _device("AA:BB:CC:DD:EE:FF", ())
    route = route_le(device, os_active=False, usb_radios=[RTL])
    assert route.transport == USB
    assert route.source_id == "usb:realtek"


def test_classic_only_sena_cannot_serve_le():
    device = _device("AA:BB:CC:DD:EE:FF", ("usb:sena",))
    route = route_le(device, os_active=False, usb_radios=[SENA])
    assert route.transport == NONE


def test_classic_route_prefers_observing_controller():
    device = _device("AA:BB:CC:DD:EE:FF", ("usb:sena",))
    route = route_classic(device, usb_radios=[SENA, RTL])
    assert route.transport == USB
    assert route.source_id == "usb:sena"


def test_classic_route_needs_classic_capable_usb():
    device = _device("AA:BB:CC:DD:EE:FF", ("os",))
    route = route_classic(device, usb_radios=[])
    assert route.transport == NONE
