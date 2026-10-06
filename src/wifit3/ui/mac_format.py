"""MAC/BSSID display without Rich :emoji: shortcode expansion."""
from __future__ import annotations

from typing import Callable, Protocol

from rich.markup import escape
from rich.text import Text


def mac_address_text(value: str, /, **kwargs) -> Text:
    """Render a hardware address for tables and labels.

    Rich treats ``:ab:`` inside markup as an emoji shortcode. MAC addresses
    must use ``emoji=False`` (and escaped markup) so ``08:ab:…`` stays literal.
    """
    text = str(value or "")
    no_wrap = kwargs.pop("no_wrap", None)
    rendered = Text.from_markup(escape(text), emoji=False, **kwargs)
    if no_wrap is not None:
        rendered.no_wrap = no_wrap
    return rendered


class _BluetoothAddressDevice(Protocol):
    identifier: str
    ble_mac: str


def bluetooth_identifier_text(
    device: _BluetoothAddressDevice,
    *,
    shortener: Callable[[str], str] | None = None,
    primary_style: str = "bold",
    secondary_style: str = "dim italic",
) -> Text:
    """Scanner/detail address cell: BD_ADDR when resolved, else platform ID."""
    from wifit3.bluetooth.analytics import is_bluetooth_bd_addr, normalize_ble_mac

    ident = str(device.identifier or "")
    mac = normalize_ble_mac(device.ble_mac)
    if not mac and is_bluetooth_bd_addr(ident):
        mac = normalize_ble_mac(ident)
    short = shortener or (lambda value: value)
    if mac and ident.casefold() != mac.casefold():
        primary = mac_address_text(mac, style=primary_style, no_wrap=True)
        secondary = Text(f"\n{short(ident)}", style=secondary_style, no_wrap=True)
        return primary + secondary
    label = short(ident or mac)
    return mac_address_text(label, style="dim" if not mac else primary_style, no_wrap=True)
