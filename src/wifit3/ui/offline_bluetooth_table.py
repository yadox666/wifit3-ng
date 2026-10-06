"""Offline BT/BLE table rows aligned with the live scanner layout."""
from __future__ import annotations

from typing import Any

from rich.text import Text

from wifit3.bluetooth.assigned_numbers import service_label, service_name
from wifit3.bluetooth.classification import device_classification
from wifit3.bluetooth.gatt_metadata import display_model_label
from wifit3.bluetooth.analytics import is_bluetooth_bd_addr, normalize_ble_mac
from wifit3.persist.bluetooth_history import bluetooth_device_from_offline_record
from wifit3.ui.catalog_format import catalog_class_cell, catalog_family_cell
from wifit3.ui.bluetooth_detail import (
    bluetooth_manufacturer_label,
    displayed_service_uuids,
)
from wifit3.ui.mac_format import mac_address_text

OFFLINE_BLUETOOTH_COLUMNS: tuple[tuple[str, str], ...] = (
    ("name", "DEVICE"),
    ("model", "MODEL"),
    ("catalog_class", "CLASS"),
    ("catalog_family", "FAMILY"),
    ("radio", "RADIO"),
    ("device_type", "TYPE"),
    ("manufacturer", "MANUFACTURER"),
    ("services", "ADVERTISED SERVICES"),
    ("protocol", "PROTOCOL"),
    ("address", "ADDRESS"),
    ("address_kind", "ADDR KIND"),
    ("location", "GPS"),
    ("target", "TARGET"),
)

OFFLINE_BLUETOOTH_COLUMN_WIDTHS: dict[str, int] = {
    "name": 22,
    "model": 14,
    "catalog_class": 16,
    "catalog_family": 22,
    "radio": 8,
    "device_type": 22,
    "manufacturer": 20,
    "services": 23,
    "protocol": 16,
    "address": 18,
    "address_kind": 12,
    "location": 25,
    "target": 28,
}

_SHORT_ADDRESS_KIND: dict[str, str] = {
    "platform-opaque": "OS UUID",
    "public": "public",
    "public-identity": "public",
    "random-identity": "static",
    "random-static": "static",
    "resolvable-private": "RPA",
    "non-resolvable-private": "NRPA",
    "random-reserved": "random",
    "random": "random",
    "anonymous": "anon",
    "unknown": "unknown",
    "": "unknown",
}


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def short_offline_address_kind(address_type: str) -> str:
    text = str(address_type or "unknown").strip()
    return _SHORT_ADDRESS_KIND.get(text, text or "unknown")


def _offline_address_cell(device) -> Text:
    """Hardware address when known; omit opaque OS identifiers."""
    ident = str(device.identifier or "")
    mac = normalize_ble_mac(getattr(device, "ble_mac", ""))
    if not mac and is_bluetooth_bd_addr(ident):
        mac = normalize_ble_mac(ident)
    if mac:
        return mac_address_text(mac, style="bold", no_wrap=True)
    return Text("·", style="dim", no_wrap=True)


def _name_cell(device) -> Text:
    name = device.name
    cell = Text(no_wrap=True)
    if name == "<Unknown>":
        cell.append("‹unnamed›", style="dim italic")
    else:
        cell.append(_clip(name, OFFLINE_BLUETOOTH_COLUMN_WIDTHS["name"]), style="bold")
    if device.catalog_attention:
        cell = Text("◆ ", style="bold yellow") + cell
    if device.baseline_status == "new":
        cell = Text("+ ", style="bold cyan") + cell
    elif device.baseline_status == "changed":
        cell = Text("Δ ", style="bold yellow") + cell
    return cell


def _services_cell(device) -> Text:
    all_services = displayed_service_uuids(device)
    service_names = [service_name(uuid) for uuid in all_services]
    services_cell = Text(no_wrap=True)
    for index, label in enumerate(service_names[:2]):
        if index:
            services_cell.append("  ·  ", style="dim")
        services_cell.append(_clip(label, 18))
    if len(service_names) > 2:
        services_cell.append(f"  +{len(service_names) - 2}", style="cyan")
    if not service_names:
        services_cell.append("·", style="dim")
    services_cell.truncate(
        OFFLINE_BLUETOOTH_COLUMN_WIDTHS["services"],
        overflow="ellipsis",
    )
    return services_cell


def _protocol_cell(device) -> Text:
    text = (
        device.protocol_type
        or device.decode_state
        or device.protocol_category
        or ""
    ).strip()
    return Text(text if text else "·", style="" if text else "dim", no_wrap=True)


def offline_bluetooth_device(record: dict[str, Any]):
    return bluetooth_device_from_offline_record(record)


def offline_bluetooth_row_cells(
    record: dict[str, Any],
    *,
    location_cell: Text,
    target_cell: Text,
) -> tuple[Any, ...]:
    device = offline_bluetooth_device(record)
    classification = device_classification(device)
    manufacturer = bluetooth_manufacturer_label(device)
    model_text = display_model_label(device)
    model_cell = Text(
        model_text if model_text else "·",
        style="bold" if model_text else "dim",
        no_wrap=False,
    )
    type_cell = Text(
        _clip(classification.detail, OFFLINE_BLUETOOTH_COLUMN_WIDTHS["device_type"]),
        style="cyan",
        no_wrap=True,
    )
    manufacturer_cell = Text(
        _clip(manufacturer, OFFLINE_BLUETOOTH_COLUMN_WIDTHS["manufacturer"])
        if manufacturer else "·",
        style="" if manufacturer else "dim",
        no_wrap=True,
    )
    address_cell = _offline_address_cell(device)
    kind_cell = Text(
        short_offline_address_kind(device.address_type),
        style="dim",
        no_wrap=True,
    )
    return (
        _name_cell(device),
        model_cell,
        catalog_class_cell(device),
        catalog_family_cell(device),
        Text(device.radio_label, style="cyan", no_wrap=True),
        type_cell,
        manufacturer_cell,
        _services_cell(device),
        _protocol_cell(device),
        address_cell,
        kind_cell,
        location_cell,
        target_cell,
    )


def offline_bluetooth_sort_value(record: dict[str, Any], key: str) -> Any:
    device = offline_bluetooth_device(record)
    classification = device_classification(device)
    if key == "name":
        value = device.name
    elif key == "model":
        value = display_model_label(device)
    elif key == "catalog_class":
        value = catalog_class_cell(device).plain.removeprefix("·").strip()
    elif key == "catalog_family":
        value = catalog_family_cell(device).plain.removeprefix("◆").strip()
    elif key == "radio":
        value = device.radio_label
    elif key == "device_type":
        value = classification.detail
    elif key == "manufacturer":
        value = bluetooth_manufacturer_label(device)
    elif key == "services":
        all_services = displayed_service_uuids(device)
        value = " ".join(service_label(uuid) for uuid in all_services)
    elif key == "protocol":
        value = device.protocol_type or device.decode_state or device.protocol_category
    elif key == "address":
        mac = normalize_ble_mac(device.ble_mac)
        if not mac and is_bluetooth_bd_addr(device.identifier):
            mac = normalize_ble_mac(device.identifier)
        value = mac or device.identifier
    elif key == "address_kind":
        value = short_offline_address_kind(device.address_type)
    elif key == "last_seen":
        value = float(record.get("last_seen") or 0.0)
    else:
        value = record.get(key)
    if isinstance(value, str):
        return value.casefold()
    return value
