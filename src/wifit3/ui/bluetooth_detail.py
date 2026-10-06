"""Shared BT/BLE device detail rendering (scanner log + USB lab panel).

The scanner's detail log and the USB lab's device panel must show the exact same
information, so the full line-by-line renderer lives here and both screens call
it. Kept in a neutral module to avoid a circular import between the scanner and
the USB lab screen.
"""
from __future__ import annotations

from collections.abc import Callable

from rich.markup import escape

from wifit3.bluetooth.analytics import is_bluetooth_bd_addr, normalize_ble_mac
from wifit3.bluetooth.apple_identifiers import format_device_model_number
from wifit3.bluetooth.assigned_numbers import (
    known_company_label,
    manufacturer_label,
    service_label,
    service_name,
    service_uuid_owner,
)
from wifit3.bluetooth.classification import device_classification
from wifit3.bluetooth.sources import sources_label
from wifit3.models import BluetoothDevice
from wifit3.ui.catalog_format import catalog_detail_lines
from wifit3.ui.signal_bar import dbm_style


def _is_anonymous_apple(device: BluetoothDevice) -> bool:
    return 0x004C in device.manufacturer_ids and device.name == "<Unknown>"


def _discovery_source_label(source: str) -> str:
    if source == "system+usb-hci":
        return "system BLE + dedicated USB HCI"
    if source == "usb-hci":
        return "dedicated USB HCI"
    return "system BLE"


def _address_kind_label(address_type: str) -> str:
    """Short, user-facing stability/privacy label for a Bluetooth address."""
    return {
        "public": "public/stable (OUI-based, trackable)",
        "public-identity": "public identity/stable (trackable)",
        "random-identity": "random identity/stable after bonding",
        "random-static": "random static (stable until changed/restarted)",
        "resolvable-private": "private rotating (RPA; IRK-resolvable)",
        "non-resolvable-private": "private random (NRPA; non-resolvable)",
        "random-reserved": "random/reserved pattern",
        "random": "random (privacy subtype unknown)",
        "anonymous": "anonymous (no device address)",
        "platform-opaque": "OS-opaque UUID (MAC hidden)",
        "unknown": "unknown",
        "": "unknown",
    }.get(address_type, address_type)


def bluetooth_manufacturer_label(device: BluetoothDevice) -> str:
    """Advertisement manufacturer, falling back to member service UUID owners."""
    direct = manufacturer_label(device.manufacturer_ids, device.identifier)
    owners = {
        owner
        for uuid in set(device.service_uuids) | set(device.service_data_uuids)
        if (owner := service_uuid_owner(uuid))
    }
    owner_label = ", ".join(sorted(owners))
    if device.manufacturer_ids:
        return (
            known_company_label(device.manufacturer_ids)
            or owner_label
            or ", ".join(f"0x{company_id:04X}" for company_id in device.manufacturer_ids)
        )
    return direct or owner_label


def displayed_service_uuids(device: BluetoothDevice) -> tuple[str, ...]:
    """Services excluding UUIDs that only identify their registered company."""
    services = sorted(set(device.service_uuids) | set(device.service_data_uuids))
    return tuple(uuid for uuid in services if service_uuid_owner(uuid) is None)


def translated_service_labels(device: BluetoothDevice) -> tuple[str, ...]:
    """Displayed advertised or GATT-discovered services with readable names."""
    services = displayed_service_uuids(device)
    labels: list[str] = []
    for uuid in services:
        short_name = service_name(uuid)
        labels.append(
            short_name
            if short_name.startswith("Custom (")
            else service_label(uuid)
        )
    return tuple(labels)


def advertised_services_tooltip(device: BluetoothDevice) -> str:
    labels = translated_service_labels(device)
    if not labels:
        return "No advertised or GATT-discovered services"
    return "Advertised / discovered services\n" + "\n".join(
        f"• {label}" for label in labels
    )


def device_detail_lines(
    device: BluetoothDevice,
    *,
    apple_expanded: bool = False,
    device_information_hint: Callable[[BluetoothDevice], str] | None = None,
) -> list[str]:
    """Full BT/BLE device detail as Rich-markup lines (shared scanner + lab)."""
    lines: list[str] = []
    manufacturer = bluetooth_manufacturer_label(device) or "Unknown"
    classification = device_classification(device)
    category = classification.category
    service_details = translated_service_labels(device)
    tx_power = f"{device.tx_power} dBm" if device.tx_power is not None else "not advertised"
    interval = (
        f"{device.advertisement_interval * 1000:.0f} ms"
        if device.advertisement_interval is not None else "waiting for another packet"
    )
    duration = max(0.0, device.last_seen - device.first_seen)
    identifier = (
        f"approximately {device.group_size} recently observed rotating identifiers"
        if device.approximate_group else device.identifier
    )
    lines.append(f"[bold]{device.name}[/bold]  [dim]{identifier}[/dim]")
    sources = getattr(device, "observation_sources", ())
    discovery = (
        sources_label(sources) if sources
        else _discovery_source_label(device.discovery_source)
    )
    lines.append(
        f"Radio: [bold cyan]{device.radio_label}[/bold cyan]  "
        f"Discovery: [bold]{escape(discovery)}[/bold]"
    )
    resolved_mac = normalize_ble_mac(device.ble_mac)
    if (
        not device.approximate_group
        and resolved_mac
        and (
            not is_bluetooth_bd_addr(device.identifier)
            or device.identifier.upper() != resolved_mac
        )
    ):
        lines.append(
            f"Resolved BLE MAC: [bold]{escape(resolved_mac)}[/bold]  "
            "[dim](from OS stack when available)[/dim]"
        )
    if device.approximate_group:
        lines.append(
            "[bold yellow]Approximate privacy group:[/bold yellow] identifiers cannot be "
            "proven to belong to the same physical device. Press [bold]Enter[/bold] to expand."
        )
    elif apple_expanded and _is_anonymous_apple(device):
        lines.append(
            "[dim]Expanded Apple privacy identifier; press Enter to collapse the group.[/dim]"
        )
    lines.append(f"Manufacturer: [bold]{manufacturer}[/bold]")
    if device.hardware_product or device.hardware_vendor:
        hardware = " ".join(
            part
            for part in (device.hardware_vendor, device.hardware_product)
            if part
        )
        lines.append(
            f"Hardware identity: [bold]{escape(hardware)}[/bold]  "
            f"Source: {escape(device.hardware_source or 'BlueZ Device ID')}"
        )
    if device.modalias:
        lines.append(f"BlueZ modalias: {escape(device.modalias)}")
    device_information = [
        (
            "Model",
            format_device_model_number(device.model_number, detail=True)
            if device.model_number
            else device.model_number,
        ),
        ("GATT name", device.gatt_device_name),
        ("Manufacturer (GATT)", device.manufacturer_name),
        ("PnP ID", device.pnp_id),
        ("Firmware", device.firmware_revision),
        ("Hardware", device.hardware_revision),
        ("Software", device.software_revision),
        ("Serial", device.serial_number),
    ]
    if any(value for _, value in device_information):
        lines.append(
            "[bold cyan]GATT identity[/bold cyan] "
            "[dim](GAP 0x1800 + Device Information 0x180A)[/dim]"
        )
        for label, value in device_information:
            if value:
                lines.append(f"  {label}: [bold]{escape(value)}[/bold]")
    if device_information_hint is not None:
        lines.append(
            f"Model (GATT 0x2A24): [bold]{escape(device_information_hint(device))}[/bold]"
        )
    lines.append(
        f"Probable type: [bold cyan]{escape(classification.detail)}[/bold cyan]  "
        f"Category: [bold]{category}[/bold]  "
        f"Evidence: {escape(classification.source)} ({classification.confidence})"
    )
    lines.extend(catalog_detail_lines(device))
    if classification.ambiguous:
        lines.append(
            "[bold yellow]Ambiguous classification:[/bold yellow] equally strong "
            "advertised evidence disagrees."
        )
    baseline_labels = {
        "new": "[bold cyan]new identifier[/bold cyan]",
        "returning": "[green]seen previously[/green]",
        "changed": "[bold yellow]advertising profile changed[/bold yellow]",
        "unavailable": "[dim]history unavailable[/dim]",
    }
    address_kind = _address_kind_label(device.address_type)
    lines.append(
        f"Baseline: {baseline_labels.get(device.baseline_status, escape(device.baseline_status))}  "
        f"Address type: [bold]{escape(device.address_type)}[/bold]  "
        f"MAC kind: [bold]{escape(address_kind)}[/bold]"
    )
    if device.similar_identifier_count > 1 and not device.approximate_group:
        lines.append(
            f"[yellow]Privacy history:[/yellow] {device.similar_identifier_count} identifiers "
            "shared this advertising profile; this does not prove they are one device."
        )
    lines.append(
        f"Signal: [{dbm_style(device.rssi)}]{device.rssi} dBm[/]  TX: {tx_power}  "
        f"Observations: {device.advertisement_count}  Latest gap: {interval}"
    )
    if device.rssi_average is not None:
        lines.append(
            f"Signal window: average [bold]{device.rssi_average:.1f} dBm[/bold]  "
            f"range {device.rssi_min}…{device.rssi_max} dBm  "
            f"trend [bold]{device.rssi_trend}[/bold]  samples {device.rssi_samples}"
        )
    lines.append(
        f"Observed for: {duration:.1f}s  Discovery payload: "
        f"manufacturer {device.manufacturer_data_bytes} B, service {device.service_data_bytes} B"
    )
    if device.class_of_device is not None:
        lines.append(f"Classic class of device: [bold]0x{device.class_of_device:06x}[/bold]")
        lines.append(
            f"Classic inquiry: page scan repetition {device.page_scan_repetition_mode}, "
            f"clock offset {device.clock_offset}"
        )
    if device.appearance is not None:
        lines.append(f"BLE Appearance: [bold]0x{device.appearance:04x}[/bold]")
    if service_details:
        lines.append(f"Advertised services: {len(service_details)}")
        lines.extend(f"  • {escape(label)}" for label in service_details)
    else:
        lines.append("Advertised services: None advertised")
    if device.payload_fingerprint:
        lines.append(
            f"Payload fingerprint: [dim]{device.payload_fingerprint}[/dim]  "
            f"Profile: [dim]{device.profile_fingerprint}[/dim]"
        )
    if device.is_connectable_with_bleak:
        lines.append(
            "[dim]A complete GATT service list requires connecting to the device.[/dim]"
        )
    else:
        lines.append(
            "[dim]This Classic-only observation has no BLE GATT endpoint. "
            "Press Enter for Classic identity, HCI health, and read-only SDP Focus.[/dim]"
        )
    if device.related_identifiers:
        lines.append(
            f"[yellow]Probable BT/BLE relation ({device.correlation_confidence}):[/yellow] "
            f"{', '.join(device.related_identifiers)} · "
            f"{', '.join(device.correlation_evidence)}"
        )
    return lines
