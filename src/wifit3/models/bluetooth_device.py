"""Bluetooth discovery data shared by the scanner backend and UI."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .location import SignalPosition


BLE_RADIO = "BLE"
CLASSIC_RADIO = "BT"


def has_stable_persistent_identifier(device: "BluetoothDevice") -> bool:
    identifier = device.identifier.strip()
    return not (
        not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", identifier)
        or identifier.casefold() in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
        or device.address_type in {
            "anonymous",
            "non-resolvable-private",
            "platform-opaque",
            "random",
            "random-reserved",
            "resolvable-private",
        }
    )


def has_coherent_persistent_identity(device: "BluetoothDevice") -> bool:
    if not has_stable_persistent_identifier(device):
        return False
    meaningful_name = device.name.strip().casefold() not in {
        "", "<unknown>", "unknown", "unnamed", "bluetooth device",
    }
    return bool(
        meaningful_name
        or device.service_uuids
        or device.service_data_uuids
        or device.manufacturer_ids
        or device.class_of_device is not None
        or device.appearance is not None
        or device.protocol_type
        or device.modalias
        or device.hardware_vendor
        or device.hardware_product
        or _gatt_identity_present(device)
    )


def _gatt_identity_present(device: "BluetoothDevice") -> bool:
    from wifit3.bluetooth.gatt_metadata import GATT_IDENTITY_STORAGE_FIELDS

    return any(
        str(getattr(device, field, "") or "").strip()
        for field in GATT_IDENTITY_STORAGE_FIELDS
    )


def _is_platform_uuid_identifier(identifier: str) -> bool:
    text = identifier.strip()
    return len(text) == 36 and text.count("-") == 4


def has_advertisement_signal(device: "BluetoothDevice") -> bool:
    return bool(
        device.service_uuids
        or device.service_data_uuids
        or device.manufacturer_ids
        or device.class_of_device is not None
        or device.appearance is not None
    )


def _persistible_unstable_identifier(device: "BluetoothDevice") -> bool:
    if device.address_type in {"anonymous", "non-resolvable-private"}:
        return False
    identifier = device.identifier.strip()
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", identifier):
        return True
    return _is_platform_uuid_identifier(identifier)


def should_persist_bluetooth_observation(device: "BluetoothDevice") -> bool:
    """Whether this row should be written to offline Bluetooth history."""
    if has_coherent_persistent_identity(device):
        return True
    if not _persistible_unstable_identifier(device):
        return False
    return _gatt_identity_present(device) or has_advertisement_signal(device)


@dataclass(slots=True)
class BluetoothDevice:
    """The latest discovery observation for one Bluetooth device identifier."""

    identifier: str
    name: str
    rssi: int
    service_uuids: tuple[str, ...]
    service_data_uuids: tuple[str, ...]
    manufacturer_ids: tuple[int, ...]
    manufacturer_data_bytes: int
    service_data_bytes: int
    tx_power: int | None
    advertisement_count: int
    advertisement_interval: float | None
    first_seen: float
    last_seen: float
    approximate_group: bool = False
    group_size: int = 1
    similar_identifier_count: int = 1
    radio_types: tuple[str, ...] = (BLE_RADIO,)
    discovery_source: str = "system"
    observation_sources: tuple[str, ...] = ()
    class_of_device: int | None = None
    page_scan_repetition_mode: int | None = None
    clock_offset: int | None = None
    appearance: int | None = None
    address_type: str = "unknown"
    payload_fingerprint: str = ""
    profile_fingerprint: str = ""
    baseline_status: str = "unavailable"
    profile_changed: bool = False
    rssi_average: float | None = None
    rssi_min: int | None = None
    rssi_max: int | None = None
    rssi_samples: int = 0
    rssi_trend: str = "insufficient"
    protocol_category: str = ""
    protocol_type: str = ""
    protocol_source: str = ""
    protocol_confidence: str = ""
    modalias: str = ""
    hardware_vendor: str = ""
    hardware_product: str = ""
    hardware_source: str = ""
    related_identifiers: tuple[str, ...] = ()
    correlation_confidence: str = ""
    correlation_evidence: tuple[str, ...] = ()
    correlation_links: tuple[
        tuple[str, str, tuple[str, ...]], ...
    ] = ()
    positions: list[SignalPosition] = field(default_factory=list)
    decode_state: str = ""
    signature_watch: bool = False
    model_number: str = ""
    serial_number: str = ""
    firmware_revision: str = ""
    hardware_revision: str = ""
    software_revision: str = ""
    manufacturer_name: str = ""
    gatt_device_name: str = ""
    pnp_id: str = ""
    catalog_labels: tuple[str, ...] = ()
    catalog_class: str = ""
    catalog_notes: str = ""
    catalog_attention: str = ""
    catalog_live: str = ""
    catalog_live_strong: bool = False
    catalog_sentence: str = ""
    catalog_family_id: str = ""
    ble_mac: str = ""

    @property
    def radio_label(self) -> str:
        if set(self.radio_types) == {BLE_RADIO, CLASSIC_RADIO}:
            return "BT+BLE"
        if CLASSIC_RADIO in self.radio_types:
            return CLASSIC_RADIO
        return BLE_RADIO

    @property
    def is_connectable_with_bleak(self) -> bool:
        return BLE_RADIO in self.radio_types and "system" in self.discovery_source.split("+")

