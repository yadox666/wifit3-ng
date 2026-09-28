"""Bluetooth discovery data shared by the scanner backend and UI."""
from __future__ import annotations

from dataclasses import dataclass


BLE_RADIO = "BLE"
CLASSIC_RADIO = "BT"


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
    class_of_device: int | None = None
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

