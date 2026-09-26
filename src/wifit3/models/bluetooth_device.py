"""Bluetooth discovery data shared by the scanner backend and UI."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class BluetoothDevice:
    """The latest BLE advertisement observed for one platform device identifier."""

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

