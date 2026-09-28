from __future__ import annotations

from dataclasses import dataclass, field

from .bluetooth_device import BluetoothDevice


@dataclass(slots=True)
class BluetoothCharacteristic:
    handle: int
    uuid: str
    name: str
    properties: tuple[str, ...]
    value: str = ""
    value_hex: str = ""
    value_bytes: int = 0
    read_error: str = ""
    notifications: int = 0
    notification_bytes: int = 0


@dataclass(slots=True)
class BluetoothService:
    uuid: str
    name: str
    characteristics: list[BluetoothCharacteristic] = field(default_factory=list)


@dataclass(slots=True)
class BluetoothTraffic:
    gatt_reads: int = 0
    read_bytes: int = 0
    notifications: int = 0
    notification_bytes: int = 0
    errors: int = 0


@dataclass(slots=True)
class BluetoothInspection:
    device: BluetoothDevice
    connected: bool = False
    connecting: bool = False
    disconnected_reason: str = ""
    connected_at: float | None = None
    services: list[BluetoothService] = field(default_factory=list)
    traffic: BluetoothTraffic = field(default_factory=BluetoothTraffic)

