from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping

from wifit3.bluetooth.linux_hwdb import resolve_bluez_modalias
from wifit3.bluetooth.signatures import (
    APPLE_CONTINUITY_PROTOCOLS,
    MANUFACTURER_PROTOCOLS,
    SERVICE_PROTOCOLS,
)
from wifit3.observe.signature_pack import describe_bluetooth


HCI_PUBLIC_ADDRESS = 0x00
HCI_RANDOM_ADDRESS = 0x01
HCI_PUBLIC_IDENTITY_ADDRESS = 0x02
HCI_RANDOM_IDENTITY_ADDRESS = 0x03
HCI_ANONYMOUS_ADDRESS = 0xFF


def hci_address_type(identifier: str, address_type: int) -> str:
    if address_type == HCI_PUBLIC_ADDRESS:
        return "public"
    if address_type == HCI_PUBLIC_IDENTITY_ADDRESS:
        return "public-identity"
    if address_type == HCI_RANDOM_IDENTITY_ADDRESS:
        return "random-identity"
    if address_type == HCI_ANONYMOUS_ADDRESS:
        return "anonymous"
    if address_type != HCI_RANDOM_ADDRESS:
        return "unknown"
    try:
        most_significant = int(identifier.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return "random"
    kind = most_significant >> 6
    return {
        0b00: "non-resolvable-private",
        0b01: "resolvable-private",
        0b11: "random-static",
    }.get(kind, "random-reserved")


_RANDOM_LE_ADDRESS_TYPES = frozenset({
    "random",
    "random-static",
    "random-identity",
    "resolvable-private",
    "non-resolvable-private",
    "random-reserved",
})


def le_hci_peer_address_type(address_type: str, identifier: str = "") -> int:
    """Peer_Address_Type for HCI LE Create Connection (0 public, 1 random)."""
    if address_type in {"public", "public-identity"}:
        return HCI_PUBLIC_ADDRESS
    if address_type in _RANDOM_LE_ADDRESS_TYPES:
        return HCI_RANDOM_ADDRESS
    if address_type in {"", "unknown", "platform-opaque", "anonymous"}:
        try:
            most_significant = int(identifier.split(":", 1)[0], 16)
        except (ValueError, IndexError):
            return HCI_PUBLIC_ADDRESS
        kind = most_significant >> 6
        if kind in {0b01, 0b11}:
            return HCI_RANDOM_ADDRESS
        return HCI_PUBLIC_ADDRESS
    return HCI_RANDOM_ADDRESS


def platform_address_type(identifier: str) -> str:
    if len(identifier) == 36 and identifier.count("-") == 4:
        return "platform-opaque"
    return "unknown"


def normalize_ble_mac(mac: str) -> str:
    """Uppercase colon-separated BD_ADDR, or empty when invalid."""
    text = str(mac or "").strip().upper()
    return text if is_bluetooth_bd_addr(text) else ""


def resolved_ble_mac(device) -> str:
    """Best available 6-byte address for UI, USB HCI, and persistence."""
    identifier = normalize_ble_mac(getattr(device, "identifier", ""))
    if identifier:
        return identifier
    return normalize_ble_mac(getattr(device, "ble_mac", ""))


def is_bluetooth_bd_addr(identifier: str) -> bool:
    """True when ``identifier`` is a colon-separated 6-byte Bluetooth address."""
    parts = identifier.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


def hci_bd_addr_bytes(identifier: str) -> bytes:
    """Little-endian BD_ADDR for HCI commands (MSB of address in last byte)."""
    if not is_bluetooth_bd_addr(identifier):
        raise ValueError(
            f"not a Bluetooth address: {identifier!r} "
            "(expected AA:BB:CC:DD:EE:FF)"
        )
    return bytes.fromhex(identifier.replace(":", ""))[::-1]


def normalized_bluetooth_name(name: str) -> str:
    """Fold a discovery name for equality (DESKTOP-JOI2SAP vs Desktop JOI2SAP)."""
    normalized = "".join(character for character in name.casefold() if character.isalnum())
    if normalized in {"", "unknown", "unnamed", "bluetoothdevice"}:
        return ""
    return normalized if len(normalized) >= 4 else ""


def discovery_names_match(observed_name: str, target_name: str) -> bool:
    left = normalized_bluetooth_name(observed_name)
    right = normalized_bluetooth_name(target_name)
    return bool(left and right and left == right)


def device_lacks_usb_hci_bd_addr(identifier: str, related_identifiers: tuple[str, ...] = ()) -> bool:
    """True when USB HCI cannot derive a 6-byte peer address from the scanner row."""
    if is_bluetooth_bd_addr(identifier):
        return False
    return not any(is_bluetooth_bd_addr(related) for related in related_identifiers)


def ble_advertisement_matches_target(
    observation_identifier: str,
    observation_name: str,
    target_identifier: str,
    *,
    alternate_identifiers: tuple[str, ...] = (),
    target_name: str = "",
) -> bool:
    """Match USB LE reports to a scanner row (MAC, correlated MAC, or name)."""
    observed = observation_identifier.casefold()
    if observed == target_identifier.casefold():
        return True
    for alternate in alternate_identifiers:
        if observed == alternate.casefold():
            return True
    name = (target_name or "").strip()
    if name.casefold() in {"", "<unknown>", "unknown"}:
        return False
    observed_name = (observation_name or "").strip()
    return observed_name.casefold() == name.casefold()


def bluez_platform_metadata(platform_data: tuple, identifier: str) -> dict:
    if len(platform_data) != 2:
        return {}
    path, properties = platform_data
    if (
        not isinstance(path, str)
        or not path.startswith("/org/bluez/")
        or not isinstance(properties, Mapping)
    ):
        return {}
    metadata = {}
    appearance = properties.get("Appearance")
    class_of_device = properties.get("Class")
    if isinstance(appearance, int) and 0 <= appearance <= 0xFFFF:
        metadata["appearance"] = appearance
    if isinstance(class_of_device, int) and 0 <= class_of_device <= 0xFFFFFF:
        metadata["class_of_device"] = class_of_device
    modalias = properties.get("Modalias")
    if isinstance(modalias, str):
        metadata.update(resolve_bluez_modalias(modalias))
    reported_type = properties.get("AddressType")
    if reported_type == "public":
        metadata["address_type"] = "public"
    elif reported_type == "random":
        metadata["address_type"] = hci_address_type(identifier, HCI_RANDOM_ADDRESS)
    return metadata


def payload_fingerprint(
    manufacturer_data: Mapping[int, bytes] | None,
    service_data: Mapping[str, bytes] | None,
) -> str:
    digest = hashlib.sha256()
    for identifier, value in sorted((manufacturer_data or {}).items()):
        digest.update(b"m")
        digest.update(int(identifier).to_bytes(4, "big"))
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    for identifier, value in sorted((service_data or {}).items()):
        encoded = identifier.casefold().encode("utf-8")
        digest.update(b"s")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()[:24] if manufacturer_data or service_data else ""


def protocol_type_hint(
    manufacturer_data: Mapping[int, bytes] | None,
    service_data: Mapping[str, bytes] | None,
    service_uuids: Iterable[str] = (),
    *,
    name: str = "",
) -> dict[str, str]:
    compiled = _compiled_protocol_hint(
        manufacturer_data, service_data, service_uuids, name=name,
    )
    notes = describe_bluetooth(
        manufacturer_data, service_data, tuple(service_uuids), name=name,
    )
    if notes.protocol_type and (notes.prefer or not compiled):
        result = _protocol_hint(
            notes.category, notes.protocol_type, notes.source, notes.confidence,
        )
    else:
        result = dict(compiled)
    if notes.detail:
        result["decode_state"] = notes.detail
    elif notes.prefer:
        result["decode_state"] = ""
    if notes.prefer:
        result["signature_watch"] = "1" if notes.alert else ""
    elif notes.alert:
        result["signature_watch"] = "1"
    return result


def _compiled_protocol_hint(
    manufacturer_data: Mapping[int, bytes] | None,
    service_data: Mapping[str, bytes] | None,
    service_uuids: Iterable[str] = (),
    *,
    name: str = "",
) -> dict[str, str]:
    manufacturers = manufacturer_data or {}
    normalized_name = name.strip().casefold()
    if (
        0x09C8 in manufacturers
        and ("flock" in normalized_name or normalized_name == "fs ext battery")
    ):
        return _protocol_hint(
            "Sensor",
            "Flock Safety camera/accessory",
            "AirHound composite signature",
            "high",
        )
    apple = manufacturers.get(0x004C, b"")
    if apple.startswith(b"\x02\x15"):
        return _protocol_hint("Beacon", "Apple iBeacon", "Manufacturer protocol", "high")
    if apple.startswith(b"\x07"):
        return _protocol_hint(
            "Audio", "Apple Proximity Pairing audio", "Manufacturer protocol", "high",
        )
    if apple.startswith(b"\x12\x19"):
        return _protocol_hint(
            "Tracker",
            "Apple Find My-compatible tracker",
            "AirHound signature",
            "medium",
        )
    if apple.startswith(b"\x06"):
        return _protocol_hint(
            "Other", "Apple HomeKit accessory", "Manufacturer protocol", "medium",
        )
    if len(apple) >= 2 and (signature := APPLE_CONTINUITY_PROTOCOLS.get(apple[0])):
        return _protocol_hint(
            signature.category,
            signature.detail,
            signature.source,
            signature.confidence,
        )
    if any(value.startswith(b"\xBE\xAC") for value in manufacturers.values()):
        return _protocol_hint("Beacon", "AltBeacon", "Manufacturer protocol", "high")
    ruuvi = manufacturers.get(0x0499, b"")
    if ruuvi[:1] in {b"\x03", b"\x05"}:
        return _protocol_hint("Sensor", "Ruuvi sensor", "Manufacturer protocol", "high")
    manufacturer_hint = _manufacturer_protocol_hint(manufacturers)
    if manufacturer_hint:
        return manufacturer_hint
    service_keys = {
        _compact_service_uuid(key)
        for key in (*tuple(service_data or {}), *tuple(service_uuids))
    }
    matches = [
        signature
        for service_uuid, signature in SERVICE_PROTOCOLS.items()
        if service_uuid in service_keys
    ]
    if matches:
        signature = max(
            matches,
            key=lambda candidate: candidate.confidence == "high",
        )
        return {
            "protocol_category": signature.category,
            "protocol_type": signature.detail,
            "protocol_source": signature.source,
            "protocol_confidence": signature.confidence,
        }
    return {}


def _manufacturer_protocol_hint(
    manufacturer_data: Mapping[int, bytes],
) -> dict[str, str]:
    nordic = manufacturer_data.get(0x0059, b"")
    if (
        len(nordic) == 15
        and nordic.startswith(b"\x07\x6c")
        and nordic[11] == 0x01
    ):
        return _protocol_hint(
            "Sensor",
            "MOKOSmart time-of-flight sensor",
            "reelyActive advlib signature",
            "high",
        )
    moko = manufacturer_data.get(0x0A62, b"")
    if len(moko) >= 18 and moko.startswith(b"\x02") and moko[1] + 2 == len(moko):
        return _protocol_hint(
            "Sensor",
            "MOKO proximity sensor",
            "reelyActive advlib signature",
            "high",
        )
    espruino = manufacturer_data.get(0x0590, b"")
    if len(espruino) >= 2 and espruino.startswith(b"{") and espruino.endswith(b"}"):
        try:
            decoded = json.loads(espruino.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, dict):
            return _protocol_hint(
                "Other",
                "Espruino telemetry device",
                "reelyActive advlib signature",
                "medium",
            )
    for signature in MANUFACTURER_PROTOCOLS:
        payload = manufacturer_data.get(signature.company_id)
        if payload is None or not payload.startswith(signature.prefix):
            continue
        if signature.lengths and len(payload) not in signature.lengths:
            continue
        if len(payload) < signature.minimum_length:
            continue
        return _protocol_hint(
            signature.category,
            signature.detail,
            signature.source,
            signature.confidence,
        )
    return {}


def _protocol_hint(
    category: str,
    detail: str,
    source: str,
    confidence: str,
) -> dict[str, str]:
    return {
        "protocol_category": category,
        "protocol_type": detail,
        "protocol_source": source,
        "protocol_confidence": confidence,
    }


def _compact_service_uuid(service_uuid: str) -> str:
    lowered = service_uuid.casefold()
    suffix = "-0000-1000-8000-00805f9b34fb"
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return lowered


def raw_payload_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:24] if data else ""


def profile_fingerprint(
    *,
    name: str,
    address_type: str,
    service_uuids: Iterable[str],
    service_data_uuids: Iterable[str],
    manufacturer_ids: Iterable[int],
    class_of_device: int | None,
    appearance: int | None,
    protocol_type: str,
    decode_state: str = "",
    modalias: str = "",
    hardware_product: str = "",
) -> str:
    profile = {
        "name": "" if name == "<Unknown>" else name,
        "address_type": address_type,
        "service_uuids": sorted(set(service_uuids)),
        "service_data_uuids": sorted(set(service_data_uuids)),
        "manufacturer_ids": sorted(set(manufacturer_ids)),
        "class_of_device": class_of_device,
        "appearance": appearance,
        "protocol_type": protocol_type,
        "decode_state": decode_state,
        "modalias": modalias,
        "hardware_product": hardware_product,
    }
    encoded = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def signal_summary(samples: Iterable[int]) -> tuple[float, int, int, int, str]:
    values = list(samples)
    average = round(sum(values) / len(values), 1)
    trend = "insufficient"
    if len(values) >= 4:
        midpoint = len(values) // 2
        earlier = sum(values[:midpoint]) / midpoint
        later_values = values[midpoint:]
        later = sum(later_values) / len(later_values)
        delta = later - earlier
        trend = "approaching" if delta >= 4 else "leaving" if delta <= -4 else "stable"
    return average, min(values), max(values), len(values), trend
