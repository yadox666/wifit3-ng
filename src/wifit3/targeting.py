from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from wifit3.bluetooth.assigned_numbers import manufacturer_label
from wifit3.bluetooth.classification import device_classification
from wifit3.id import vendor_for_mac
from wifit3.models import AccessPoint, BluetoothDevice, Client
from wifit3.persist.targets import SavedTarget, TargetStore
from wifit3.wlan.enterprise_risk import enterprise_findings


@dataclass(frozen=True)
class TargetCandidate:
    medium: str
    kind: str
    identifier: str
    title: str
    details: dict[str, Any]


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (set, tuple, list)):
        return [_json_safe(item) for item in value]
    return value


def ap_candidate(ap: AccessPoint) -> TargetCandidate:
    identity = ap.identity
    details = {
        "ssid": ap.ssid,
        "bssid": ap.bssid,
        "manufacturer": identity.manufacturer or vendor_for_mac(ap.bssid),
        "model_name": identity.model_name,
        "model_number": identity.model_number,
        "device_name": identity.device_name,
        "device_type": identity.device_type,
        "serial_number": identity.serial_number,
        "channel": ap.channel,
        "signal_dbm": ap.signal,
        "encryption": ap.encryption,
        "akms": list(ap.akms),
        "pairwise_cipher": ap.pairwise_cipher,
        "group_cipher": ap.group_cipher,
        "wpa3": ap.wpa3,
        "transition_mode": ap.transition_mode,
        "pmf_capable": ap.pmf_capable,
        "pmf_required": ap.pmf_required,
        "wps": ap.wps,
        "wps_locked": ap.wps_locked,
        "wps_version": ap.wps_version,
        "country_code": ap.country_code,
        "first_seen": ap.first_seen,
        "last_seen": ap.last_seen,
        "capabilities": _json_safe(asdict(ap.capabilities)),
        "enterprise": _json_safe(asdict(ap.enterprise)),
        "enterprise_findings": [
            _json_safe(asdict(finding)) for finding in enterprise_findings(ap)
        ],
    }
    return TargetCandidate(
        medium="wifi",
        kind="ap",
        identifier=ap.bssid,
        title=ap.ssid or ap.bssid,
        details=details,
    )


def client_candidate(
    client: Client,
    access_point: AccessPoint | None,
) -> TargetCandidate:
    details = {
        "mac": client.mac,
        "manufacturer": vendor_for_mac(client.mac),
        "signal_dbm": client.signal,
        "packets": client.packets,
        "associated_bssid": client.bssid,
        "associated_ssid": access_point.ssid if access_point is not None else None,
        "associated_channel": access_point.channel if access_point is not None else None,
        "probe_requests": sorted(client.probed_ssids),
        "probe_observations": {
            ssid: _json_safe(asdict(observation))
            for ssid, observation in sorted(client.probe_observations.items())
        },
        "first_seen": client.first_seen,
        "last_seen": client.last_seen,
        "capabilities": _json_safe(asdict(client.capabilities)),
        "enterprise": _json_safe(asdict(client.enterprise)),
    }
    return TargetCandidate(
        medium="wifi",
        kind="client",
        identifier=client.mac,
        title=client.mac,
        details=details,
    )


def bluetooth_candidate(device: BluetoothDevice) -> TargetCandidate:
    manufacturer = manufacturer_label(device.manufacturer_ids, device.identifier)
    classification = device_classification(device)
    details = {
        "identifier": device.identifier,
        "name": device.name,
        "radio_types": list(device.radio_types),
        "discovery_source": device.discovery_source,
        "class_of_device": device.class_of_device,
        "appearance": device.appearance,
        "manufacturer": manufacturer,
        "probable_type": classification.category,
        "exact_type": classification.detail,
        "classification_source": classification.source,
        "classification_confidence": classification.confidence,
        "protocol_type": device.protocol_type,
        "protocol_source": device.protocol_source,
        "signal_dbm": device.rssi,
        "service_uuids": list(device.service_uuids),
        "service_data_uuids": list(device.service_data_uuids),
        "manufacturer_ids": list(device.manufacturer_ids),
        "manufacturer_data_bytes": device.manufacturer_data_bytes,
        "service_data_bytes": device.service_data_bytes,
        "tx_power_dbm": device.tx_power,
        "advertisement_count": device.advertisement_count,
        "advertisement_interval": device.advertisement_interval,
        "first_seen": device.first_seen,
        "last_seen": device.last_seen,
        "approximate_group": device.approximate_group,
        "group_size": device.group_size,
        "similar_identifier_count": device.similar_identifier_count,
    }
    return TargetCandidate(
        medium="bluetooth",
        kind="device",
        identifier=device.identifier,
        title=device.name if device.name != "<Unknown>" else device.identifier,
        details=details,
    )


def _bluetooth_is_ble(device: BluetoothDevice) -> bool:
    radios = {item.casefold() for item in device.radio_types}
    if "ble" in radios or "le" in radios:
        return True
    if "classic" in radios or "br/edr" in radios:
        return False
    return device.is_connectable_with_bleak


def editor_category(target: SavedTarget) -> str:
    if target.role == "whitelist":
        return "whitelist"
    if target.medium == "wifi" and target.kind == "ap":
        return "ap"
    if target.medium == "wifi" and target.kind == "client":
        return "sta"
    radios = {
        str(item).casefold()
        for item in (target.details.get("radio_types") or [])
    }
    if "classic" in radios or "br/edr" in radios:
        return "bt"
    return "ble"


def editor_category_label(category: str) -> str:
    return {
        "all": "All",
        "ap": "Wi-Fi AP",
        "sta": "Wi-Fi STA",
        "ble": "BLE",
        "bt": "Bluetooth",
        "whitelist": "Whitelist",
    }.get(category, category)


def match_access_point(store: TargetStore, ap: AccessPoint) -> SavedTarget | None:
    by_bssid = store.find("wifi", "ap", ap.bssid)
    if by_bssid is not None:
        return by_bssid
    if ap.ssid:
        return store.find_by_name("wifi", "ap", ap.ssid)
    return None


def _client_probe_matches(store: TargetStore, client: Client) -> list[SavedTarget]:
    seen: set[str] = set()
    matches: list[SavedTarget] = []
    for ssid in sorted(client.probed_ssids):
        for candidate in (
            store.find_by_probe(ssid),
            store.find_by_name("wifi", "ap", ssid),
        ):
            if candidate is not None and candidate.id not in seen:
                seen.add(candidate.id)
                matches.append(candidate)
    return matches


def match_client(
    store: TargetStore,
    client: Client,
) -> SavedTarget | None:
    direct = store.find("wifi", "client", client.mac)
    if direct is not None:
        return direct
    for entry in _client_probe_matches(store, client):
        return entry
    return None


def iter_wifi_client_sightings(
    store: TargetStore,
    client: Client,
) -> list[tuple[SavedTarget, str]]:
    """Distinct saved entries to notify for this client (MAC, probes, AP-name rules)."""
    seen: set[str] = set()
    sightings: list[tuple[SavedTarget, str]] = []

    def add(target: SavedTarget | None, where: str) -> None:
        if target is None or not target.enabled or target.id in seen:
            return
        seen.add(target.id)
        sightings.append((target, where))

    add(store.find("wifi", "client", client.mac), f"client {client.mac}")
    for ssid in sorted(client.probed_ssids):
        add(store.find_by_probe(ssid), f"client {client.mac} probing {ssid}")
        add(store.find_by_name("wifi", "ap", ssid), f"client {client.mac} probing {ssid}")
    return sightings


def match_bluetooth_device(
    store: TargetStore,
    device: BluetoothDevice,
) -> SavedTarget | None:
    by_id = store.find("bluetooth", "device", device.identifier)
    if by_id is not None:
        return by_id
    if device.name and device.name != "<Unknown>":
        by_name = store.find_by_name("bluetooth", "device", device.name)
        if by_name is not None:
            return by_name
    return None


def match_candidate(store: TargetStore, candidate: TargetCandidate) -> SavedTarget | None:
    if candidate.medium == "wifi" and candidate.kind == "ap":
        by_id = store.find(candidate.medium, candidate.kind, candidate.identifier)
        if by_id is not None:
            return by_id
        ssid = candidate.details.get("ssid")
        if isinstance(ssid, str) and ssid:
            return store.find_by_name(candidate.medium, candidate.kind, ssid)
        return None
    if candidate.medium == "wifi" and candidate.kind == "client":
        return store.find(candidate.medium, candidate.kind, candidate.identifier)
    if candidate.medium == "bluetooth" and candidate.kind == "device":
        by_id = store.find(candidate.medium, candidate.kind, candidate.identifier)
        if by_id is not None:
            return by_id
        name = candidate.details.get("name")
        if isinstance(name, str) and name and name != "<Unknown>":
            return store.find_by_name(candidate.medium, candidate.kind, name)
    return None


def is_whitelisted_entry(target: SavedTarget | None) -> bool:
    return target is not None and target.enabled and target.role == "whitelist"


def is_target_entry(target: SavedTarget | None) -> bool:
    return target is not None and target.enabled and target.role == "target"


def is_wifi_client_whitelisted(store: TargetStore, mac: str) -> bool:
    return is_whitelisted_entry(store.find("wifi", "client", mac))


def is_wifi_ap_whitelisted(store: TargetStore, bssid: str) -> bool:
    return is_whitelisted_entry(store.find("wifi", "ap", bssid))


def bluetooth_editor_category(device: BluetoothDevice) -> str:
    return "ble" if _bluetooth_is_ble(device) else "bt"
