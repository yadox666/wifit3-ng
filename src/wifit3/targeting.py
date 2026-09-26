from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from wifit3.bluetooth.assigned_numbers import manufacturer_label
from wifit3.bluetooth.classification import device_category
from wifit3.id import vendor_for_mac
from wifit3.models import AccessPoint, BluetoothDevice, Client
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
    details = {
        "identifier": device.identifier,
        "name": device.name,
        "manufacturer": manufacturer,
        "probable_type": device_category(device),
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
