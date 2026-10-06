from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from wifit3.bluetooth.assigned_numbers import manufacturer_label
from wifit3.bluetooth.classification import device_classification
from wifit3.id import vendor_for_mac
from wifit3.models import AccessPoint, BluetoothDevice, Client
from wifit3.observe.product_catalog import (
    CatalogHit,
    catalog_family_record,
    catalog_hit_for_family_id,
    matched_bluetooth_family_ids,
    matched_wifi_family_ids,
)
from wifit3.persist.targets import SavedTarget, TargetMember, TargetStore
from wifit3.wlan.enterprise_risk import enterprise_findings


@dataclass(frozen=True)
class TargetCandidate:
    medium: str
    kind: str
    identifier: str
    title: str
    details: dict[str, Any]
    match_mode: str = "id"


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


def catalog_family_candidate(family_id: str) -> TargetCandidate:
    """Target group member: any radio that matches this catalog family id."""
    wanted = (family_id or "").strip()
    record = catalog_family_record(wanted) if wanted else None
    hit = catalog_hit_for_family_id(wanted) if wanted else CatalogHit()
    label = (
        record.get("label", wanted)
        if isinstance(record, dict) else wanted
    )
    catalog_class = (
        str(record.get("class") or "")
        if isinstance(record, dict) else hit.catalog_class
    )
    return TargetCandidate(
        medium="catalog",
        kind="family",
        identifier=wanted,
        title=str(label or wanted),
        details={
            "catalog_family_id": wanted,
            "catalog_class": catalog_class,
            "catalog_labels": list(hit.labels),
        },
        match_mode="id",
    )


def infrastructure_candidate(
    members: list[AccessPoint] | tuple[AccessPoint, ...],
) -> TargetCandidate | None:
    """Create one SSID rule from a collapsed same-SSID infrastructure."""
    if not members:
        return None
    ssids = {
        (ap.ssid or "").strip()
        for ap in members
        if (ap.ssid or "").strip()
    }
    if len(ssids) != 1:
        return None
    ssid = next(iter(ssids))
    security_levels = sorted({_ap_security_label(ap) for ap in members})
    security = (
        security_levels[0]
        if len(security_levels) == 1
        else "Mixed: " + ", ".join(security_levels)
    )
    channels = sorted({ap.channel for ap in members})
    details = {
        "ssid": ssid,
        "infrastructure": True,
        "ap_count": len(members),
        "bssids": [ap.bssid for ap in members],
        "channels": channels,
        "encryption": security,
        "security_levels": security_levels,
        "wps": any(ap.wps for ap in members),
    }
    return TargetCandidate(
        medium="wifi",
        kind="ap",
        identifier=ssid,
        title=ssid,
        details=details,
        match_mode="name",
    )


def _ap_security_label(ap: AccessPoint) -> str:
    akms = {str(akm).upper() for akm in ap.akms}
    if ap.wpa3 and ap.transition_mode:
        return "WPA2/3-PSK"
    if ap.wpa3:
        return "WPA3-SAE"
    if any("EAP" in akm for akm in akms):
        return "WPA2-Enterprise"
    if akms or (ap.encryption or "").upper().startswith("WPA2"):
        return "WPA2-PSK"
    return (ap.encryption or "Unknown").upper()


def client_candidate(
    client: Client,
    access_point: AccessPoint | None,
) -> TargetCandidate:
    details = {
        "mac": client.mac,
        "known_macs": [client.mac],
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
    correlation_links = (
        device.correlation_links
        if device.correlation_links
        else tuple(
            (
                identifier,
                device.correlation_confidence or "medium",
                device.correlation_evidence,
            )
            for identifier in device.related_identifiers
        )
    )
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
        "probable_links": [
            {
                "identifier": identifier,
                "confidence": confidence,
                "evidence": list(evidence),
            }
            for identifier, confidence, evidence in correlation_links
        ],
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
    return (
        _member_editor_category(target.members[0])
        if target.members else "all"
    )


def editor_categories(target: SavedTarget) -> set[str]:
    if target.role == "whitelist":
        return {"whitelist"}
    return {
        _member_editor_category(member)
        for member in target.members
    }


def _member_editor_category(member: TargetMember) -> str:
    if member.medium == "catalog" and member.kind == "family":
        return "catalog"
    if member.medium == "wifi" and member.kind == "ap":
        return "ap"
    if member.medium == "wifi" and member.kind == "client":
        return "sta"
    radios = {
        str(item).casefold()
        for item in (member.details.get("radio_types") or [])
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
        "catalog": "Catalog family",
    }.get(category, category)


def _wifi_ap_catalog_family_ids(ap: AccessPoint) -> frozenset[str]:
    return matched_wifi_family_ids(
        ap.ssid,
        ap.bssid,
        ap.capabilities.vendor_ouis,
        catalog_family_id=ap.capabilities.catalog_family_id,
    )


def target_matches_wifi_ap(target: SavedTarget, ap: AccessPoint) -> bool:
    for member in target.members:
        if member.medium == "catalog" and member.kind == "family":
            if member.identifier in _wifi_ap_catalog_family_ids(ap):
                return True
            continue
        if member.medium != "wifi" or member.kind != "ap":
            continue
        if member.match_mode == "id":
            if member.identifier.casefold() == ap.bssid.casefold():
                return True
        elif member.match_mode == "name" and ap.ssid:
            if member.identifier.casefold() == ap.ssid.casefold():
                return True
    return False


def target_matches_bluetooth_device(
    target: SavedTarget,
    device: BluetoothDevice,
) -> bool:
    family_ids = matched_bluetooth_family_ids(device)
    for member in target.members:
        if member.medium == "catalog" and member.kind == "family":
            if member.identifier in family_ids:
                return True
            continue
        if member.medium != "bluetooth" or member.kind != "device":
            continue
        if member.match_mode == "id":
            if member.identifier.casefold() == device.identifier.casefold():
                return True
            related = {
                value.casefold() for value in device.related_identifiers
            }
            if member.identifier.casefold() in related:
                return True
        elif member.match_mode == "name" and device.name and device.name != "<Unknown>":
            if member.identifier.casefold() == device.name.casefold():
                return True
    return False


def match_access_point(store: TargetStore, ap: AccessPoint) -> SavedTarget | None:
    by_bssid = store.find("wifi", "ap", ap.bssid)
    if by_bssid is not None:
        return by_bssid
    if ap.ssid:
        by_name = store.find_by_name("wifi", "ap", ap.ssid)
        if by_name is not None:
            return by_name
    for family_id in _wifi_ap_catalog_family_ids(ap):
        by_family = store.find("catalog", "family", family_id)
        if by_family is not None:
            return by_family
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
    for target, _where in _client_identity_matches(store, client):
        return target
    for entry in _client_probe_matches(store, client):
        return entry
    return None


def _client_identity_matches(
    store: TargetStore,
    client: Client,
) -> list[tuple[SavedTarget, str]]:
    """Match stable saved client identity by a known MAC."""
    observed_mac = client.mac.casefold()
    matches: list[tuple[SavedTarget, str]] = []
    for target in store.ordered("wifi"):
        for member in target.members:
            if (
                member.medium != "wifi"
                or member.kind != "client"
                or member.match_mode != "id"
            ):
                continue
            saved_macs = member.details.get("known_macs", [])
            if not isinstance(saved_macs, (list, tuple, set)):
                saved_macs = []
            known_macs = {
                member.identifier.casefold(),
                *(
                    str(value).casefold()
                    for value in saved_macs
                    if isinstance(value, str)
                ),
            }
            if observed_mac in known_macs:
                matches.append((target, f"client {client.mac} · MAC match"))
                break
    return matches


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

    for target, where in _client_identity_matches(store, client):
        add(target, where)
    for ssid in sorted(client.probed_ssids):
        add(store.find_by_probe(ssid), f"client {client.mac} probing {ssid}")
        add(store.find_by_name("wifi", "ap", ssid), f"client {client.mac} probing {ssid}")
    return sightings


def match_bluetooth_device(
    store: TargetStore,
    device: BluetoothDevice,
) -> SavedTarget | None:
    for family_id in matched_bluetooth_family_ids(device):
        by_family = store.find("catalog", "family", family_id)
        if by_family is not None:
            return by_family
    by_id = store.find("bluetooth", "device", device.identifier)
    if by_id is not None:
        return by_id
    for related in device.related_identifiers:
        linked = store.find("bluetooth", "device", related)
        if linked is not None:
            return linked
    observed_identifier = device.identifier.casefold()
    for target in store.ordered("bluetooth"):
        for member in target.members:
            if member.medium != "bluetooth" or member.kind != "device":
                continue
            probable_links = member.details.get("probable_links")
            if not isinstance(probable_links, list):
                continue
            if any(
                isinstance(link, dict)
                and str(link.get("identifier", "")).casefold()
                == observed_identifier
                and str(link.get("confidence", "medium"))
                in {"medium", "high"}
                for link in probable_links
            ):
                return target
    if device.name and device.name != "<Unknown>":
        by_name = store.find_by_name("bluetooth", "device", device.name)
        if by_name is not None:
            return by_name
    return None


def match_candidate(store: TargetStore, candidate: TargetCandidate) -> SavedTarget | None:
    if candidate.medium == "catalog" and candidate.kind == "family":
        return store.find(
            candidate.medium,
            candidate.kind,
            candidate.identifier,
        )
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


def _summary_value(value: Any, *, max_len: int = 56) -> str | None:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value == int(value):
            value = int(value)
        return str(value)
    if isinstance(value, list):
        items = [str(item) for item in value if item not in (None, "", [])]
        if not items:
            return None
        if len(items) > 3:
            return ", ".join(items[:3]) + f" (+{len(items) - 3} more)"
        return ", ".join(items)
    text = str(value).strip()
    if not text or text == "<Unknown>":
        return None
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def _summary_pair(
    lines: list[tuple[str, str]],
    label: str,
    value: Any,
) -> None:
    rendered = _summary_value(value)
    if rendered is not None:
        lines.append((label, rendered))


def _format_wifi_channel(channel: Any) -> str | None:
    if channel in (None, ""):
        return None
    try:
        number = int(channel)
    except (TypeError, ValueError):
        return _summary_value(channel)
    if 1 <= number <= 14:
        band = "2.4 GHz"
    elif number > 14:
        band = "5 GHz"
    else:
        band = ""
    return f"Ch {number} on {band}" if band else f"Ch {number}"


def _signal_strength_label(dbm: Any) -> str | None:
    try:
        value = int(dbm)
    except (TypeError, ValueError):
        return _summary_value(dbm)
    if value >= -55:
        bars = "▮▮▮▮"
        word = "Strong"
    elif value >= -67:
        bars = "▮▮▮▯"
        word = "Good"
    elif value >= -75:
        bars = "▮▮▯▯"
        word = "Fair"
    else:
        bars = "▮▯▯▯"
        word = "Weak"
    return f"{bars}  {value} dBm · {word}"


def observation_kind_subtitle(medium: str, kind: str) -> str:
    return {
        ("wifi", "ap"): "Wi-Fi access point",
        ("wifi", "client"): "Wi-Fi client",
        ("bluetooth", "device"): "Bluetooth device",
        ("catalog", "family"): "Product catalog family",
    }.get((medium, kind), "Device")


def observation_summary_lines(
    medium: str,
    kind: str,
    details: dict[str, Any],
    *,
    identifier: str = "",
) -> list[tuple[str, str]]:
    """Short, human-readable fields for the targets editor (not full stored JSON)."""
    lines: list[tuple[str, str]] = []
    if medium == "wifi" and kind == "ap":
        ssid = details.get("ssid")
        if ssid:
            _summary_pair(lines, "Network", ssid)
        if details.get("infrastructure"):
            _summary_pair(lines, "Scope", f"{details.get('ap_count', 0)} APs by SSID")
            _summary_pair(lines, "Security", details.get("encryption"))
            _summary_pair(lines, "Channels", details.get("channels"))
            bssids = details.get("bssids")
            if isinstance(bssids, list):
                _summary_pair(lines, "BSSIDs", f"{len(bssids)} captured")
            return lines
        _summary_pair(lines, "Address", details.get("bssid") or identifier)
        _summary_pair(lines, "Channel", _format_wifi_channel(details.get("channel")))
        _summary_pair(lines, "Security", details.get("encryption"))
        signal = details.get("signal_dbm")
        if signal is not None:
            _summary_pair(lines, "Signal", _signal_strength_label(signal))
        _summary_pair(lines, "Vendor", details.get("manufacturer"))
    elif medium == "wifi" and kind == "client":
        mac = details.get("mac") or details.get("client_mac") or identifier
        _summary_pair(lines, "Address", mac)
        _summary_pair(lines, "Known MACs", details.get("known_macs"))
        _summary_pair(lines, "Vendor", details.get("manufacturer"))
        _summary_pair(lines, "On network", details.get("associated_ssid"))
        _summary_pair(lines, "AP", details.get("associated_bssid"))
        signal = details.get("signal_dbm")
        if signal is not None:
            _summary_pair(lines, "Signal", _signal_strength_label(signal))
        access_points = details.get("access_points")
        if isinstance(access_points, list) and access_points:
            latest = max(
                access_points,
                key=lambda item: item.get("last_seen") or 0,
            )
            _summary_pair(lines, "Last SSID", latest.get("ssid"))
            _summary_pair(lines, "Last AP", latest.get("bssid"))
        _summary_pair(lines, "Probed SSIDs", details.get("probe_requests"))
    elif medium == "catalog" and kind == "family":
        _summary_pair(lines, "Family", details.get("catalog_labels") or details.get("label"))
        _summary_pair(lines, "Class", details.get("catalog_class"))
        _summary_pair(lines, "Family id", details.get("catalog_family_id") or identifier)
    elif medium == "bluetooth" and kind == "device":
        _summary_pair(lines, "Name", details.get("name"))
        _summary_pair(lines, "ID", details.get("identifier") or identifier)
        _summary_pair(lines, "Radio", details.get("radio_types"))
        signal = details.get("signal_dbm")
        if signal is not None:
            _summary_pair(lines, "Signal", _signal_strength_label(signal))
        _summary_pair(lines, "Vendor", details.get("manufacturer"))
        device_type = details.get("probable_type") or details.get("exact_type")
        _summary_pair(lines, "Type", device_type)
        protocol = details.get("protocol")
        if isinstance(protocol, dict):
            _summary_pair(
                lines,
                "Protocol",
                protocol.get("label") or protocol.get("type"),
            )
        else:
            _summary_pair(lines, "Protocol", protocol)
        probable_links = details.get("probable_links")
        if isinstance(probable_links, list) and probable_links:
            confidence = {
                str(item.get("confidence", "medium"))
                for item in probable_links
                if isinstance(item, dict)
            }
            label = "high" if "high" in confidence else "medium"
            _summary_pair(
                lines,
                "Radio link",
                f"{len(probable_links)} probable counterpart(s) · {label}",
            )
    return lines


def observation_display_markup(
    medium: str,
    kind: str,
    details: dict[str, Any],
    *,
    identifier: str = "",
    headline: str = "",
    layout: str = "card",
) -> str:
    """Rich markup for the targets editor observation pane."""
    from rich.markup import escape

    if medium == "wifi" and kind == "ap":
        name = headline or _summary_value(details.get("ssid")) or "Hidden network"
    elif medium == "wifi" and kind == "client":
        name = headline or _summary_value(
            details.get("mac") or details.get("client_mac") or identifier,
        ) or "Wi-Fi client"
    elif medium == "bluetooth" and kind == "device":
        name = headline or _summary_value(details.get("name")) or _summary_value(
            details.get("identifier") or identifier,
        ) or "Bluetooth device"
    else:
        name = headline or identifier or "Device"

    subtitle = (
        "Wi-Fi infrastructure"
        if medium == "wifi" and kind == "ap" and details.get("infrastructure")
        else observation_kind_subtitle(medium, kind)
    )
    pairs = observation_summary_lines(
        medium,
        kind,
        details,
        identifier=identifier,
    )
    if medium == "wifi" and kind == "ap":
        pairs = [
            (label, value)
            for label, value in pairs
            if label != "Network" or value != name
        ]
    pairs = [
        (label, value)
        for label, value in pairs
        if label != "Name" or value != name
    ]
    row_markup = [
        f"[dim]{escape(label):12}[/]  [bold]{escape(value)}[/]"
        for label, value in pairs
    ]
    if not row_markup:
        row_markup = ["[dim]No extra details were captured[/dim]"]

    if layout == "draft":
        return (
            f"[bold cyan]{escape(name)}[/]\n"
            f"[dim]{escape(subtitle)}[/]\n\n"
            + "\n".join(row_markup)
        )

    return (
        f"[bold]{escape(name)}[/]\n"
        f"[dim italic]{escape(subtitle)}[/]\n\n"
        + "\n".join(row_markup)
    )


def offline_record_candidate(
    kind: str,
    record: dict[str, Any],
) -> TargetCandidate | None:
    """Build a targets-editor draft from an Offline DB row."""
    details = _json_safe(
        {key: value for key, value in record.items() if key != "positions"},
    )
    if not isinstance(details, dict):
        details = {}
    if kind == "aps":
        bssid = str(record.get("bssid") or "")
        if not bssid:
            return None
        ssid = record.get("ssid")
        title = str(ssid or bssid)
        return TargetCandidate(
            medium="wifi",
            kind="ap",
            identifier=bssid,
            title=title,
            details=details,
        )
    if kind == "clients":
        mac = str(record.get("client_mac") or "")
        if not mac:
            return None
        return TargetCandidate(
            medium="wifi",
            kind="client",
            identifier=mac,
            title=mac,
            details=details,
        )
    if kind == "bluetooth":
        identifier = str(record.get("identifier") or "")
        if not identifier:
            return None
        name = record.get("name")
        title = (
            str(name)
            if isinstance(name, str) and name and name != "<Unknown>"
            else identifier
        )
        return TargetCandidate(
            medium="bluetooth",
            kind="device",
            identifier=identifier,
            title=title,
            details=details,
        )
    return None
