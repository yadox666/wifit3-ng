"""Explain one access point or station from the same facts used by hand.

The report joins the live beacon, the OUI database (including a locally
administered virtual BSSID), the other band of the same radio, stored
sightings, the product catalog, and associated clients. It does not guess a
password or a street address.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import time
from typing import Any

from wifit3.id.common import is_locally_administered_mac, vendor_for_mac
from wifit3.observe.product_catalog import wifi_catalog_hit
from wifit3.ui.focus_model import band_twins

_LIST_LIMIT = 8
_UPTIME_MATCH_S = 2.0
_GENERIC_SSID_WORDS = frozenset({
    "wifi", "wi", "fi", "plus", "ext", "extender", "iot", "home", "private",
    "public", "free", "default", "wlan", "wireless", "network", "net",
    "band", "ghz", "box",
})
_UNIT_CODE = re.compile(r"[a-z]{1,3}\d{2,4}")


@dataclass
class InvestigateSection:
    title: str
    lines: list[str] = field(default_factory=list)


@dataclass
class InvestigateReport:
    title: str
    conclusion: str
    sections: list[InvestigateSection]


def universal_mac(mac: str) -> str | None:
    """Factory-looking address: the same MAC with the local-admin bit cleared."""
    parts = _octets(mac)
    if parts is None:
        return None
    parts[0] = f"{int(parts[0], 16) ^ 0x02:02x}"
    return ":".join(parts)


def other_band_bssid(mac: str) -> str | None:
    """Sibling address used when a radio flips bit 7 of the fourth octet per band."""
    parts = _octets(mac)
    if parts is None:
        return None
    parts[3] = f"{int(parts[3], 16) ^ 0x80:02x}"
    return ":".join(parts)


def investigate_ap(ap, array=None, history=None) -> InvestigateReport:
    """Build the AP focus investigation from the live record and the history DB."""
    bssid = str(getattr(ap, "bssid", "") or "")
    ssid = getattr(ap, "ssid", None) or "(unnamed)"
    dossier = _call(history, "access_point_dossier", bssid) or {}
    vendor, universal, local = _mac_vendor(bssid)
    twins = band_twins(ap, array) if array is not None else []
    predicted = other_band_bssid(bssid)
    family, neighbors = _same_device(ap, array, history, predicted)
    live_clients = _live_clients(array, bssid)
    stored_clients = list(dossier.get("clients") or [])
    caps = getattr(ap, "capabilities", None)
    router = _router_profile(ap, array, family, history, dossier)
    catalog = router["catalog"]
    paragraphs = _ap_conclusion(
        ap, ssid, vendor, universal, local, twins, predicted, dossier,
        live_clients, family, neighbors, router, catalog,
    )
    router_lines = _router_lines(router)
    if catalog.get("class"):
        router_lines.append(f"Catalog class: {catalog['class']}")
    if catalog.get("family"):
        router_lines.append(f"Catalog family: {catalog['family']}")
    if catalog.get("notes"):
        router_lines.append(f"Catalog notes: {catalog['notes']}")
    sections = [
        InvestigateSection("Vendor", _vendor_lines(bssid, vendor, universal, local)),
        InvestigateSection("Router", router_lines),
        InvestigateSection("Radio", _radio_lines(ap, caps)),
        InvestigateSection("Configuration", _config_lines(ap, caps)),
        InvestigateSection("History", _ap_history_lines(ap, dossier)),
        InvestigateSection("Same device", _relation_lines(ap, twins, predicted, dossier, family)),
        InvestigateSection("Clients", _client_lines(live_clients, stored_clients)),
    ]
    return InvestigateReport(
        title=f"Investigate  {ssid}",
        conclusion="\n\n".join(paragraphs),
        sections=[section for section in sections if section.lines],
    )


def investigate_client(client, array=None, history=None) -> InvestigateReport:
    """Build the client focus investigation from the live station and the history DB."""
    mac = str(getattr(client, "mac", "") or "")
    dossier = _call(history, "client_dossier", mac) or {}
    vendor, universal, local = _mac_vendor(mac)
    ap = _associated_ap(client, array)
    associations = list(dossier.get("associations") or [])
    if not associations and history is not None:
        for record in _call(history, "aps_for_client", mac) or []:
            associations.append({
                "bssid": record.bssid,
                "ssid": record.ssid,
                "channel": record.channel,
                "encryption": record.encryption,
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
            })
    sentences = _client_conclusion(client, vendor, universal, local, ap, associations)
    sections = [
        InvestigateSection("Vendor", _vendor_lines(mac, vendor, universal, local)),
        InvestigateSection("Current network", _current_ap_lines(client, ap)),
        InvestigateSection("Probes", _probe_lines(client)),
        InvestigateSection("Access points", _association_lines(associations)),
        InvestigateSection("Dates", _client_date_lines(client, dossier)),
    ]
    return InvestigateReport(
        title=f"Investigate  {mac}",
        conclusion=" ".join(sentences),
        sections=[section for section in sections if section.lines],
    )


def _ap_conclusion(
    ap, ssid, vendor, universal, local, twins, predicted, dossier, live_clients,
    family, neighbors, router, catalog,
) -> list[str]:
    """Two or three paragraphs: this radio, the chassis, then when and where it was heard."""
    identity: list[str] = []
    chassis: list[str] = []
    context: list[str] = []
    channel = getattr(ap, "channel", None)
    band = _band_name(channel)
    guest_name = _guest_name(ssid, family, predicted)
    if vendor and band and (guest_name or local):
        kind = "guest network" if guest_name else "extra SSID"
        lead = f"This is a {vendor} {band} radio of a {kind}."
        if guest_name and guest_name.casefold() != str(ssid).casefold():
            lead += f" The stored name for this radio is {guest_name}."
        elif ssid and ssid != "(unnamed)":
            lead += f" The name is {ssid}."
        identity.append(lead)
    if catalog.get("sentence"):
        identity.append(catalog["sentence"])
    if local and vendor and universal:
        identity.append(
            f"{getattr(ap, 'bssid', '')} is not a randomized phone address. "
            f"The local bit is set because this vendor adds 2 to the first octet "
            f"for an extra SSID. Clearing it leaves {universal}, the {vendor} prefix."
        )
    elif local and universal:
        identity.append(
            f"The address is locally administered. The universal prefix {universal} "
            "is not in the OUI database."
        )
    elif vendor:
        identity.append(f"The address is factory-assigned and the prefix belongs to {vendor}.")
    else:
        identity.append("The address is factory-assigned and the prefix is not in the OUI database.")
    model_text, band_text = _router_sentence(router, str(getattr(ap, "bssid", "") or ""))
    if model_text:
        identity.append(model_text)
    if band_text:
        chassis.append(band_text)
    borrowed = router.get("borrowed") or ""
    if borrowed:
        chassis.append(borrowed)
    named = _named_family(family, predicted, twins)
    if named:
        chassis.append(named)
    uptime_match = _uptime_sentence(family)
    if uptime_match:
        chassis.append(uptime_match)
    confirmed = _identity_sentence(family)
    if confirmed:
        chassis.append(confirmed)
    neighbor_note = _neighbor_sentence(neighbors)
    if neighbor_note:
        chassis.append(neighbor_note)
    elif predicted and not _already_named(predicted, family, twins):
        chassis.append(
            f"The other band, using the usual fourth-octet step, would be {predicted}."
        )
    mains = _main_ssids(family)
    if mains:
        shown = "; ".join(mains[:4])
        label = _label_bssid(family)
        chassis.append(
            f"The main SSIDs on this Router-AP are {shown}."
            + (f" The router label should show {label}." if label else "")
        )
    block = _home_block(channel, _width(ap))
    if block:
        context.append(
            f"Channel {channel} at {_width(ap)} MHz is the {block} block of a home router, "
            "not a phone hotspot."
        )
    elif channel:
        radio = f"Channel {channel}"
        width = _width(ap)
        if width:
            radio += f", {width} MHz"
        context.append(radio + ".")
    country = getattr(ap, "country_code", None)
    if country:
        context.append(
            f"The beacon announces country {country} as its regulatory domain, "
            "not as the device's location."
        )
        if str(country).upper() == "DE" and vendor and "zyxel" in vendor.casefold():
            context.append(
                "Zyxel European firmware often announces DE even when the router "
                "is outside Germany."
            )
    uptime = _uptime(getattr(ap, "uptime_us", None))
    if uptime:
        context.append(f"The radio has been up for {uptime} since the last boot.")
    if dossier.get("first_seen"):
        context.append(
            f"In the database, first seen {_when(dossier.get('first_seen'))} "
            f"and last seen {_when(dossier.get('last_seen'))}."
        )
    heard = _card_sentence(ap)
    if heard:
        context.append(heard)
    count = len(list(dossier.get("clients") or [])) or len(live_clients)
    if count:
        context.append(f"{count} associated stations can be listed.")
    return [" ".join(group) for group in (identity, chassis, context) if group]


def _client_conclusion(client, vendor, universal, local, ap, associations) -> list[str]:
    sentences: list[str] = []
    mac = str(getattr(client, "mac", "") or "")
    if local and vendor and universal:
        sentences.append(
            f"{mac} is a local address. The equivalent factory prefix is "
            f"{universal}, {vendor}."
        )
    elif local:
        sentences.append(
            f"{mac} is a local address. The operating system rotates it, so it does not "
            "identify the device vendor."
        )
    elif vendor:
        sentences.append(f"{mac} is a factory address from {vendor}.")
    else:
        sentences.append(f"{mac} is a factory address with no vendor in the OUI database.")
    if ap is not None:
        name = ap.ssid or ap.bssid
        sentences.append(f"It is currently on {name}, channel {ap.channel}, {ap.bssid}.")
        ap_vendor, ap_universal, ap_local = _mac_vendor(ap.bssid)
        if ap_local and ap_vendor:
            sentences.append(
                f"That access point is also virtual ({ap_universal}, {ap_vendor})."
            )
    elif associations:
        latest = associations[0]
        name = latest.get("ssid") or latest.get("bssid")
        sentences.append(f"The last stored network is {name}.")
    else:
        sentences.append("No stored association for this station.")
    probes = sorted(getattr(client, "probed_ssids", ()) or ())
    if probes:
        shown = ", ".join(probes[:_LIST_LIMIT])
        sentences.append(f"It has probed for {shown}.")
    return sentences


_EMPTY_FACT = frozenset({
    "", "none", "null", "n/a", "na", "unknown", "0000", "00000000",
})
_SOURCE_RANK = {"WSC_M1": 0, "WSC_BEACON": 1, "OUI": 2}
_PHY_RANK = {
    "802.11b": 0, "802.11g": 1, "802.11a": 2, "802.11n": 3,
    "802.11ac": 4, "802.11ax": 5, "802.11be": 6,
}
_ROUTER_FEATURES = (
    ("wmm", "WMM"),
    ("pmf_capable", "PMF"),
    ("radio_measurement", "802.11k"),
    ("bss_transition", "802.11v"),
    ("fast_transition", "802.11r"),
    ("multi_link", "multi-link"),
)
_ROUTER_FIELDS = (
    ("manufacturer", "Manufacturer"),
    ("model", "Model"),
    ("model_number", "Model number"),
    ("device_name", "Device"),
    ("serial", "Serial"),
    ("wps_version", "WPS version"),
    ("os_version", "OS version"),
)


def _router_profile(ap, array, family, history, dossier) -> dict:
    """Model, serial, version, and radio details taken from every radio of this chassis."""
    own = str(getattr(ap, "bssid", "") or "")
    radios = [_radio_snapshot(ap, dossier, None)]
    seen = {own.casefold()}
    for record in family:
        bssid = str(record.get("bssid") or "")
        if not bssid or bssid.casefold() in seen:
            continue
        seen.add(bssid.casefold())
        stored = _call(history, "access_point_dossier", bssid) or {}
        radios.append(_radio_snapshot(_live_ap(array, bssid), stored, record))
    facts = _router_facts(radios, own)
    bands = _router_bands(radios)
    streams = max(
        (radio["streams"] for radio in radios if radio["streams"]),
        default=None,
    )
    features: list[str] = []
    present = set()
    for radio in radios:
        present |= radio["features"]
    for _key, label in _ROUTER_FEATURES:
        if label in present:
            features.append(label)
    own_band = _band_name(getattr(ap, "channel", None))
    other_band = any(
        _band_name(radio["channel"]) not in {"", own_band}
        for radio in radios
    )
    catalog = _catalog_from_radios(radios, own)
    return {
        "show": bool(facts) or other_band or bool(catalog["sentence"]),
        "facts": facts,
        "band_lines": [item["line"] for item in bands],
        "band_phrase": _join_and([item["phrase"] for item in bands]),
        "streams": streams,
        "features": features,
        "catalog": catalog,
        "borrowed": _borrowed_sentence(radios, own),
    }


def _router_lines(profile: dict) -> list[str]:
    if not profile["show"]:
        return []
    lines = []
    for label, value, source in profile["facts"]:
        lines.append(f"{label}: {value}" + (f" · {source}" if source else ""))
    lines.extend(profile["band_lines"])
    if profile["streams"]:
        lines.append(f"Spatial streams: {profile['streams']}")
    if profile["features"]:
        lines.append("Features: " + ", ".join(profile["features"]))
    return lines


def _router_sentence(profile: dict, own_bssid: str) -> tuple[str, str]:
    del own_bssid
    if not profile["show"]:
        return "", ""
    facts = profile["facts"]
    by_label = {label: (value, source) for label, value, source in facts}
    parts: list[str] = []
    manufacturer, _source = by_label.get("Manufacturer", ("", ""))
    model, _source = by_label.get("Model", ("", ""))
    title = " ".join(part for part in (manufacturer, model) if part)
    if title:
        parts.append(title)
    number, _source = by_label.get("Model number", ("", ""))
    if number and number.casefold() != model.casefold():
        parts.append(f"model number {number}")
    serial, _source = by_label.get("Serial", ("", ""))
    if serial:
        parts.append(f"serial {serial}")
    version, _source = by_label.get("WPS version", ("", ""))
    if version:
        parts.append(f"WPS {version}")
    os_version, _source = by_label.get("OS version", ("", ""))
    if os_version:
        parts.append(f"OS {os_version}")
    sentence = ""
    if parts:
        sentence = "The router is " + ", ".join(parts) + "."
        sources = []
        for _label, _value, source in facts:
            if source and source not in sources:
                sources.append(source)
        if len(sources) == 1:
            sentence += f" That comes from {sources[0]}."
        elif sources:
            sentence += " Those values come from " + _join_and(sources) + "."
    band_sentence = ""
    if profile["band_phrase"]:
        band_sentence = f"This Router-AP advertises {profile['band_phrase']}"
        if profile["streams"]:
            band_sentence += f", with {profile['streams']} spatial streams"
        band_sentence += "."
    return sentence, band_sentence


def _router_facts(radios: list[dict], own_bssid: str) -> list[tuple[str, str, str]]:
    chosen: dict[str, tuple[str, str]] = {}
    for radio in radios:
        source = ""
        if radio["bssid"].casefold() != own_bssid.casefold():
            source = _radio_source(radio)
        for key, label in _ROUTER_FIELDS:
            if key in chosen or not radio.get(key):
                continue
            if key == "device_name" and radio[key].casefold() == radio.get("model", "").casefold():
                continue
            chosen[key] = (radio[key], source)
    return [
        (label, chosen[key][0], chosen[key][1])
        for key, label in _ROUTER_FIELDS
        if key in chosen
    ]


def _router_bands(radios: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, int], dict] = {}
    for radio in radios:
        band = _band_name(radio.get("channel"))
        if not band:
            continue
        try:
            channel = int(radio["channel"])
        except (TypeError, ValueError):
            continue
        bucket = grouped.setdefault((band, channel), {"phy": set(), "widths": set()})
        bucket["phy"] |= radio["phy"]
        bucket["widths"] |= radio["widths"]
    rows = []
    for (band, channel), bucket in sorted(
        grouped.items(),
        key=lambda item: (0 if item[0][0] == "2.4 GHz" else 1, item[0][1]),
    ):
        extras = []
        if bucket["widths"]:
            extras.append("/".join(str(item) for item in sorted(bucket["widths"])) + " MHz")
        if bucket["phy"]:
            extras.append(", ".join(_sorted_phy(bucket["phy"])))
        suffix = f" ({', '.join(extras)})" if extras else ""
        phrase = f"{band} on channel {channel}{suffix}"
        rows.append({"line": phrase, "phrase": phrase})
    return rows


def _radio_snapshot(live, stored: dict | None, fallback: dict | None) -> dict:
    stored = stored or {}
    fallback = fallback or {}
    radio = _radio_from_stored(stored, fallback)
    if live is not None:
        _fill_radio(radio, _radio_from_live(live))
    if not radio["ssid"]:
        radio["ssid"] = _present(fallback.get("ssid") if fallback else "")
    if radio["channel"] is None and fallback:
        radio["channel"] = fallback.get("channel")
    if not radio["bssid"]:
        radio["bssid"] = str(
            getattr(live, "bssid", "") or stored.get("bssid") or fallback.get("bssid") or ""
        )
    if not radio["catalog_class"] and not radio["catalog_label"]:
        reading = _reading_from_name(radio.get("ssid"), radio["bssid"])
        if reading:
            radio["catalog_class"], radio["catalog_label"], notes = reading
            if notes and not radio["catalog_notes"]:
                radio["catalog_notes"] = notes
    return radio


def _fill_radio(base: dict, newer: dict) -> None:
    """Prefer the live beacon, and keep a stored value only where the beacon is empty."""
    for key in (
        "ssid", "bssid", "manufacturer", "model", "model_number",
        "device_name", "serial", "wps_version", "os_version",
        "catalog_class", "catalog_label", "catalog_notes",
    ):
        if newer.get(key):
            base[key] = newer[key]
    if newer.get("wps_locked"):
        base["wps_locked"] = True
    if newer.get("channel") is not None:
        base["channel"] = newer["channel"]
    base["phy"] |= newer["phy"]
    base["widths"] |= newer["widths"]
    base["features"] |= newer["features"]
    if newer.get("streams"):
        base["streams"] = max(base["streams"] or 0, newer["streams"])


def _radio_from_live(ap) -> dict:
    identity = getattr(ap, "identity", None)
    caps = getattr(ap, "capabilities", None)
    manufacturer = ""
    if identity is not None:
        source = getattr(identity, "manufacturer_source", None)
        if getattr(source, "name", "") != "OUI":
            manufacturer = _present(getattr(identity, "manufacturer", None))
    radio = _blank_radio()
    radio.update({
        "ssid": _present(getattr(ap, "ssid", None)),
        "bssid": str(getattr(ap, "bssid", "") or ""),
        "channel": getattr(ap, "channel", None),
        "manufacturer": manufacturer,
        "model": _present(getattr(identity, "model_name", None) if identity else None),
        "model_number": _present(getattr(identity, "model_number", None) if identity else None),
        "device_name": _present(getattr(identity, "device_name", None) if identity else None),
        "serial": _real_serial(getattr(identity, "serial_number", None) if identity else None),
        "wps_version": _present(getattr(ap, "wps_version", None)),
        "os_version": _format_os(getattr(ap, "wps_os_version", None)),
        "wps_locked": bool(getattr(ap, "wps_locked", False)),
    })
    reading = _reading_from_caps(caps)
    if reading:
        radio["catalog_class"], radio["catalog_label"] = reading
    _copy_catalog_notes(radio, caps)
    if caps is not None:
        if not radio["manufacturer"]:
            radio["manufacturer"] = _present(getattr(caps, "wps_manufacturer", None))
        if not radio["model"]:
            radio["model"] = _present(getattr(caps, "wps_model", None))
        if not radio["device_name"]:
            radio["device_name"] = _present(getattr(caps, "wps_device_name", None))
        radio["phy"] = _text_set(getattr(caps, "phy_modes", ()))
        radio["widths"] = _width_set(getattr(caps, "channel_widths_mhz", ()))
        radio["streams"] = _positive(getattr(caps, "max_spatial_streams", None))
        radio["features"] = _feature_set(caps)
    return radio


def _radio_from_stored(record: dict, fallback: dict) -> dict:
    identity = _identity_map(record.get("identity"))
    caps = record.get("capabilities") if isinstance(record.get("capabilities"), dict) else {}
    wps = record.get("wps") if isinstance(record.get("wps"), dict) else {}
    radio = _blank_radio()
    radio.update({
        "ssid": _present(record.get("ssid") or fallback.get("ssid")),
        "bssid": str(record.get("bssid") or fallback.get("bssid") or ""),
        "channel": record.get("channel", fallback.get("channel")),
        "manufacturer": identity.get("MANUFACTURER") or _present(caps.get("wps_manufacturer")),
        "model": identity.get("MODEL_NAME") or _present(caps.get("wps_model")),
        "model_number": identity.get("MODEL_NUMBER", ""),
        "device_name": identity.get("DEVICE_NAME") or _present(caps.get("wps_device_name")),
        "serial": _real_serial(identity.get("SERIAL_NUMBER")),
        "wps_version": _present(wps.get("version")),
        "os_version": _format_os(wps.get("os_version")),
        "wps_locked": bool(wps.get("locked")),
        "phy": _text_set(caps.get("phy_modes")),
        "widths": _width_set(caps.get("channel_widths_mhz")),
        "streams": _positive(caps.get("max_spatial_streams")),
        "features": _feature_set(caps),
    })
    _copy_catalog(radio, caps)
    return radio


def _blank_radio() -> dict:
    return {
        "ssid": "",
        "bssid": "",
        "channel": None,
        "manufacturer": "",
        "model": "",
        "model_number": "",
        "device_name": "",
        "serial": "",
        "wps_version": "",
        "os_version": "",
        "catalog_class": "",
        "catalog_label": "",
        "catalog_notes": "",
        "wps_locked": False,
        "phy": set(),
        "widths": set(),
        "streams": None,
        "features": set(),
    }


def _identity_map(rows) -> dict[str, str]:
    best: dict[str, tuple[int, str]] = {}
    for item in rows or []:
        field = str(item.get("field") or "")
        source = str(item.get("source") or "")
        value = _present(item.get("value"))
        if not field or not value or (field == "MANUFACTURER" and source == "OUI"):
            continue
        rank = _SOURCE_RANK.get(source, 9)
        current = best.get(field)
        if current is None or rank < current[0]:
            best[field] = (rank, value)
    return {field: value for field, (_rank, value) in best.items()}


def _radio_source(radio: dict) -> str:
    name = radio.get("ssid") or radio.get("bssid") or "a related radio"
    bssid = radio.get("bssid") or ""
    if bssid and name != bssid:
        return f"{name} ({bssid})"
    return str(name)


def _feature_set(caps) -> set[str]:
    found = set()
    for key, label in _ROUTER_FEATURES:
        value = caps.get(key) if isinstance(caps, dict) else getattr(caps, key, False)
        if value:
            found.add(label)
    return found


def _text_set(value) -> set[str]:
    if not isinstance(value, (set, list, tuple)):
        return set()
    return {str(item) for item in value if item}


def _width_set(value) -> set[int]:
    found: set[int] = set()
    if not isinstance(value, (set, list, tuple)):
        return found
    for item in value:
        try:
            found.add(int(item))
        except (TypeError, ValueError):
            continue
    return found


def _positive(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _sorted_phy(modes: set[str]) -> list[str]:
    return sorted(modes, key=lambda item: (_PHY_RANK.get(item, 50), item))


def _format_os(value) -> str:
    if value is None or value == "":
        return ""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return _present(value)
    if number in {0, 0x80000000}:
        return ""
    body = number & 0x7FFFFFFF
    major = (body >> 24) & 0x7F
    minor = (body >> 16) & 0xFF
    build = body & 0xFFFF
    if major or minor:
        text = f"{major}.{minor}"
        if build:
            text += f".{build}"
        return text
    return f"0x{number:08X}"


def _present(value) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).split())
    if text.casefold() in _EMPTY_FACT:
        return ""
    return text


def _join_and(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + ", and " + items[-1]


def _live_ap(array, bssid: str):
    points = getattr(array, "access_points", {}) if array is not None else {}
    if not isinstance(points, dict):
        return None
    found = points.get(bssid)
    if found is not None:
        return found
    folded = bssid.casefold()
    for key, value in points.items():
        if str(key).casefold() == folded or str(getattr(value, "bssid", "")).casefold() == folded:
            return value
    return None


def _already_named(bssid: str, family: list[dict], twins) -> bool:
    folded = bssid.casefold()
    if any(twin.bssid.casefold() == folded for twin in twins):
        return True
    return any(str(record.get("bssid") or "").casefold() == folded for record in family)


def _real_serial(value) -> str:
    """A WPS serial of 1234, or any other placeholder, is not the router serial."""
    return _usable_serial(value)


def report_markdown(report: InvestigateReport) -> str:
    """The investigation as a Markdown document."""
    lines = [f"# {report.title}", "", report.conclusion, ""]
    for section in report.sections:
        lines.extend(["", f"## {section.title}", ""])
        lines.extend(f"- {line}" for line in section.lines)
    return "\n".join(lines).rstrip() + "\n"


def save_investigation_markdown(report: InvestigateReport, directory: Path | str) -> Path:
    """Write the report under ``directory`` and return the file path."""
    dest = Path(directory)
    dest.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", report.title.casefold()).strip("-") or "investigate"
    path = dest / f"{slug[:80]}-{time.strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(report_markdown(report), encoding="utf-8")
    return path


def _vendor_lines(mac, vendor, universal, local) -> list[str]:
    lines = [mac]
    if local:
        lines.append("Locally administered: this is not the address printed on the label.")
        if universal:
            lines.append(f"Universal prefix: {universal}")
    else:
        lines.append("Universally administered, assigned by the manufacturer.")
    lines.append(f"Vendor: {vendor or 'unknown'}")
    return lines


def _radio_lines(ap, caps) -> list[str]:
    lines = [f"Channel {getattr(ap, 'channel', '?')}"]
    width = _width(ap)
    if width:
        lines.append(f"Operating width: {width} MHz")
    if caps is not None and caps.channel_widths_mhz:
        widths = "/".join(str(item) for item in sorted(caps.channel_widths_mhz))
        lines.append(f"Advertised widths: {widths} MHz")
    if caps is not None and caps.phy_modes:
        lines.append("PHY: " + "/".join(sorted(caps.phy_modes)))
    if caps is not None and caps.max_spatial_streams:
        lines.append(f"Spatial streams: {caps.max_spatial_streams}")
    country = getattr(ap, "country_code", None)
    if country:
        lines.append(f"Beacon country: {country}")
    uptime = _uptime(getattr(ap, "uptime_us", None))
    if uptime:
        lines.append(f"Uptime: {uptime}")
    cards = getattr(ap, "signal_by_card", None) or {}
    if cards:
        heard = ", ".join(
            f"{name} {rssi} dBm" for name, rssi in sorted(cards.items(), key=lambda item: -item[1])
        )
        lines.append(f"Heard by: {heard}")
    return lines


def _config_lines(ap, caps) -> list[str]:
    lines = [f"Encryption: {getattr(ap, 'encryption', None) or 'unknown'}"]
    akms = getattr(ap, "akms", None) or []
    if akms:
        lines.append("AKM: " + ", ".join(str(item) for item in akms))
    pairwise = getattr(ap, "pairwise_ciphers", None) or []
    if not pairwise and getattr(ap, "pairwise_cipher", None):
        pairwise = [ap.pairwise_cipher]
    if pairwise:
        lines.append("Pairwise: " + ", ".join(pairwise))
    if getattr(ap, "group_cipher", None):
        lines.append(f"Group cipher: {ap.group_cipher}")
    if getattr(ap, "pmf_required", False):
        lines.append("PMF required")
    elif getattr(ap, "pmf_capable", False):
        lines.append("PMF capable")
    if getattr(ap, "wps", False):
        lines.append("WPS advertised")
    identity = getattr(ap, "identity", None)
    summary = getattr(identity, "summary", "") if identity is not None else ""
    if summary:
        lines.append(f"Identity: {summary}")
    if caps is not None and caps.catalog_sentence:
        lines.append(caps.catalog_sentence)
    elif caps is not None and caps.catalog_family_id:
        lines.append(f"Catalog: {caps.catalog_family_id}")
    return lines


def _ap_history_lines(ap, dossier: dict) -> list[str]:
    lines = [
        f"This session: {_when(getattr(ap, 'first_seen', None))} → "
        f"{_when(getattr(ap, 'last_seen', None))}"
    ]
    if dossier.get("first_seen"):
        lines.append(
            f"Database: {_when(dossier.get('first_seen'))} → "
            f"{_when(dossier.get('last_seen'))}"
        )
        if dossier.get("ssid") and dossier.get("ssid") != getattr(ap, "ssid", None):
            lines.append(f"Stored SSID: {dossier.get('ssid')}")
    sessions = list(dossier.get("sessions") or [])
    if sessions:
        lines.append(f"Scan sessions: {len(sessions)}")
        for session in sessions[:_LIST_LIMIT]:
            name = session.get("name") or "unnamed"
            lines.append(
                f"  {name} · {_when(session.get('first_seen'))} → "
                f"{_when(session.get('last_seen'))}"
            )
    else:
        lines.append("No earlier sessions in the database.")
    for item in list(dossier.get("identity") or [])[:_LIST_LIMIT]:
        lines.append(
            f"  {item.get('field')}: {item.get('value')} ({item.get('source')})"
        )
    return lines


def _relation_lines(ap, twins, predicted, dossier: dict, family: list[dict]) -> list[str]:
    lines: list[str] = []
    for record in family[:_LIST_LIMIT]:
        lines.append(_family_line(record))
    siblings = list(getattr(ap, "siblings", ()) or ())
    if siblings:
        lines.append("Same band: " + ", ".join(siblings[:_LIST_LIMIT]))
    seen = {str(record.get("bssid") or "").casefold() for record in family}
    for twin in twins:
        if twin.bssid.casefold() in seen:
            continue
        lines.append(
            f"Other band, live: {twin.ssid or '(unnamed)'} · "
            f"channel {twin.channel} · {twin.bssid}"
        )
    if predicted and predicted.casefold() not in seen and not any(
        twin.bssid.casefold() == predicted for twin in twins
    ):
        lines.append(f"Other band, predicted: {predicted}")
    for item in list(dossier.get("relationships") or [])[:_LIST_LIMIT]:
        lines.append(
            f"Stored ({item.get('kind')}): {item.get('related_bssid')} · "
            f"{_when(item.get('last_seen'))}"
        )
    return lines or ["No related radio."]


def _same_device(ap, array, history, predicted: str | None) -> tuple[list[dict], list[dict]]:
    """Live and stored BSSIDs of this chassis, plus radios that only share a boot.

    Address distance, a real WPS UUID, a real serial, and the SSID unit code
    (C274, CE28) each join a radio. Uptime within 2 seconds joins only when
    that code does not already belong to a different chassis.
    """
    bssid = str(getattr(ap, "bssid", "") or "")
    found: dict[str, dict] = {}
    for record in _call(history, "chassis_access_points", bssid) or []:
        other = str(record.get("bssid") or "")
        if _same_chassis(bssid, other):
            found[other.casefold()] = record
    if predicted and predicted.casefold() not in found:
        stored = _call(history, "access_point_dossier", predicted)
        if stored and stored.get("bssid"):
            found[predicted.casefold()] = stored
    points = getattr(array, "access_points", {}) if array is not None else {}
    live = [
        other for other in points.values()
        if other.bssid.casefold() != bssid.casefold() and not getattr(other, "is_own_fake", False)
    ]
    anchor_boot = _boot_time(ap)
    anchor_wps = _wps_key(ap)
    anchor_serial = _serial_key(ap)
    known = _unit_codes(getattr(ap, "ssid", None)) | _codes_in(found.values())
    neighbors: list[dict] = []
    uptime_only: list[tuple[object, float]] = []

    for other in live:
        delta = _uptime_delta(anchor_boot, other)
        reasons, shared = _strong_reasons(
            bssid, other, known, anchor_wps, anchor_serial,
        )
        if reasons:
            _remember(found, other, reasons, delta if delta is not None else None)
            known |= _unit_codes(getattr(other, "ssid", None)) | shared
            continue
        if delta is not None:
            uptime_only.append((other, delta))

    for other, delta in uptime_only:
        other_codes = _unit_codes(getattr(other, "ssid", None))
        if known and other_codes and not (known & other_codes):
            neighbors.append({
                "bssid": other.bssid,
                "ssid": other.ssid,
                "channel": other.channel,
                "uptime_delta_s": delta,
                "unit_code": sorted(other_codes)[0],
            })
            continue
        _remember(found, other, ["uptime"], delta)
        known |= other_codes

    for other in live:
        if other.bssid.casefold() in found:
            continue
        shared = known & _unit_codes(getattr(other, "ssid", None))
        if not shared:
            continue
        _remember(found, other, [_name_reason(shared)], _uptime_delta(anchor_boot, other))

    family = sorted(found.values(), key=lambda item: _bit_diff(bssid, str(item.get("bssid") or "")))
    return family, neighbors


def _strong_reasons(bssid, other, known: set[str], anchor_wps: str, anchor_serial: str):
    reasons: list[str] = []
    if _same_chassis(bssid, other.bssid):
        reasons.append("address")
    if anchor_wps and _wps_key(other) == anchor_wps:
        reasons.append("WPS UUID")
    if anchor_serial and _serial_key(other) == anchor_serial:
        reasons.append("serial")
    shared = known & _unit_codes(getattr(other, "ssid", None))
    if shared:
        reasons.append(_name_reason(shared))
    return reasons, shared


def _remember(found: dict, other, reasons: list[str], delta: float | None) -> None:
    key = other.bssid.casefold()
    current = found.get(key, {})
    merged: list[str] = []
    for reason in list(current.get("reasons") or []) + reasons:
        if reason not in merged:
            merged.append(reason)
    found[key] = {
        "bssid": other.bssid,
        "ssid": other.ssid or current.get("ssid"),
        "channel": other.channel,
        "encryption": other.encryption or current.get("encryption"),
        "country_code": getattr(other, "country_code", None) or current.get("country_code"),
        "first_seen": current.get("first_seen"),
        "last_seen": current.get("last_seen") or other.last_seen,
        "uptime_delta_s": delta if delta is not None else current.get("uptime_delta_s"),
        "reasons": merged,
    }


def _name_reason(codes: set[str]) -> str:
    return "name " + sorted(codes)[0].upper()


def _same_chassis(left: str, right: str) -> bool:
    if not left or not right or left.casefold() == right.casefold():
        return False
    if _universal_oui(left) != _universal_oui(right):
        return False
    distance = _bit_diff(left, right)
    return 0 < distance <= 8


def _universal_oui(mac: str) -> str | None:
    parts = _octets(mac)
    if parts is None:
        return None
    parts[0] = f"{int(parts[0], 16) & ~0x02:02x}"
    return ":".join(parts[:3])


def _bit_diff(left: str, right: str) -> int:
    first, second = _octets(left), _octets(right)
    if first is None or second is None:
        return 48
    return sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(first, second))


def _guest_name(ssid: str, family: list[dict], predicted: str | None) -> str:
    if _looks_guest(ssid):
        return ssid
    for record in family:
        name = str(record.get("ssid") or "")
        if not _looks_guest(name):
            continue
        if predicted and str(record.get("bssid") or "").casefold() == predicted.casefold():
            return name
    for record in family:
        name = str(record.get("ssid") or "")
        if _looks_guest(name):
            return name
    return ""


def _copy_catalog(radio: dict, caps) -> None:
    reading = _reading_from_caps(caps)
    if reading:
        radio["catalog_class"], radio["catalog_label"] = reading
    _copy_catalog_notes(radio, caps)


def _copy_catalog_notes(radio: dict, caps) -> None:
    if caps is None:
        return
    notes = caps.get("catalog_notes") if isinstance(caps, dict) else getattr(caps, "catalog_notes", None)
    text = _present(notes)
    if text:
        radio["catalog_notes"] = text


def _catalog_from_radios(radios: list[dict], own_bssid: str) -> dict:
    """This radio's catalog when it has one, otherwise the first related radio that does."""
    ordered = sorted(
        radios,
        key=lambda radio: radio.get("bssid", "").casefold() != own_bssid.casefold(),
    )
    chosen = next(
        (radio for radio in ordered if radio.get("catalog_class") or radio.get("catalog_label")),
        None,
    )
    if chosen is None:
        return {"class": "", "family": "", "notes": "", "sentence": ""}
    catalog_class = str(chosen.get("catalog_class") or "")
    label = str(chosen.get("catalog_label") or "")
    source = ""
    if chosen.get("bssid", "").casefold() != own_bssid.casefold():
        source = _radio_source(chosen)
    return {
        "class": "" if catalog_class == "Ambiguous" else catalog_class,
        "family": label,
        "notes": str(chosen.get("catalog_notes") or ""),
        "sentence": _catalog_sentence(catalog_class, label, source),
    }


def _borrowed_sentence(radios: list[dict], own_bssid: str) -> str:
    """Settings this radio does not advertise, taken from a related radio."""
    own = next(
        (radio for radio in radios if radio.get("bssid", "").casefold() == own_bssid.casefold()),
        None,
    )
    own_features = own["features"] if own else set()
    parts: list[str] = []
    if not (own and own.get("wps_locked")):
        donor = next((radio for radio in radios if radio.get("wps_locked")), None)
        if donor is not None:
            parts.append(f"WPS is locked on {_radio_source(donor)}")
    for _key, label in _ROUTER_FEATURES:
        if label in own_features:
            continue
        donor = next((radio for radio in radios if label in radio["features"]), None)
        if donor is None:
            continue
        parts.append(f"{label} is advertised on {_radio_source(donor)}")
    if not parts:
        return ""
    return "Taken from the related radios: " + "; ".join(parts) + "."


def _catalog_sentence(catalog_class: str, label: str, source: str = "") -> str:
    shown_class = "" if catalog_class == "Ambiguous" else catalog_class
    if shown_class and label:
        sentence = f"The catalog class is {shown_class} and the family is {label}"
    elif shown_class:
        sentence = f"The catalog class is {shown_class}"
    elif label:
        sentence = f"The catalog family is {label}"
    else:
        return ""
    if source:
        sentence += f", taken from {source}"
    sentence += "."
    meaning = _catalog_meaning(shown_class, label)
    if meaning:
        sentence += f" That means this is {meaning}."
    return sentence


def _catalog_meaning(catalog_class: str, label: str) -> str:
    if catalog_class == "Home router":
        if label:
            return f"a router from the telephone company {label}"
        return "a router from a telephone company"
    if catalog_class == "Vehicle":
        return f"a {label} vehicle" if label else "a vehicle"
    kind = {
        "Surveillance": "a surveillance device",
        "Camera": "a camera",
        "Cameras": "a camera",
        "Alarm": "an alarm",
        "Phone": "a phone",
        "Tablet": "a tablet",
        "Computer": "a computer",
        "Display": "a display",
        "Wearable": "a wearable",
        "Audio": "an audio device",
        "Drone": "a drone",
        "Printer": "a printer",
        "Finder": "a tracker",
        "Sensor": "a sensor",
        "IoT": "an IoT device",
        "Hospitality": "a hospitality network",
        "Public safety": "a public-safety radio",
        "Network": "network equipment",
        "Fitness": "a fitness device",
        "Glasses": "glasses",
        "Health": "a health device",
        "Lock": "a lock",
        "Smart home": "a smart-home device",
        "Beacon": "a beacon",
        "Cleaning device": "a cleaning device",
        "Pentest": "a pentest radio",
        "Peripherals": "a peripheral",
    }.get(catalog_class, "")
    if kind and label:
        return f"{kind} ({label})"
    return kind


def _reading_from_caps(caps) -> tuple[str, str] | None:
    if caps is None:
        return None
    if isinstance(caps, dict):
        catalog_class = str(caps.get("catalog_class") or "")
        labels = caps.get("catalog_labels") or ()
        family_id = str(caps.get("catalog_family_id") or "")
    else:
        catalog_class = str(getattr(caps, "catalog_class", "") or "")
        labels = getattr(caps, "catalog_labels", ()) or ()
        family_id = str(getattr(caps, "catalog_family_id", "") or "")
    label = ""
    if isinstance(labels, str):
        label = labels.strip()
    elif labels:
        label = str(next(iter(labels), "") or "").strip()
    if family_id and (not catalog_class or not label):
        try:
            from wifit3.observe.product_catalog import catalog_hit_for_family_id

            hit = catalog_hit_for_family_id(family_id)
        except Exception:
            hit = None
        if hit is not None and getattr(hit, "present", False):
            catalog_class = catalog_class or str(hit.catalog_class or "")
            if not label and hit.labels:
                label = str(hit.labels[0])
    if not catalog_class and not label:
        return None
    return catalog_class, label


def _reading_from_name(ssid, bssid: str) -> tuple[str, str, str] | None:
    name = str(ssid or "")
    if not name or name == "(unnamed)":
        return None
    try:
        hit = wifi_catalog_hit(name, bssid or "", set())
    except Exception:
        return None
    if not getattr(hit, "present", False):
        return None
    labels = getattr(hit, "labels", ()) or ()
    label = str(labels[0]) if labels else ""
    catalog_class = str(getattr(hit, "catalog_class", "") or "")
    if not catalog_class and not label:
        return None
    return catalog_class, label, _present(getattr(hit, "notes", ""))


def _looks_guest(ssid: str) -> bool:
    return bool(ssid) and "guest" in ssid.casefold()


def _named_family(family: list[dict], predicted: str | None, twins) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for twin in twins:
        seen.add(twin.bssid.casefold())
        parts.append(
            f"{twin.ssid or twin.bssid} on {twin.bssid} "
            f"(channel {twin.channel}, in this scan)"
        )
    for record in family:
        bssid = str(record.get("bssid") or "")
        if bssid.casefold() in seen:
            continue
        if predicted and bssid.casefold() == predicted.casefold():
            seen.add(bssid.casefold())
            name = record.get("ssid") or bssid
            parts.append(
                f"{name} on {bssid} (channel {record.get('channel')}, "
                f"{record.get('encryption') or 'unknown encryption'}, stored)"
            )
    if not parts:
        return ""
    return "The same device is already stored: " + "; ".join(parts[:3]) + "."


def _main_ssids(family: list[dict]) -> list[str]:
    lines: list[str] = []
    for record in family:
        bssid = str(record.get("bssid") or "")
        if is_locally_administered_mac(bssid):
            continue
        name = str(record.get("ssid") or "")
        if not name:
            continue
        lines.append(f"{name} ({bssid}, channel {record.get('channel')})")
    return lines


def _label_bssid(family: list[dict]) -> str:
    universal = [
        record for record in family
        if record.get("bssid") and not is_locally_administered_mac(str(record["bssid"]))
    ]
    if not universal:
        return ""
    on_24 = [record for record in universal if _band_name(record.get("channel")) == "2.4 GHz"]
    chosen = on_24[0] if on_24 else universal[0]
    return str(chosen.get("bssid") or "")


def _family_line(record: dict) -> str:
    name = record.get("ssid") or "(unnamed)"
    band = _band_name(record.get("channel")) or "unknown band"
    line = (
        f"{name} · {record.get('bssid')} · {band} · channel {record.get('channel')} · "
        f"{record.get('encryption') or 'unknown encryption'}"
    )
    delta = record.get("uptime_delta_s")
    if delta is not None:
        line += f" · uptime Δ {delta:.1f} s"
    reasons = [reason for reason in (record.get("reasons") or []) if reason != "uptime"]
    if reasons:
        line += " · " + ", ".join(reasons)
    return line


def _boot_time(ap) -> float | None:
    """Wall-clock boot estimate: when the beacon was heard, minus its uptime."""
    uptime = getattr(ap, "uptime_us", None)
    seen = getattr(ap, "last_seen", None)
    if uptime is None or seen is None:
        return None
    try:
        return float(seen) - float(uptime) / 1_000_000
    except (TypeError, ValueError):
        return None


def _uptime_delta(anchor: float | None, other) -> float | None:
    if anchor is None:
        return None
    other_boot = _boot_time(other)
    if other_boot is None:
        return None
    delta = abs(anchor - other_boot)
    if delta > _UPTIME_MATCH_S:
        return None
    return delta


def _unit_codes(ssid: str | None) -> set[str]:
    """Chassis tokens such as C274. Shared product words and guestN are ignored."""
    if not ssid or ssid in {"(unnamed)", "<hidden>"}:
        return set()
    found: set[str] = set()
    for token in re.findall(r"[A-Za-z0-9]+", ssid):
        folded = token.casefold()
        if folded in _GENERIC_SSID_WORDS or folded.startswith("guest"):
            continue
        if _UNIT_CODE.fullmatch(folded):
            found.add(folded)
    return found


def _codes_in(records) -> set[str]:
    found: set[str] = set()
    for record in records:
        found |= _unit_codes(str(record.get("ssid") or ""))
    return found


_UUID_PLACEHOLDERS = frozenset({
    "0" * 32,
    "f" * 32,
    "00112233445566778899aabbccddeeff",
    "0123456789abcdef0123456789abcdef",
})
_SERIAL_PLACEHOLDERS = frozenset({
    "1234", "12345", "123456", "12345678", "00000000",
    "default", "n/a", "na", "none", "null", "serial", "unknown",
})


def _usable_uuid(value) -> str:
    if not value:
        return ""
    canonical = str(value).strip().casefold().replace("-", "").replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{32}", canonical) or canonical in _UUID_PLACEHOLDERS:
        return ""
    return canonical


def _usable_serial(value) -> str:
    text = _present(value)
    if not text:
        return ""
    compact = re.sub(r"[^0-9a-z]", "", text.casefold())
    if (
        len(compact) < 6
        or text.casefold() in _SERIAL_PLACEHOLDERS
        or len(set(compact)) <= 1
    ):
        return ""
    return text


def _wps_key(ap) -> str:
    return _usable_uuid(getattr(ap, "wps_uuid_e", None))


def _serial_key(ap) -> str:
    identity = getattr(ap, "identity", None)
    serial = getattr(identity, "serial_number", None) if identity is not None else None
    return _usable_serial(serial)


def _identity_sentence(family: list[dict]) -> str:
    parts: list[str] = []
    for record in family:
        reasons = [
            reason for reason in (record.get("reasons") or [])
            if reason not in {"uptime", "address"}
        ]
        if not reasons:
            continue
        if record.get("uptime_delta_s") is not None and all(
            reason.startswith("name ") for reason in reasons
        ):
            continue
        name = record.get("ssid") or record.get("bssid")
        parts.append(f"{name} ({', '.join(reasons)})")
    if not parts:
        return ""
    return (
        "The same router is also confirmed by "
        + "; ".join(parts[:_LIST_LIMIT]) + "."
    )


def _neighbor_sentence(neighbors: list[dict]) -> str:
    if not neighbors:
        return ""
    parts: list[str] = []
    for record in neighbors[:4]:
        name = record.get("ssid") or record.get("bssid")
        code = str(record.get("unit_code") or "")
        gap = f"{float(record['uptime_delta_s']):.1f} s"
        if code:
            parts.append(f"{name} ({gap}, name code {code.upper()})")
        else:
            parts.append(f"{name} ({gap})")
    return (
        "These radios booted within 2 seconds, but the name code belongs to a different Router-AP: "
        + "; ".join(parts) + "."
    )


def _uptime_sentence(family: list[dict]) -> str:
    matched = [record for record in family if record.get("uptime_delta_s") is not None]
    if not matched:
        return ""
    parts = []
    for record in matched[:_LIST_LIMIT]:
        name = record.get("ssid") or record.get("bssid")
        parts.append(
            f"{name} ({record.get('bssid')}, {float(record['uptime_delta_s']):.1f} s)"
        )
    return (
        "These live radios booted within 2 seconds of this one, so they are the same router: "
        + "; ".join(parts) + "."
    )


def _band_name(channel) -> str:
    try:
        number = int(channel)
    except (TypeError, ValueError):
        return ""
    if number <= 0:
        return ""
    return "2.4 GHz" if number <= 14 else "5 GHz"


def _home_block(channel, width: int | None) -> str:
    try:
        number = int(channel)
    except (TypeError, ValueError):
        return ""
    if width != 80 or not 36 <= number <= 48:
        return ""
    return "36–48"


def _client_lines(live_clients, stored_clients) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for client in live_clients:
        mac = client.mac.casefold()
        seen.add(mac)
        vendor = vendor_for_mac(client.mac) or "no OUI"
        lines.append(f"Live: {client.mac} · {vendor} · {_when(client.last_seen)}")
    for item in stored_clients:
        mac = str(item.get("client_mac") or "")
        if mac.casefold() in seen:
            continue
        vendor = vendor_for_mac(mac) or "no OUI"
        lines.append(
            f"History: {mac} · {vendor} · {_when(item.get('first_seen'))} → "
            f"{_when(item.get('last_seen'))}"
        )
        if len(lines) >= _LIST_LIMIT:
            break
    return lines or ["No associated stations."]


def _current_ap_lines(client, ap) -> list[str]:
    if ap is None:
        bssid = getattr(client, "bssid", None)
        return [f"Current BSSID: {bssid}"] if bssid else ["No associated access point."]
    lines = [
        f"{ap.ssid or '(unnamed)'}",
        f"{ap.bssid} · channel {ap.channel} · {ap.encryption or 'unknown encryption'}",
    ]
    vendor, universal, local = _mac_vendor(ap.bssid)
    if vendor:
        lines.append(
            f"AP vendor: {vendor}"
            + (f" ({universal})" if local and universal else "")
        )
    return lines


def _probe_lines(client) -> list[str]:
    names = sorted(getattr(client, "probed_ssids", ()) or ())
    if not names:
        return ["No SSID probes in this session."]
    lines = []
    observations = getattr(client, "probe_observations", {}) or {}
    for name in names[:_LIST_LIMIT]:
        observation = observations.get(name)
        if observation is None:
            lines.append(name)
            continue
        lines.append(
            f"{name} · channel {observation.channel} · {observation.count} · "
            f"{_when(observation.last_seen)}"
        )
    extra = len(names) - _LIST_LIMIT
    if extra > 0:
        lines.append(f"and {extra} more")
    return lines


def _association_lines(associations) -> list[str]:
    if not associations:
        return ["No associations in the database."]
    lines = []
    for item in associations[:_LIST_LIMIT]:
        name = item.get("ssid") or "(unnamed)"
        channel = item.get("channel")
        channel_text = f"channel {channel}" if channel else "channel ?"
        lines.append(
            f"{name} · {item.get('bssid')} · {channel_text} · "
            f"{item.get('encryption') or '?'} · {_when(item.get('last_seen'))}"
        )
    return lines


def _client_date_lines(client, dossier: dict) -> list[str]:
    lines = [
        f"This session: {_when(getattr(client, 'first_seen', None))} → "
        f"{_when(getattr(client, 'last_seen', None))}"
    ]
    sessions = list(dossier.get("sessions") or [])
    if sessions:
        lines.append(f"Sessions: {len(sessions)}")
        for session in sessions[:_LIST_LIMIT]:
            lines.append(
                f"  {session.get('name') or 'unnamed'} · {session.get('bssid')} · "
                f"{_when(session.get('last_seen'))}"
            )
    return lines


def _mac_vendor(mac: str) -> tuple[str | None, str | None, bool]:
    local = is_locally_administered_mac(mac)
    universal = universal_mac(mac) if local else None
    vendor = vendor_for_mac(universal or mac)
    return vendor, universal, local


def _live_clients(array, bssid: str) -> list:
    if array is None or not bssid:
        return []
    clients = getattr(array, "clients", {}) or {}
    forged = {item.casefold() for item in (getattr(array, "forged_macs", ()) or ())}
    matched = []
    for client in clients.values():
        if (client.bssid or "").casefold() != bssid.casefold():
            continue
        if client.mac.casefold() in forged or getattr(client, "is_fake", False):
            continue
        matched.append(client)
    return sorted(matched, key=lambda item: item.last_seen, reverse=True)


def _associated_ap(client, array):
    bssid = getattr(client, "bssid", None)
    if not bssid or array is None:
        return None
    points = getattr(array, "access_points", {}) or {}
    return points.get(bssid) or points.get(bssid.casefold())


def _card_sentence(ap) -> str:
    cards = getattr(ap, "signal_by_card", None) or {}
    if not cards:
        return ""
    name, rssi = max(cards.items(), key=lambda item: item[1])
    noun = "card" if len(cards) == 1 else "cards"
    return f"Heard by {len(cards)} {noun}; the strongest is {name} at {rssi} dBm."


def _width(ap) -> int | None:
    caps = getattr(ap, "capabilities", None)
    if caps is None:
        return None
    return getattr(caps, "operating_width_mhz", None)


def _uptime(microseconds: int | None) -> str | None:
    if microseconds is None or microseconds < 0:
        return None
    seconds = int(microseconds / 1_000_000)
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min"


def _when(value: Any) -> str:
    if value is None:
        return "-"
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp))


def _octets(mac: str) -> list[str] | None:
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) != 6:
        return None
    try:
        if any(len(part) != 2 or int(part, 16) > 255 for part in parts):
            return None
    except ValueError:
        return None
    return parts


def _call(target, name: str, *args):
    method = getattr(target, name, None)
    if not callable(method):
        return None
    try:
        return method(*args)
    except Exception:
        return None
