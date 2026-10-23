"""Scanner-facing identity strings (CPE model + firmware beside chipset WPS IDs)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from wifit3.id import vendor_for_mac
from wifit3.models.identity import ApIdentity, IdKey, IdSource, clean_text, is_silicon_odm

if TYPE_CHECKING:
    from wifit3.models import AccessPoint


def format_wps_os_version(value: int | None) -> str:
    """Decode WSC OS Version (major.minor.build) for display."""
    if value is None:
        return ""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return ""
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


def _chipset_line(identity: ApIdentity) -> str:
    """WSC chipset identity (e.g. Quantenna Topaz) even when OUI overrides the OEM manufacturer."""
    for source in (IdSource.WSC_M1, IdSource.WSC_BEACON):
        mfr = identity.get_source_value(IdKey.MANUFACTURER, source)
        if not is_silicon_odm(mfr):
            continue
        model = (
            identity.get_source_value(IdKey.MODEL_NAME, source)
            or identity.get_source_value(IdKey.MODEL_NUMBER, source)
        )
        model = clean_text(model)
        if not model or model.casefold() == (mfr or "").casefold():
            return mfr or ""
        return f"{mfr} {model}"
    return ""


def _cpe_hardware_label(ap: AccessPoint) -> str | None:
    """Router/CPE product name or model number, not the radio chipset marketing name."""
    identity = ap.identity
    chip_model = (identity.model or "").casefold()
    skip = {
        chip_model,
        (identity.manufacturer or "").casefold(),
        (identity.model_name or "").casefold(),
    }
    for key in (IdKey.DEVICE_NAME, IdKey.MODEL_NUMBER, IdKey.MODEL_NAME):
        value, _ = identity.get(key)
        cleaned = clean_text(value)
        if not cleaned:
            continue
        lowered = cleaned.casefold()
        if lowered in skip or lowered == chip_model:
            continue
        if is_silicon_odm(cleaned):
            continue
        if lowered in {"topaz"} and is_silicon_odm(identity.manufacturer):
            continue
        return cleaned
    caps = ap.capabilities
    for raw in (caps.wps_device_name, caps.wps_model):
        cleaned = clean_text(raw)
        if not cleaned:
            continue
        lowered = cleaned.casefold()
        if lowered in skip or is_silicon_odm(cleaned):
            continue
        return cleaned
    oui = vendor_for_mac(ap.bssid)
    if oui and is_silicon_odm(identity.get(IdKey.MANUFACTURER)[0]):
        if not is_silicon_odm(oui) and oui.casefold() not in skip:
            return oui
    return None


def scanner_identity_summary(ap: AccessPoint) -> str:
    """VENDOR/ID column: CPE hardware, optional chipset line, WPS firmware."""
    identity = ap.identity
    parts: list[str] = []

    cpe = _cpe_hardware_label(ap)
    chipset = _chipset_line(identity)
    base = identity.summary

    if cpe:
        parts.append(cpe)
        if chipset and chipset.casefold() not in cpe.casefold():
            parts.append(chipset)
    elif base:
        parts.append(base)

    fw = format_wps_os_version(ap.wps_os_version)
    if fw:
        parts.append(f"fw {fw}")

    return " · ".join(parts)
