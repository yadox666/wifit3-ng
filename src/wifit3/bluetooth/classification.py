from __future__ import annotations

from wifit3.models import BluetoothDevice


_SERVICE_CATEGORIES = {
    "1812": "Input",
    "180d": "Health",
    "1814": "Health",
    "1816": "Health",
    "1818": "Health",
    "1843": "Audio",
    "1844": "Audio",
    "184e": "Audio",
    "1853": "Audio",
}

_NAME_CATEGORIES = (
    (("airpods", "earbuds", "headphone", "headset", "speaker"), "Audio"),
    (("watch", "fitbit", "wristband", "smart band"), "Wearable"),
    (("keyboard", "mouse", "trackpad", "gamepad", "controller"), "Input"),
    (("beacon", "ibeacon", "eddystone"), "Beacon"),
    (("heart", "fitness", "scale", "thermometer", "glucose"), "Health"),
    (("iphone", "galaxy", "pixel", "phone"), "Phone"),
    (("macbook", "laptop", "notebook", "desktop", "computer"), "Computer"),
)

_CLASSIC_MAJOR_CATEGORIES = {
    0x01: "Computer",
    0x02: "Phone",
    0x04: "Audio",
    0x05: "Input",
    0x07: "Wearable",
    0x09: "Health",
}


def _uuid16(uuid: str) -> str:
    lowered = uuid.lower()
    if len(lowered) == 4:
        return lowered
    suffix = "-0000-1000-8000-00805f9b34fb"
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return ""


def device_category(device: BluetoothDevice) -> str:
    """Infer a broad device category from advertised names and standard services."""
    name = device.name.casefold()
    for tokens, category in _NAME_CATEGORIES:
        if any(token in name for token in tokens):
            return category
    services = set(device.service_uuids) | set(device.service_data_uuids)
    for uuid in services:
        category = _SERVICE_CATEGORIES.get(_uuid16(uuid))
        if category:
            return category
    if device.class_of_device is not None:
        classic_category = _CLASSIC_MAJOR_CATEGORIES.get(
            (device.class_of_device >> 8) & 0x1F
        )
        if classic_category:
            return classic_category
    return "Other" if device.name != "<Unknown>" else "Unknown"
