from __future__ import annotations

from dataclasses import dataclass

from wifit3.bluetooth.assigned_numbers import manufacturer_label
from wifit3.bluetooth.signatures import SERVICE_CLASSIFICATIONS
from wifit3.models import BluetoothDevice


@dataclass(frozen=True, slots=True)
class DeviceClassification:
    category: str
    detail: str
    source: str
    confidence: str
    ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class _Candidate:
    category: str
    detail: str
    source: str
    confidence: int


_APPEARANCE_CATEGORIES = {
    0x001: ("Phone", "Phone"),
    0x002: ("Computer", "Computer"),
    0x003: ("Watch", "Wearable"),
    0x004: ("Clock", "Other"),
    0x005: ("Display", "Display"),
    0x006: ("Remote Control", "Input"),
    0x007: ("Eye-glasses", "Wearable"),
    0x008: ("Tag", "Beacon"),
    0x009: ("Keyring", "Beacon"),
    0x00A: ("Media Player", "Audio"),
    0x00B: ("Barcode Scanner", "Input"),
    0x00C: ("Thermometer", "Health"),
    0x00D: ("Heart Rate Sensor", "Health"),
    0x00E: ("Blood Pressure", "Health"),
    0x00F: ("Human Interface Device", "Input"),
    0x010: ("Glucose Meter", "Health"),
    0x011: ("Running Walking Sensor", "Health"),
    0x012: ("Cycling Sensor", "Health"),
    0x013: ("Control Device", "Input"),
    0x014: ("Network Device", "Network"),
    0x015: ("Sensor", "Sensor"),
    0x016: ("Light Fixture", "Appliance"),
    0x017: ("Fan", "Appliance"),
    0x018: ("HVAC", "Appliance"),
    0x019: ("Air Conditioning", "Appliance"),
    0x01A: ("Humidifier", "Appliance"),
    0x01B: ("Heating", "Appliance"),
    0x01C: ("Access Control", "Appliance"),
    0x01D: ("Motorized Device", "Appliance"),
    0x01E: ("Power Device", "Appliance"),
    0x01F: ("Light Source", "Appliance"),
    0x020: ("Window Covering", "Appliance"),
    0x021: ("Audio Sink", "Audio"),
    0x022: ("Audio Source", "Audio"),
    0x023: ("Motorized Vehicle", "Vehicle"),
    0x024: ("Domestic Appliance", "Appliance"),
    0x025: ("Wearable Audio Device", "Audio"),
    0x026: ("Aircraft", "Vehicle"),
    0x027: ("AV Equipment", "Audio"),
    0x028: ("Display Equipment", "Display"),
    0x029: ("Hearing Aid", "Health"),
    0x02A: ("Gaming", "Input"),
    0x02B: ("Signage", "Display"),
    0x031: ("Pulse Oximeter", "Health"),
    0x032: ("Weight Scale", "Health"),
    0x033: ("Personal Mobility Device", "Health"),
    0x034: ("Continuous Glucose Monitor", "Health"),
    0x035: ("Insulin Pump", "Health"),
    0x036: ("Medication Delivery", "Health"),
    0x037: ("Spirometer", "Health"),
    0x051: ("Outdoor Sports Activity", "Wearable"),
    0x052: ("Industrial Measurement Device", "Other"),
    0x053: ("Industrial Tool", "Other"),
    0x054: ("Cookware Device", "Appliance"),
}

_APPEARANCE_DETAILS = {
    (0x002, 0x03): "Laptop",
    (0x002, 0x06): "Wearable Computer",
    (0x002, 0x07): "Tablet",
    (0x002, 0x0D): "IoT Gateway",
    (0x003, 0x01): "Sports Watch",
    (0x003, 0x02): "Smartwatch",
    (0x00C, 0x01): "Ear Thermometer",
    (0x00D, 0x01): "Heart Rate Belt",
    (0x00E, 0x01): "Arm Blood Pressure Monitor",
    (0x00E, 0x02): "Wrist Blood Pressure Monitor",
    (0x00F, 0x01): "Keyboard",
    (0x00F, 0x02): "Mouse",
    (0x00F, 0x03): "Joystick",
    (0x00F, 0x04): "Gamepad",
    (0x00F, 0x05): "Digitizer Tablet",
    (0x00F, 0x07): "Digital Pen",
    (0x00F, 0x09): "Touchpad",
    (0x00F, 0x0A): "Presentation Remote",
    (0x014, 0x01): "Access Point",
    (0x014, 0x02): "Mesh Device",
    (0x015, 0x01): "Motion Sensor",
    (0x015, 0x02): "Air Quality Sensor",
    (0x015, 0x03): "Temperature Sensor",
    (0x015, 0x04): "Humidity Sensor",
    (0x015, 0x05): "Leak Sensor",
    (0x015, 0x06): "Smoke Sensor",
    (0x015, 0x07): "Occupancy Sensor",
    (0x015, 0x08): "Contact Sensor",
    (0x015, 0x11): "Proximity Sensor",
    (0x015, 0x12): "Multi-Sensor",
    (0x016, 0x17): "Light Bulb",
    (0x018, 0x01): "Thermostat",
    (0x01C, 0x08): "Door Lock",
    (0x01E, 0x01): "Power Outlet",
    (0x01E, 0x03): "Smart Plug",
    (0x01E, 0x08): "Charging Case",
    (0x01E, 0x09): "Power Bank",
    (0x021, 0x01): "Speaker",
    (0x021, 0x02): "Soundbar",
    (0x021, 0x05): "Speakerphone",
    (0x022, 0x01): "Microphone",
    (0x023, 0x01): "Car",
    (0x023, 0x04): "Motorbike",
    (0x023, 0x05): "Scooter",
    (0x024, 0x01): "Refrigerator",
    (0x024, 0x06): "Washing Machine",
    (0x024, 0x0C): "Vacuum Cleaner",
    (0x024, 0x0D): "Robot Vacuum",
    (0x025, 0x01): "Earbud",
    (0x025, 0x02): "Headset",
    (0x025, 0x03): "Headphones",
    (0x025, 0x04): "Neck Band",
    (0x025, 0x05): "Left Earbud",
    (0x025, 0x06): "Right Earbud",
    (0x028, 0x01): "Television",
    (0x028, 0x02): "Monitor",
    (0x028, 0x03): "Projector",
    (0x029, 0x01): "In-ear Hearing Aid",
    (0x029, 0x02): "Behind-ear Hearing Aid",
    (0x029, 0x03): "Cochlear Implant",
    (0x02A, 0x01): "Game Console",
    (0x02A, 0x02): "Handheld Game Console",
    (0x031, 0x01): "Fingertip Pulse Oximeter",
    (0x031, 0x02): "Wrist Pulse Oximeter",
    (0x035, 0x04): "Patch Insulin Pump",
    (0x035, 0x08): "Insulin Pen",
}

_NAME_TYPES = (
    (("airpods", "earbuds", "earbud"), "Audio", "Earbuds"),
    (("headphones", "headphone"), "Audio", "Headphones"),
    (("headset",), "Audio", "Headset"),
    (("soundbar",), "Audio", "Soundbar"),
    (("speaker",), "Audio", "Speaker"),
    (("watch", "fitbit", "wristband", "smart band"), "Wearable", "Wearable"),
    (("keyboard",), "Input", "Keyboard"),
    (("trackpad", "touchpad"), "Input", "Touchpad"),
    (("gamepad", "joypad"), "Input", "Gamepad"),
    (("mouse",), "Input", "Mouse"),
    (("television", "smart tv", "tv"), "Display", "Television"),
    (("printer",), "Other", "Printer"),
    (("camera",), "Other", "Camera"),
    (("thermostat",), "Appliance", "Thermostat"),
    (("sensor",), "Sensor", "Sensor"),
    (("tracker",), "Beacon", "Tracker"),
    (("beacon", "ibeacon", "eddystone"), "Beacon", "Beacon"),
    (("thermometer",), "Health", "Thermometer"),
    (("glucose",), "Health", "Glucose Monitor"),
    (("heart rate",), "Health", "Heart Rate Sensor"),
    (("iphone", "pixel phone"), "Phone", "Phone"),
    (("macbook", "laptop", "notebook"), "Computer", "Laptop"),
)

_CLASSIC_MAJOR_TYPES = {
    0x01: ("Computer", "Computer"),
    0x02: ("Phone", "Phone"),
    0x03: ("Network", "Network Device"),
    0x04: ("Audio", "Audio Device"),
    0x05: ("Input", "Input Device"),
    0x06: ("Display", "Imaging Device"),
    0x07: ("Wearable", "Wearable"),
    0x08: ("Other", "Toy"),
    0x09: ("Health", "Health Device"),
}

_CLASSIC_AUDIO_MINOR = {
    0x01: "Headset",
    0x02: "Hands-Free Device",
    0x04: "Microphone",
    0x05: "Speaker",
    0x06: "Headphones",
    0x07: "Portable Audio",
    0x08: "Car Audio",
    0x09: "Set-Top Box",
    0x0A: "HiFi Audio",
    0x0B: "Video Cassette Recorder",
    0x0C: "Video Camera",
    0x0D: "Camcorder",
    0x0E: "Video Conferencing",
    0x0F: "Gaming/Toy Audio",
}

_CLASSIC_MINOR_TYPES = {
    0x01: {
        0x01: ("Computer", "Desktop Workstation"),
        0x02: ("Computer", "Server"),
        0x03: ("Computer", "Laptop"),
        0x04: ("Computer", "Handheld PC/PDA"),
        0x05: ("Computer", "Palm-size PC/PDA"),
        0x06: ("Wearable", "Wearable Computer"),
        0x07: ("Computer", "Tablet"),
    },
    0x02: {
        0x01: ("Phone", "Cellular Phone"),
        0x02: ("Phone", "Cordless Phone"),
        0x03: ("Phone", "Smartphone"),
        0x04: ("Network", "Wired Modem/Voice Gateway"),
        0x05: ("Phone", "Common ISDN Access"),
    },
    0x07: {
        0x01: ("Wearable", "Wristwatch"),
        0x02: ("Wearable", "Pager"),
        0x03: ("Wearable", "Wearable Jacket"),
        0x04: ("Wearable", "Wearable Helmet"),
        0x05: ("Wearable", "Wearable Glasses"),
    },
    0x08: {
        0x01: ("Other", "Robot"),
        0x02: ("Other", "Toy Vehicle"),
        0x03: ("Other", "Doll/Action Figure"),
        0x04: ("Input", "Toy Controller"),
        0x05: ("Other", "Game"),
    },
    0x09: {
        0x01: ("Health", "Blood Pressure Monitor"),
        0x02: ("Health", "Thermometer"),
        0x03: ("Health", "Weighing Scale"),
        0x04: ("Health", "Glucose Meter"),
        0x05: ("Health", "Pulse Oximeter"),
        0x06: ("Health", "Heart/Pulse Rate Monitor"),
        0x07: ("Health", "Health Data Display"),
        0x08: ("Health", "Step Counter"),
        0x09: ("Health", "Body Composition Analyzer"),
        0x0A: ("Health", "Peak Flow Monitor"),
        0x0B: ("Health", "Medication Monitor"),
        0x0C: ("Health", "Knee Prosthesis"),
        0x0D: ("Health", "Ankle Prosthesis"),
        0x0E: ("Health", "Generic Health Manager"),
        0x0F: ("Health", "Personal Mobility Device"),
    },
}

_CONFIDENCE_LABELS = {3: "high", 2: "medium", 1: "low"}


def _uuid16(uuid: str) -> str:
    lowered = uuid.lower()
    if len(lowered) == 4:
        return lowered
    suffix = "-0000-1000-8000-00805f9b34fb"
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(suffix):
        return lowered[4:8]
    return ""


def device_classification(device: BluetoothDevice) -> DeviceClassification:
    candidates = []
    if device.protocol_type:
        candidates.append(_Candidate(
            device.protocol_category or "Other",
            device.protocol_type,
            device.protocol_source or "Advertising protocol",
            3 if device.protocol_confidence == "high" else 2,
        ))
    if device.appearance:
        category_code = device.appearance >> 6
        subcategory = device.appearance & 0x3F
        broad = _APPEARANCE_CATEGORIES.get(category_code)
        if broad is not None:
            generic_detail, category = broad
            detail = _APPEARANCE_DETAILS.get(
                (category_code, subcategory), generic_detail,
            )
            candidates.append(_Candidate(
                category,
                detail,
                "Appearance",
                3 if subcategory and detail != generic_detail else 2,
            ))
    if device.class_of_device is not None:
        classic = _classic_candidate(device.class_of_device)
        if classic is not None:
            candidates.append(classic)
    services = set(device.service_uuids) | set(device.service_data_uuids)
    for uuid in sorted(services):
        service_type = SERVICE_CLASSIFICATIONS.get(_uuid16(uuid))
        if service_type:
            candidates.append(_Candidate(
                service_type[0], service_type[1], "Service UUID", 2,
            ))
    if device.hardware_product:
        hardware_name = " ".join(
            part for part in (device.hardware_vendor, device.hardware_product) if part
        )
        hardware_category = next((
            (category, detail)
            for tokens, category, detail in _NAME_TYPES
            if any(token in hardware_name.casefold() for token in tokens)
        ), None)
        candidates.append(_Candidate(
            hardware_category[0] if hardware_category else "Other",
            hardware_name,
            device.hardware_source or "BlueZ Device ID",
            3 if hardware_category else 1,
        ))
    name = device.name.casefold()
    for tokens, category, detail in _NAME_TYPES:
        if any(token in name for token in tokens):
            candidates.append(_Candidate(category, detail, "Name", 1))
            break
    if not candidates:
        if device.manufacturer_ids:
            manufacturer = manufacturer_label(
                device.manufacturer_ids, device.identifier,
            )
            if manufacturer:
                return DeviceClassification(
                    "Other",
                    f"{manufacturer} device",
                    "Manufacturer",
                    "low",
                )
        if services:
            return DeviceClassification(
                "Other",
                "Service-advertising device",
                "Service UUID",
                "low",
            )
        fallback = "Other" if device.name != "<Unknown>" else "Unknown"
        return DeviceClassification(fallback, fallback, "None", "none")
    confidence = max(candidate.confidence for candidate in candidates)
    strongest = [candidate for candidate in candidates if candidate.confidence == confidence]
    categories = {candidate.category for candidate in strongest}
    if len(categories) > 1:
        sources = " + ".join(dict.fromkeys(candidate.source for candidate in strongest))
        details = " / ".join(dict.fromkeys(candidate.detail for candidate in strongest))
        return DeviceClassification(
            "Ambiguous", details, sources, _CONFIDENCE_LABELS[confidence], True,
        )
    selected = strongest[0]
    return DeviceClassification(
        selected.category,
        selected.detail,
        selected.source,
        _CONFIDENCE_LABELS[selected.confidence],
    )


def device_category(device: BluetoothDevice) -> str:
    return device_classification(device).category


def _classic_candidate(class_of_device: int) -> _Candidate | None:
    major = (class_of_device >> 8) & 0x1F
    broad = _CLASSIC_MAJOR_TYPES.get(major)
    if broad is None:
        return None
    category, detail = broad
    specific = False
    minor = (class_of_device & 0xFC) >> 2
    minor_type = _CLASSIC_MINOR_TYPES.get(major, {}).get(minor)
    if minor_type is not None:
        category, detail = minor_type
        specific = True
    elif major == 0x04:
        detail = _CLASSIC_AUDIO_MINOR.get(minor, detail)
        specific = minor in _CLASSIC_AUDIO_MINOR
    elif major == 0x05:
        peripheral_type = (class_of_device & 0xC0) >> 6
        minor = (class_of_device & 0x3C) >> 2
        if peripheral_type == 0x01:
            detail, specific = "Keyboard", True
        elif peripheral_type == 0x02:
            detail, specific = ("Digitizer Tablet" if minor == 0x05 else "Mouse"), True
        elif peripheral_type == 0x03:
            detail, specific = "Keyboard/Pointing Device", True
        elif minor in {0x01, 0x02}:
            detail, specific = "Game Controller", True
        elif minor == 0x03:
            detail, specific = "Remote Control", True
    elif major == 0x06:
        for mask, candidate, candidate_category in (
            (0x80, "Printer", "Other"),
            (0x40, "Scanner", "Input"),
            (0x20, "Camera", "Other"),
            (0x10, "Display", "Display"),
        ):
            if class_of_device & mask:
                category, detail, specific = candidate_category, candidate, True
                break
    return _Candidate(category, detail, "Class of Device", 3 if specific else 2)
