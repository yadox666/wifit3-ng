"""Conservative Bluetooth service and advertising-protocol signatures.

Assigned services and Classic profiles follow the Bluetooth SIG Assigned
Numbers and BlueZ profile constants. Selected vendor protocol identifiers are
cross-checked against the Apache-2.0 Home Assistant Bluetooth matcher database.
Exact manufacturer-frame rules are derived from the MIT-licensed reelyActive
advlib database, with selected composite rules from MIT-licensed AirHound.
The catalog deliberately maps only stable evidence and does not copy device
names from broad, heuristic, GPLv3, or CC-BY-SA matcher collections.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProtocolSignature:
    category: str
    detail: str
    source: str = "Service protocol"
    confidence: str = "high"


@dataclass(frozen=True, slots=True)
class ManufacturerProtocolSignature:
    company_id: int
    prefix: bytes
    category: str
    detail: str
    lengths: tuple[int, ...] = ()
    minimum_length: int = 0
    source: str = "reelyActive advlib signature"
    confidence: str = "high"


SERVICE_CLASSIFICATIONS = {
    "1101": ("Other", "Serial Port"),
    "1102": ("Network", "LAN Access"),
    "1103": ("Network", "Dial-up Networking"),
    "1104": ("Other", "IrMC Sync"),
    "1105": ("Other", "Object Push"),
    "1106": ("Computer", "File Transfer"),
    "1108": ("Audio", "Headset Profile"),
    "110a": ("Audio", "A2DP Audio Source"),
    "110b": ("Audio", "A2DP Audio Sink"),
    "110c": ("Audio", "A/V Remote Control Target"),
    "110d": ("Audio", "Advanced Audio Distribution"),
    "110e": ("Audio", "A/V Remote Control"),
    "1112": ("Audio", "Headset Audio Gateway"),
    "1115": ("Network", "Personal Area Network User"),
    "1116": ("Network", "Network Access Point"),
    "1117": ("Network", "Group Ad-hoc Network"),
    "111e": ("Audio", "Hands-Free Headset"),
    "111f": ("Audio", "Hands-Free Audio Gateway"),
    "1124": ("Input", "Human Interface Device"),
    "112d": ("Phone", "SIM Access"),
    "112e": ("Other", "Phonebook Access Client"),
    "112f": ("Phone", "Phonebook Access Server"),
    "1132": ("Phone", "Message Access Server"),
    "1133": ("Other", "Message Notification Server"),
    "1203": ("Audio", "Generic Audio"),
    "1303": ("Other", "Video Source"),
    "1808": ("Health", "Glucose Monitor"),
    "1809": ("Health", "Health Thermometer"),
    "180d": ("Health", "Heart Rate Sensor"),
    "180e": ("Phone", "Phone Alert Status"),
    "1810": ("Health", "Blood Pressure Monitor"),
    "1812": ("Input", "Human Interface Device"),
    "1814": ("Health", "Running Speed/Cadence Sensor"),
    "1815": ("Appliance", "Automation I/O Device"),
    "1816": ("Health", "Cycling Speed/Cadence Sensor"),
    "1818": ("Health", "Cycling Power Sensor"),
    "1819": ("Wearable", "Location/Navigation Device"),
    "181a": ("Sensor", "Environmental Sensor"),
    "181b": ("Health", "Body Composition Monitor"),
    "181d": ("Health", "Weight Scale"),
    "181f": ("Health", "Continuous Glucose Monitor"),
    "1820": ("Network", "Internet Protocol Support Device"),
    "1821": ("Beacon", "Indoor Positioning Device"),
    "1822": ("Health", "Pulse Oximeter"),
    "1823": ("Network", "HTTP Proxy"),
    "1824": ("Network", "Transport Discovery Device"),
    "1826": ("Health", "Fitness Machine"),
    "1827": ("Network", "Mesh Provisioning Device"),
    "1828": ("Network", "Mesh Proxy Device"),
    "183a": ("Health", "Insulin Delivery Device"),
    "183b": ("Sensor", "Binary Sensor"),
    "183c": ("Health", "Emergency Configuration Device"),
    "1843": ("Audio", "Audio Input Control"),
    "1844": ("Audio", "Volume Control"),
    "1845": ("Audio", "Volume Offset Control"),
    "1846": ("Audio", "Coordinated Audio Set"),
    "1848": ("Audio", "Media Control"),
    "1849": ("Audio", "Generic Media Control"),
    "184b": ("Phone", "Telephone Bearer"),
    "184c": ("Phone", "Generic Telephone Bearer"),
    "184d": ("Audio", "Microphone Control"),
    "184e": ("Audio", "Audio Stream Control"),
    "184f": ("Audio", "Broadcast Audio Scan"),
    "1850": ("Audio", "Published Audio Capabilities"),
    "1851": ("Audio", "Basic Audio Announcement"),
    "1852": ("Audio", "Broadcast Audio Announcement"),
    "1853": ("Audio", "Common Audio"),
    "1854": ("Audio", "Hearing Access Device"),
    "1855": ("Audio", "Telephony and Media Audio"),
    "1856": ("Audio", "Public Broadcast Audio"),
    "1857": ("Appliance", "Electronic Shelf Label"),
    "1858": ("Audio", "Gaming Audio"),
    "1859": ("Network", "Mesh Proxy Solicitation Device"),
}


SERVICE_PROTOCOLS = {
    "0d00": ProtocolSignature(
        "Appliance", "SwitchBot device", confidence="medium",
    ),
    "fd3d": ProtocolSignature("Sensor", "SwitchBot sensor"),
    "fd44": ProtocolSignature("Beacon", "Find My network accessory", confidence="medium"),
    "fd6f": ProtocolSignature(
        "Other", "Exposure Notification broadcaster", confidence="medium",
    ),
    "fcd2": ProtocolSignature("Sensor", "BTHome sensor"),
    "fe2c": ProtocolSignature(
        "Other", "Google Fast Pair accessory", confidence="medium",
    ),
    "fe59": ProtocolSignature(
        "Other", "Nordic Secure DFU mode", confidence="medium",
    ),
    "fe95": ProtocolSignature(
        "Other", "Xiaomi MiBeacon device", confidence="medium",
    ),
    "fe9a": ProtocolSignature("Beacon", "Estimote beacon"),
    "feaa": ProtocolSignature("Beacon", "Google Eddystone beacon"),
    "feec": ProtocolSignature("Beacon", "Tile tracker (shipping mode)"),
    "feed": ProtocolSignature("Beacon", "Tile tracker"),
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": ProtocolSignature(
        "Other", "Nordic UART device", confidence="medium",
    ),
    "b42e1f6e-ade7-11e4-89d3-123b93f75cba": ProtocolSignature(
        "Sensor", "Airthings air-quality sensor",
    ),
    "b42e1c08-ade7-11e4-89d3-123b93f75cba": ProtocolSignature(
        "Sensor", "Airthings air-quality sensor",
    ),
    "b42e3882-ade7-11e4-89d3-123b93f75cba": ProtocolSignature(
        "Sensor", "Airthings air-quality sensor",
    ),
    "b42e4a8e-ade7-11e4-89d3-123b93f75cba": ProtocolSignature(
        "Sensor", "Airthings air-quality sensor",
    ),
    "b42e90a2-ade7-11e4-89d3-123b93f75cba": ProtocolSignature(
        "Sensor", "Airthings air-quality sensor",
    ),
    "cba20d00-224d-11e6-9fb8-0002a5d5c51b": ProtocolSignature(
        "Appliance", "SwitchBot device",
    ),
    "f0cd1400-95da-4f4b-9ac8-aa55d312af0c": ProtocolSignature(
        "Sensor", "Aranet environmental sensor",
    ),
    "fce0": ProtocolSignature("Sensor", "Aranet environmental sensor"),
    "3100": ProtocolSignature(
        "Sensor", "Raven acoustic sensor", "AirHound signature", "medium",
    ),
    "3200": ProtocolSignature(
        "Sensor", "Raven acoustic sensor", "AirHound signature", "medium",
    ),
    "3300": ProtocolSignature(
        "Sensor", "Raven acoustic sensor", "AirHound signature", "medium",
    ),
    "3400": ProtocolSignature(
        "Sensor", "Raven acoustic sensor", "AirHound signature", "medium",
    ),
    "3500": ProtocolSignature(
        "Sensor", "Raven acoustic sensor", "AirHound signature", "medium",
    ),
}


MANUFACTURER_PROTOCOLS = (
    ManufacturerProtocolSignature(
        0x0077, b"\x01\x00", "Sensor", "Laird Connectivity sensor", (24,),
    ),
    ManufacturerProtocolSignature(
        0x0077, b"\x81\xff", "Tracker", "Laird contact tracer", (24,),
    ),
    ManufacturerProtocolSignature(
        0x026C, b"\x02", "Sensor", "Efento environmental sensor", (24,),
    ),
    ManufacturerProtocolSignature(
        0x026C, b"\x03", "Sensor", "Efento environmental sensor", (22,),
    ),
    ManufacturerProtocolSignature(
        0x026C, b"\x04", "Sensor", "Efento environmental sensor",
        minimum_length=7,
    ),
    ManufacturerProtocolSignature(
        0x03DA, b"", "Sensor", "EnOcean BLE sensor protocol",
        minimum_length=9, confidence="medium",
    ),
    ManufacturerProtocolSignature(
        0x0500, b"", "Tracker", "Wiliot IoT Pixel", (27,),
    ),
    ManufacturerProtocolSignature(
        0x0583, b"\x01", "Tracker", "Code Blue DirAct proximity device",
        minimum_length=1,
    ),
    ManufacturerProtocolSignature(
        0x0583, b"\x11", "Tracker", "Code Blue DirAct proximity device",
        minimum_length=1,
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\x51\x01", "Sensor", "Minew MSE01 sensor",
        minimum_length=7,
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\x51\x02", "Sensor", "Minew MSE02 sensor",
        minimum_length=7,
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xa3\x01", "Sensor", "Minew S3 environmental sensor", (20,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xa3\x03", "Sensor", "Minew S3 environmental sensor", (16,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xa4\x00", "Sensor", "Minew S4 contact sensor", (18,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xa4\x01", "Sensor", "Minew S4 contact sensor", (15,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xca\x05", "Sensor", "Minew temperature/humidity sensor", (24,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xca\x18", "Sensor", "Minew occupancy sensor", (24,),
    ),
    ManufacturerProtocolSignature(
        0x0639, b"\xca\x1e", "Sensor", "Minew time-of-flight sensor", (24,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x12", "Sensor", "ELA temperature sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x21", "Sensor", "ELA temperature/humidity sensor", (5,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x32", "Sensor", "ELA magnetic contact sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x42", "Sensor", "ELA movement sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x56", "Sensor", "ELA accelerometer", (7,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x62", "Sensor", "ELA digital-input sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\x92", "Sensor", "ELA PIR sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x0757, b"\xb2", "Input", "ELA touch sensor", (3,),
    ),
    ManufacturerProtocolSignature(
        0x075B, b"\x05", "Sensor", "HibouAir air-quality sensor", (24,),
    ),
)


APPLE_CONTINUITY_PROTOCOLS = {
    0x03: ProtocolSignature(
        "Other", "Apple AirPrint broadcaster",
        "reelyActive advlib signature", "medium",
    ),
    0x05: ProtocolSignature(
        "Other", "Apple AirDrop broadcaster",
        "reelyActive advlib signature", "medium",
    ),
    0x08: ProtocolSignature(
        "Other", "Apple Siri broadcaster",
        "reelyActive advlib signature", "medium",
    ),
    0x09: ProtocolSignature(
        "Audio", "Apple AirPlay device",
        "reelyActive advlib signature", "medium",
    ),
    0x0A: ProtocolSignature(
        "Audio", "Apple AirPlay device",
        "reelyActive advlib signature", "medium",
    ),
    0x0B: ProtocolSignature(
        "Wearable", "Apple Watch Magic Switch",
        "reelyActive advlib signature", "high",
    ),
    0x0C: ProtocolSignature(
        "Other", "Apple Handoff device",
        "reelyActive advlib signature", "medium",
    ),
    0x0D: ProtocolSignature(
        "Network", "Apple tethering target",
        "reelyActive advlib signature", "medium",
    ),
    0x0E: ProtocolSignature(
        "Network", "Apple tethering source",
        "reelyActive advlib signature", "medium",
    ),
    0x0F: ProtocolSignature(
        "Other", "Apple Nearby Action device",
        "reelyActive advlib signature", "medium",
    ),
    0x10: ProtocolSignature(
        "Other", "Apple Nearby Info device",
        "reelyActive advlib signature", "medium",
    ),
}
