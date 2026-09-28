from dataclasses import replace

import pytest

from wifit3.bluetooth.classification import device_category, device_classification
from wifit3.models import BluetoothDevice


def _device(**changes) -> BluetoothDevice:
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="<Unknown>",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=1.0,
        last_seen=1.0,
    )
    return replace(device, **changes)


def test_device_category_prefers_descriptive_name():
    assert device_category(_device(name="Living Room Headphones")) == "Audio"
    assert device_category(_device(name="Pixel Phone")) == "Phone"


def test_device_category_uses_standard_service():
    assert device_category(_device(service_uuids=("1812",))) == "Input"
    assert device_category(_device(service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",))) == "Health"


def test_device_category_keeps_unknown_inference_explicit():
    assert device_category(_device()) == "Unknown"
    assert device_category(_device(name="Acme Sensor")) == "Sensor"


def test_device_category_uses_classic_class_of_device():
    assert device_category(_device(class_of_device=0x04020C)) == "Phone"
    assert device_category(_device(class_of_device=0x240404)) == "Audio"


def test_appearance_identifies_exact_wearable_audio_type():
    classification = device_classification(
        _device(appearance=(0x025 << 6) | 0x03),
    )

    assert classification.category == "Audio"
    assert classification.detail == "Headphones"
    assert classification.source == "Appearance"
    assert classification.confidence == "high"


def test_classic_minor_class_distinguishes_headset_and_headphones():
    headset = device_classification(_device(class_of_device=0x240404))
    headphones = device_classification(_device(class_of_device=0x240418))

    assert headset.detail == "Headset"
    assert headphones.detail == "Headphones"


def test_structured_evidence_wins_over_device_name():
    classification = device_classification(
        _device(
            name="Living Room Headphones",
            appearance=(0x00F << 6) | 0x02,
        ),
    )

    assert classification.category == "Input"
    assert classification.detail == "Mouse"
    assert classification.source == "Appearance"


def test_conflicting_high_confidence_evidence_is_ambiguous():
    classification = device_classification(
        _device(
            appearance=(0x00F << 6) | 0x01,
            class_of_device=0x240404,
        ),
    )

    assert classification.category == "Ambiguous"
    assert classification.ambiguous
    assert classification.confidence == "high"


def test_verified_advertising_protocol_classifies_anonymous_device():
    classification = device_classification(
        _device(
            manufacturer_ids=(0x004C,),
            protocol_category="Audio",
            protocol_type="Apple Proximity Pairing audio",
            protocol_source="Manufacturer protocol",
            protocol_confidence="high",
        ),
    )

    assert classification.category == "Audio"
    assert classification.detail == "Apple Proximity Pairing audio"
    assert classification.source == "Manufacturer protocol"


def test_manufacturer_is_an_honest_last_resort_instead_of_unknown():
    classification = device_classification(
        _device(manufacturer_ids=(0x004C,)),
    )

    assert classification.category == "Other"
    assert classification.detail.startswith("Apple")
    assert classification.source == "Manufacturer"
    assert classification.confidence == "low"


@pytest.mark.parametrize(
    ("service_uuid", "category", "detail"),
    [
        ("110b", "Audio", "A2DP Audio Sink"),
        ("1116", "Network", "Network Access Point"),
        ("1809", "Health", "Health Thermometer"),
        ("181a", "Sensor", "Environmental Sensor"),
        ("1857", "Appliance", "Electronic Shelf Label"),
        ("1858", "Audio", "Gaming Audio"),
        ("1859", "Network", "Mesh Proxy Solicitation Device"),
    ],
)
def test_assigned_services_expand_functional_classification(
    service_uuid, category, detail,
):
    classification = device_classification(_device(service_uuids=(service_uuid,)))

    assert classification.category == category
    assert classification.detail == detail
    assert classification.source == "Service UUID"
    assert classification.confidence == "medium"


@pytest.mark.parametrize(
    ("major", "minor", "category", "detail"),
    [
        (0x01, 0x03, "Computer", "Laptop"),
        (0x02, 0x03, "Phone", "Smartphone"),
        (0x07, 0x01, "Wearable", "Wristwatch"),
        (0x08, 0x01, "Other", "Robot"),
        (0x09, 0x05, "Health", "Pulse Oximeter"),
    ],
)
def test_classic_minor_classes_cover_assigned_device_families(
    major, minor, category, detail,
):
    class_of_device = (major << 8) | (minor << 2)
    classification = device_classification(
        _device(class_of_device=class_of_device),
    )

    assert classification.category == category
    assert classification.detail == detail
    assert classification.source == "Class of Device"
    assert classification.confidence == "high"


def test_classic_peripheral_minor_uses_all_four_subclass_bits():
    classification = device_classification(
        _device(class_of_device=(0x05 << 8) | (0x05 << 2) | (0x02 << 6)),
    )

    assert classification.detail == "Digitizer Tablet"


def test_bluez_hardware_product_enriches_category_and_exact_type():
    classification = device_classification(_device(
        hardware_vendor="Acme Audio",
        hardware_product="Studio Headphones",
        hardware_source="BlueZ Device ID / systemd hwdb",
    ))

    assert classification.category == "Audio"
    assert classification.detail == "Acme Audio Studio Headphones"
    assert classification.source == "BlueZ Device ID / systemd hwdb"
    assert classification.confidence == "high"
