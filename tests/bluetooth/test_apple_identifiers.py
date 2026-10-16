from wifit3.bluetooth.apple_identifiers import (
    apple_marketing_name,
    format_device_model_number,
    looks_like_apple_internal_model,
)


def test_apple_marketing_name_resolves_iphone_and_watch():
    assert apple_marketing_name("iPhone13,4") == "iPhone 12 Pro Max"
    assert apple_marketing_name("Watch7,15") == "Apple Watch SE 3 (GPS + Cellular)"


def test_format_device_model_number_for_table_and_detail():
    assert format_device_model_number("iPhone13,4") == "iPhone 12 Pro Max"
    assert format_device_model_number("iPhone13,4", detail=True) == (
        "iPhone 12 Pro Max (iPhone13,4)"
    )
    assert format_device_model_number("WF-2910 Series") == "WF-2910 Series"


def test_looks_like_apple_internal_model():
    assert looks_like_apple_internal_model("iPhone13,4")
    assert looks_like_apple_internal_model("Watch7,15")
    assert looks_like_apple_internal_model("AudioAccessory5,1")
    assert looks_like_apple_internal_model("AirPodsPro1,1")
    assert looks_like_apple_internal_model("Device1,8212")
    assert not looks_like_apple_internal_model("SM-G998B")


def test_audio_board_ids_resolve_to_marketing_names():
    assert apple_marketing_name("AudioAccessory5,1") == "HomePod mini"
    assert apple_marketing_name("AirPodsPro1,1") == "AirPods Pro"
    assert apple_marketing_name("Device1,8212") == "AirPods Pro (2nd generation)"
    assert apple_marketing_name("BeatsFitPro1,1") == "Beats Fit Pro"
    assert apple_marketing_name("powerbeatspro1,1") == "Powerbeats Pro"
    assert apple_marketing_name("Device1,9999") is None
    assert apple_marketing_name("AirTag1,1") == "AirTag"
