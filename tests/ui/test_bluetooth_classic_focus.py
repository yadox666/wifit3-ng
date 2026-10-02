from types import SimpleNamespace

from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO
from wifit3.ui.screens.bluetooth_classic_focus import _device_supports_sdp


def test_sdp_is_shown_only_for_classic_devices():
    assert _device_supports_sdp(
        SimpleNamespace(radio_types=(CLASSIC_RADIO,)),
    )
    assert _device_supports_sdp(
        SimpleNamespace(radio_types=(BLE_RADIO, CLASSIC_RADIO)),
    )
    assert not _device_supports_sdp(
        SimpleNamespace(radio_types=(BLE_RADIO,)),
    )
