from wifit3.bluetooth.usb_claim import (
    _macos_release,
    _rfkill_event,
    claim_error_is_recoverable,
)


def test_macos_release_uses_framework_power_off(monkeypatch):
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_claim._macos_set_controller_power",
        lambda enabled: enabled is False,
    )
    monkeypatch.setattr("wifit3.bluetooth.usb_claim.time.sleep", lambda _seconds: None)
    steps = _macos_release(allow_radio_power_off=True)
    assert steps == ["Turned macOS Bluetooth power off"]


def test_macos_release_skips_power_when_disabled():
    assert _macos_release(allow_radio_power_off=False) == []


def test_macos_release_mentions_settings_when_power_off_fails(monkeypatch):
    monkeypatch.setattr(
        "wifit3.bluetooth.usb_claim._macos_set_controller_power",
        lambda enabled: False,
    )
    monkeypatch.setattr("wifit3.bluetooth.usb_claim.shutil.which", lambda _name: None)
    steps = _macos_release(allow_radio_power_off=True)
    assert "System Settings" in steps[0]


def test_rfkill_event_soft_blocks_bluetooth():
    assert _rfkill_event(True) == bytes([0, 0, 0, 0, 2, 3, 1, 0])
    assert _rfkill_event(False) == bytes([0, 0, 0, 0, 2, 3, 0, 0])


def test_recoverable_claim_errors():
    assert claim_error_is_recoverable("Could not detach RTL8761BU from the OS Bluetooth driver")
    assert claim_error_is_recoverable("Could not claim RTL8761BU")
    assert not claim_error_is_recoverable("The selected Bluetooth USB controller was disconnected")
