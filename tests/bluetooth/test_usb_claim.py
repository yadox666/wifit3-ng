from wifit3.bluetooth.usb_claim import claim_error_is_recoverable


def test_recoverable_claim_errors():
    assert claim_error_is_recoverable("Could not detach RTL8761BU from the OS Bluetooth driver")
    assert claim_error_is_recoverable("Could not claim RTL8761BU")
    assert not claim_error_is_recoverable("The selected Bluetooth USB controller was disconnected")
