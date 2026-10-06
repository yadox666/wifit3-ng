from wifit3.bluetooth.usb_hci import UsbHciScanner, classic_remote_names_enabled


def test_classic_remote_names_disabled_by_default(monkeypatch):
    monkeypatch.delenv("WIFIT3_BT_CLASSIC_REMOTE_NAMES", raising=False)
    assert classic_remote_names_enabled() is False


def test_classic_remote_names_env_toggle(monkeypatch):
    monkeypatch.setenv("WIFIT3_BT_CLASSIC_REMOTE_NAMES", "1")
    assert classic_remote_names_enabled() is True


def test_queue_remote_name_skipped_when_disabled(monkeypatch):
    from wifit3.bluetooth.usb_hci import UsbBluetoothController

    monkeypatch.delenv("WIFIT3_BT_CLASSIC_REMOTE_NAMES", raising=False)
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    scanner = UsbHciScanner(controller, lambda _observation: None)
    scanner._queue_remote_name("AA:BB:CC:DD:EE:FF")
    assert "AA:BB:CC:DD:EE:FF" in scanner._remote_name_resolved
    assert not scanner._remote_name_queue
