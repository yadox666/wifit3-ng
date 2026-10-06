from types import SimpleNamespace

import usb.core

from wifit3.sdr import HackRfDevice, find_hackrf_devices, probe_hackrf_usb


def test_hackrf_discovery_lists_only_operational_hackrf_one(monkeypatch):
    devices = [
        SimpleNamespace(idVendor=0x1D50, idProduct=0x6089, bus=2, address=7),
        SimpleNamespace(idVendor=0x0BDA, idProduct=0x2838, bus=2, address=8),
        SimpleNamespace(idVendor=0x1234, idProduct=0x5678, bus=2, address=9),
    ]
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.usb.core.find",
        lambda **_kwargs: devices,
    )

    assert find_hackrf_devices() == [
        HackRfDevice(0x1D50, 0x6089, 2, 7),
    ]


def test_hackrf_device_has_stable_instance_identity():
    device = HackRfDevice(0x1D50, 0x6089, 3, 11)

    assert device.instance_key == (0x1D50, 0x6089, 3, 11)
    assert device.label == "HackRF One · Great Scott Gadgets"


def test_hackrf_usb_probe_reads_board_and_firmware(monkeypatch):
    released = []

    class UsbDevice:
        def ctrl_transfer(self, _request_type, request, *_args, **_kwargs):
            return b"\x02" if request == 14 else b"2024.02.1\0"

    usb_device = UsbDevice()
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.usb.core.find",
        lambda **_kwargs: usb_device,
    )
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.usb.util.dispose_resources",
        released.append,
    )

    health = probe_hackrf_usb(HackRfDevice(0x1D50, 0x6089, 2, 7))

    assert health.ready is True
    assert health.status == "USB READY"
    assert health.detail == "Firmware 2024.02.1"
    assert released == [usb_device]


def test_hackrf_usb_probe_reports_permission_error(monkeypatch):
    class UsbDevice:
        def ctrl_transfer(self, *_args, **_kwargs):
            raise usb.core.USBError("denied", errno=13)

    monkeypatch.setattr(
        "wifit3.sdr.hackrf.libusb_package.get_libusb1_backend",
        lambda: object(),
    )
    monkeypatch.setattr(
        "wifit3.sdr.hackrf.usb.core.find",
        lambda **_kwargs: UsbDevice(),
    )

    health = probe_hackrf_usb(HackRfDevice(0x1D50, 0x6089, 2, 7))

    assert health.ready is False
    assert health.status == "NO ACCESS"
