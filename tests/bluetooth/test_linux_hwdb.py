from types import SimpleNamespace

from wifit3.bluetooth import linux_hwdb


def test_resolve_bluez_modalias_queries_local_hwdb(monkeypatch):
    linux_hwdb.resolve_bluez_modalias.cache_clear()
    monkeypatch.setattr(linux_hwdb.sys, "platform", "linux")
    monkeypatch.setattr(
        linux_hwdb.shutil,
        "which",
        lambda command: "/usr/bin/systemd-hwdb" if command == "systemd-hwdb" else None,
    )
    observed = {}

    def run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "ID_VENDOR_FROM_DATABASE=Acme Audio\n"
                "ID_MODEL_FROM_DATABASE=Studio Headphones\n"
                "UNTRUSTED_FIELD=ignored\n"
            ),
        )

    monkeypatch.setattr(linux_hwdb.subprocess, "run", run)

    identity = linux_hwdb.resolve_bluez_modalias(
        "bluetooth:v1234p5678d0001",
    )

    assert identity == {
        "modalias": "bluetooth:v1234p5678d0001",
        "hardware_vendor": "Acme Audio",
        "hardware_product": "Studio Headphones",
        "hardware_source": "BlueZ Device ID / systemd hwdb",
    }
    assert observed["command"] == [
        "/usr/bin/systemd-hwdb", "query", "bluetooth:v1234p5678d0001",
    ]
    assert observed["kwargs"]["timeout"] == 1.0


def test_resolve_bluez_modalias_rejects_untrusted_formats(monkeypatch):
    linux_hwdb.resolve_bluez_modalias.cache_clear()
    monkeypatch.setattr(
        linux_hwdb.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("not called")),
    )

    assert linux_hwdb.resolve_bluez_modalias("usb:v1234p5678") == {}
    assert linux_hwdb.resolve_bluez_modalias("bluetooth:$(unsafe)") == {}
