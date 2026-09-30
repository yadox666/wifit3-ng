import pytest
from types import SimpleNamespace

from wifit3.gps.manager import GpsManager, parse_nmea_line


def test_parse_gga_fix():
    fix = parse_nmea_line(
        "$GPGGA,091203.694,2807.7619,N,01526.5629,W,1,04,1.9,9.4,M,37.4,M,,0000*41",
        {},
    )

    assert fix is not None
    assert fix.latitude == pytest.approx(28.129365)
    assert fix.longitude == pytest.approx(-15.442715)
    assert fix.altitude_m == 9.4
    assert fix.accuracy_m == 9.5
    assert fix.satellites == 4


def test_rejects_invalid_checksum_and_no_fix():
    assert parse_nmea_line(
        "$GPGGA,091203.694,2807.7619,N,01526.5629,W,1,04,1.9,9.4,M,37.4,M,,0000*00",
        {},
    ) is None
    assert parse_nmea_line(
        "$GPGGA,091203.694,2807.7619,N,01526.5629,W,0,00,9.9,9.4,M,37.4,M,,0000*48",
        {},
    ) is None


def test_connected_status_includes_safe_serial_port_metadata(monkeypatch):
    port = SimpleNamespace(
        device="/dev/ttyUSB0",
        description="u-blox GNSS receiver",
        manufacturer="u-blox",
        product="NEO-M8U",
        vid=0x1546,
        pid=0x01A8,
    )
    monkeypatch.setattr(
        "wifit3.gps.manager.list_ports",
        SimpleNamespace(comports=lambda: [port]),
    )

    status = GpsManager._status_for_port("/dev/ttyUSB0", 9600)

    assert status.label == "u-blox NEO-M8U"
    assert status.instance_key == ("/dev/ttyUSB0", 9600, 0x1546, 0x01A8)
