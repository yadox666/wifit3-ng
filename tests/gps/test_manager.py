import pytest

from wifit3.gps.manager import parse_nmea_line


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
