from wifit3.ui.screens.focus_v2.client_endpoint import ClientEndpoint


def test_client_power_meter_uses_rssi_not_zero_packet_rate():
    endpoint = ClientEndpoint(mac="3a:35:38:2d:04:38", power_dbm=-56, signal=0.0)
    line = endpoint._power_line()
    plain = line.plain
    assert "╳" not in plain and "✕" not in plain
    assert "-56 dBm" in plain


def test_client_power_meter_warming_when_no_rssi():
    endpoint = ClientEndpoint(power_dbm=-100)
    assert endpoint._meter_rate() is None
