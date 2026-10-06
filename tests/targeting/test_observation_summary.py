from wifit3.targeting import observation_summary_lines


def test_ap_summary_keeps_essentials_only():
    pairs = observation_summary_lines(
        "wifi",
        "ap",
        {
            "ssid": "Lab",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "channel": 6,
            "encryption": "WPA2",
            "signal_dbm": -42,
            "manufacturer": "Netgear",
            "capabilities": {"long": "technical blob"},
        },
        identifier="aa:bb:cc:dd:ee:ff",
    )
    labels = [label for label, _value in pairs]
    assert labels == ["Network", "Address", "Channel", "Security", "Signal", "Vendor"]
    assert pairs[0] == ("Network", "Lab")
    assert pairs[2][0] == "Channel"
    assert "Ch 6" in pairs[2][1]


def test_client_probes_truncated():
    pairs = dict(
        observation_summary_lines(
            "wifi",
            "client",
            {
                "mac": "11:22:33:44:55:66",
                "probe_requests": ["A", "B", "C", "D"],
            },
            identifier="11:22:33:44:55:66",
        ),
    )
    assert "A, B, C (+1 more)" in pairs["Probed SSIDs"]


