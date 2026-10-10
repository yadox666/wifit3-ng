from unittest.mock import patch

from wifit3.ui.offline_client_panels import (
    client_has_association_or_probes,
    offline_wifi_client_stays_in_main_panel,
    offline_wifi_client_use_secondary_panel,
    partition_offline_wifi_clients,
    public_wifi_client_fingerprint_keys,
)


def test_private_mac_without_activity_goes_secondary():
    record = {"client_mac": "02:11:22:33:44:55", "fingerprint_id": "fp1", "fingerprint_completeness": 80}
    assert offline_wifi_client_use_secondary_panel(record, frozenset({"fp1"}), frozenset({"fp1"}))


def test_fingerprint_link_without_aps_stays_secondary():
    private = {
        "client_mac": "02:aa:bb:cc:dd:ee",
        "fingerprint_id": "samefp12",
        "fingerprint_completeness": 80,
    }
    with patch(
        "wifit3.ui.offline_client_panels.vendor_for_mac",
        return_value=None,
    ):
        assert offline_wifi_client_use_secondary_panel(
            private,
            frozenset({"samefp12"}),
            frozenset({"samefp12"}),
        )


def test_fingerprint_link_with_aps_stays_main():
    private = {
        "client_mac": "02:aa:bb:cc:dd:ee",
        "fingerprint_id": "samefp12",
        "fingerprint_completeness": 80,
        "access_point_count": 1,
        "access_points": [{"bssid": "00:11:22:33:44:55", "ssid": "Lab"}],
    }
    with patch(
        "wifit3.ui.offline_client_panels.vendor_for_mac",
        return_value=None,
    ):
        assert offline_wifi_client_stays_in_main_panel(
            private,
            frozenset({"samefp12"}),
            frozenset({"samefp12"}),
        )


def test_public_mac_with_vendor_and_aps_stays_main_without_fingerprint():
    record = {
        "client_mac": "00:11:22:33:44:55",
        "access_point_count": 2,
    }
    with patch(
        "wifit3.ui.offline_client_panels.vendor_for_mac",
        return_value="Example Corp",
    ):
        assert offline_wifi_client_stays_in_main_panel(
            record,
            frozenset(),
            frozenset(),
        )


def test_public_mac_with_vendor_and_probes_stays_main_without_fingerprint():
    record = {
        "client_mac": "ec:0d:a4:8b:c9:63",
        "probed_ssids": ["Guest-WiFi", "Home"],
    }
    with patch(
        "wifit3.ui.offline_client_panels.is_manufacturer_mac",
        return_value=True,
    ):
        assert offline_wifi_client_stays_in_main_panel(
            record,
            frozenset(),
            frozenset(),
        )


def test_public_mac_with_vendor_activity_and_shared_fp_stays_main():
    record = {
        "client_mac": "00:11:22:33:44:55",
        "access_point_count": 2,
        "fingerprint_id": "sharedfp",
        "fingerprint_completeness": 80,
    }
    assert offline_wifi_client_stays_in_main_panel(
        record,
        frozenset(),
        frozenset({"sharedfp"}),
    )


def test_probe_count_without_ssid_names_is_not_activity():
    record = {
        "client_mac": "02:11:22:33:44:55",
        "fingerprint_id": "sharedfp",
        "fingerprint_completeness": 80,
        "fingerprint": {
            "payload": {"behavior": {"probed_ssid_count": 3}},
        },
    }
    assert not client_has_association_or_probes(record)
    assert offline_wifi_client_use_secondary_panel(
        record,
        frozenset(),
        frozenset({"sharedfp"}),
    )


def test_saved_probe_ssids_count_as_activity():
    record = {
        "client_mac": "02:11:22:33:44:55",
        "fingerprint_id": "sharedfp",
        "fingerprint_completeness": 80,
        "probed_ssids": ["Guest", "Home"],
    }
    assert client_has_association_or_probes(record)
    assert offline_wifi_client_stays_in_main_panel(
        record,
        frozenset(),
        frozenset({"sharedfp"}),
    )


def test_two_inactive_clients_with_shared_fingerprint_both_secondary():
    shared = {
        "fingerprint_id": "ghostfp99",
        "fingerprint_completeness": 80,
    }
    all_records = [
        {"client_mac": "00:11:22:33:44:01", **shared},
        {"client_mac": "02:aa:bb:cc:dd:ee", **shared},
    ]
    with patch(
        "wifit3.ui.offline_client_panels.vendor_for_mac",
        return_value="Example Corp",
    ):
        main, secondary = partition_offline_wifi_clients(
            all_records,
            all_records=all_records,
        )
    assert main == []
    assert len(secondary) == 2


def test_partition_promotes_linked_active_private_client():
    all_records = [
        {
            "client_mac": "00:11:22:33:44:55",
            "fingerprint_id": "linkme",
            "fingerprint_completeness": 80,
            "access_point_count": 1,
        },
        {
            "client_mac": "02:11:22:33:44:01",
            "fingerprint_id": "linkme",
            "fingerprint_completeness": 80,
            "access_point_count": 1,
            "access_points": [{"bssid": "00:aa:bb:cc:dd:ee", "ssid": "Guest"}],
        },
        {"client_mac": "02:11:22:33:44:02"},
    ]
    filtered = [all_records[1]]
    with patch(
        "wifit3.ui.offline_client_panels.vendor_for_mac",
        side_effect=lambda mac: "Example Corp" if mac.startswith("00:") else None,
    ):
        main, secondary = partition_offline_wifi_clients(
            filtered,
            all_records=all_records,
        )
    assert main == [all_records[1]]
    assert secondary == []
