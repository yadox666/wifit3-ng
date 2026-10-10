from rich.text import Text

from wifit3.ui.offline_client_probes import (
    enrich_offline_wifi_client_probes,
    offline_client_probes_cell,
    offline_client_probed_ssids,
)


def test_offline_client_probed_ssids_from_record_and_fingerprint():
    record = {"probed_ssids": ["Home", "Guest"]}
    assert offline_client_probed_ssids(record) == ("Guest", "Home")

    record = {
        "radio_fingerprint": {
            "payload": {
                "behavior": {"probed_ssids": ["Coffee", "Home"]},
            },
        },
    }
    assert offline_client_probed_ssids(record) == ("Coffee", "Home")


def test_enrich_merges_hidden_probe_ssids():
    record = {"radio_fingerprint": {"payload": {"behavior": {"probed_ssids": ["A"]}}}}
    enrich_offline_wifi_client_probes(record, hidden_probe_ssids=["B", "A"])
    assert record["probed_ssids"] == ["A", "B"]


def test_offline_client_probes_cell_shows_placeholder_and_overflow():
    empty = offline_client_probes_cell({})
    assert isinstance(empty, Text)
    assert empty.plain == "·"

    many = offline_client_probes_cell(
        {"probed_ssids": [f"Net-{index}" for index in range(8)]},
    )
    assert "+2" in many.plain
