from wifit3.persist.ap_history import ApHistoryStore
from wifit3.persist.network_metadata import NetworkMetadataStore


BSSID = "aa:bb:cc:dd:ee:ff"


def test_store_round_trip_reuses_bssid_database_record(tmp_path):
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    store = NetworkMetadataStore(history, BSSID, "Cafe WiFi")
    store.metadata.add(
        "gateways", "192.168.1.1", source="dhcp_ack",
        confidence="advertised", now=100,
    )
    store.metadata.observe_website(
        "http://example.com/audit", hostname="example.com",
        source="http_request", now=101, client_mac="02:11:22:33:44:55",
    )
    for index in range(40):
        store.metadata.observe_website(
            f"http://site-{index}.example/audit",
            hostname=f"site-{index}.example",
            source="http_request",
            now=102 + index,
            client_mac="02:11:22:33:44:55",
        )
    store.save()

    payload = history.network_metadata_payload(BSSID)
    assert payload["version"] == 1
    assert payload["bssid"] == BSSID

    loaded = NetworkMetadataStore(history, BSSID.upper(), "Renamed")
    assert loaded.metadata.facts["gateways"][0].value == "192.168.1.1"
    assert loaded.metadata.clients["02:11:22:33:44:55"].facts[
        "websites"
    ][0].value == "http://example.com/audit"
    assert len(loaded.metadata.facts["websites"]) == 41
    assert len(
        loaded.metadata.clients["02:11:22:33:44:55"].facts["websites"]
    ) == 41
    assert not loaded.dirty


def test_invalid_database_payload_is_reported_and_not_trusted(tmp_path):
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    history.save_network_metadata(
        BSSID, "Cafe", {"version": 999, "bssid": BSSID},
    )

    store = NetworkMetadataStore(history, BSSID, "Cafe")

    assert store.errors == ["Unsupported or invalid network metadata"]
    assert store.metadata.facts == {}
