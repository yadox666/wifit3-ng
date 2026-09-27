import json
import stat

from wifit3.persist.network_metadata import NetworkMetadataStore, network_metadata_path


BSSID = "aa:bb:cc:dd:ee:ff"


def test_store_round_trip_is_versioned_private_and_reuses_bssid_file(tmp_path):
    store = NetworkMetadataStore(tmp_path, BSSID, "Cafe WiFi")
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

    assert store.path == network_metadata_path(tmp_path, "Cafe WiFi", BSSID)
    payload = json.loads(store.path.read_text("utf-8"))
    assert payload["version"] == 1
    assert payload["bssid"] == BSSID
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600

    loaded = NetworkMetadataStore(tmp_path, BSSID.upper(), "Renamed")
    assert loaded.path == store.path
    assert loaded.metadata.facts["gateways"][0].value == "192.168.1.1"
    assert loaded.metadata.clients["02:11:22:33:44:55"].facts[
        "websites"
    ][0].value == "http://example.com/audit"
    assert len(loaded.metadata.facts["websites"]) == 41
    assert len(
        loaded.metadata.clients["02:11:22:33:44:55"].facts["websites"]
    ) == 41
    assert not loaded.dirty


def test_invalid_file_is_reported_and_not_trusted(tmp_path):
    path = network_metadata_path(tmp_path, "Cafe", BSSID)
    path.write_text('{"version": 999, "bssid": "aa:bb:cc:dd:ee:ff"}', "utf-8")

    store = NetworkMetadataStore(tmp_path, BSSID, "Cafe")

    assert store.errors == ["Unsupported or invalid network metadata"]
    assert store.metadata.facts == {}
