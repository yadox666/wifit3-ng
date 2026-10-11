"""Stations this app transmits as must not come back as saved clients."""
import struct

from wifit3.models import AccessPoint
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.persist.pcap import PcapWriter
from wifit3.persist.probe_stations import dominant_probe_station

BSSID = "aa:bb:cc:dd:ee:ff"
OURS = "02:10:20:30:40:50"
LONG_LIVED = "02:10:20:30:40:51"
OTHER = "12:10:20:30:40:52"


def _remember_ap(store: ApHistoryStore) -> None:
    assert store.remember(
        AccessPoint(bssid=BSSID, ssid="Lab", channel=6, encryption="WPA2"),
        force=True,
    )


def _uplink(station: str, bssid: str = BSSID) -> bytes:
    destination = bytes.fromhex(bssid.replace(":", ""))
    transmitter = bytes.fromhex(station.replace(":", ""))
    return bytes([0xB0, 0x00, 0x00, 0x00]) + destination + transmitter + destination + b"\x00\x00"


def test_own_station_leaves_the_saved_client_list(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    _remember_ap(store)
    assert store.remember_client_association(BSSID, OURS, observed_at=10.0, force=True)
    assert store.remember_client_association(BSSID, OTHER, observed_at=10.0, force=True)

    assert store.remember_own_station(OURS)
    assert store.is_own_station(OURS)
    assert not store.remember_client_association(BSSID, OURS, observed_at=20.0, force=True)

    macs = {row.client_mac for row in store.clients_for_ap(BSSID)}
    assert macs == {OTHER}
    assert store.aps_for_client(OURS) == []
    assert [row.bssid for row in store.aps_for_client(OTHER)] == [BSSID]

    store.clear()
    assert not store.is_own_station(OURS)
    store.close()


def test_probe_capture_names_the_uplink_station(tmp_path):
    path = tmp_path / "Lab_aa-bb-cc-dd-ee-ff_1_enterprise_probe.pcap"
    writer = PcapWriter(path)
    writer.write(_uplink(OURS))
    writer.write(_uplink(OURS))
    writer.write(_uplink(OTHER))
    writer.close()

    assert dominant_probe_station(path) == OURS


def test_tied_uplink_stations_are_not_guessed(tmp_path):
    path = tmp_path / "tied.pcap"
    writer = PcapWriter(path)
    writer.write(_uplink(OURS))
    writer.write(_uplink(OURS))
    writer.write(_uplink(LONG_LIVED))
    writer.write(_uplink(LONG_LIVED))
    writer.close()

    assert dominant_probe_station(path) is None


def test_import_drops_one_shot_local_macs_on_a_probed_ap(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    _remember_ap(store)
    assert store.remember_client_association(BSSID, OURS, observed_at=10.0, force=True)
    assert store.remember_client_association(BSSID, LONG_LIVED, observed_at=10.0, force=True)
    assert store.remember_client_association(BSSID, LONG_LIVED, observed_at=40.0, force=True)
    assert store.remember_client_association(BSSID, OTHER, observed_at=10.0, force=True)

    captures = tmp_path / "captures"
    captures.mkdir()
    path = captures / "Lab_aa-bb-cc-dd-ee-ff_1_enterprise_probe.pcap"
    writer = PcapWriter(path)
    writer.close()
    assert struct.unpack_from("<I", path.read_bytes(), 0)[0] == 0xA1B2C3D4

    assert store.import_probe_stations(captures) == 1
    macs = {row.client_mac for row in store.clients_for_ap(BSSID)}
    assert OURS not in macs
    assert macs == {LONG_LIVED, OTHER}
    store.close()
