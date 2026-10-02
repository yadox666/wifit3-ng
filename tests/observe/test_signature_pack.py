import json
import struct

import pytest

from tests.wlan.test_parser import _build_beacon
from wifit3.bluetooth.analytics import protocol_type_hint
from wifit3.dot11.parser import WlanFrameParser
from wifit3.observe.remote_id import summarize_remote_id
from wifit3.observe.tracker_state import decode_dult, decode_find_hub


@pytest.fixture
def pack(tmp_path, monkeypatch):
    import wifit3.observe.signature_pack as module

    monkeypatch.setattr(module, "stock_path", lambda: tmp_path / "signatures-stock.json")
    monkeypatch.setattr(module, "user_path", lambda: tmp_path / "signatures-user.json")
    module._install(())
    yield module
    module._install(())


def test_dult_separated_names_the_network_and_alerts():
    state = decode_dult(bytes([0x01, 0x00]))

    assert state is not None
    assert state.protocol_type == "DULT tracker · Separated"
    assert "Apple" in state.detail
    assert state.alert is True


def test_dult_near_owner_stays_quiet():
    state = decode_dult(bytes([0x02, 0x01]))

    assert state is not None
    assert state.protocol_type == "DULT tracker · Near owner"
    assert "Google" in state.detail
    assert state.alert is False


def test_find_hub_frame_types():
    separated = decode_find_hub(b"\x41" + b"\x11" * 20)
    nearby = decode_find_hub(b"\x40" + b"\x22" * 20)
    eddystone = decode_find_hub(b"\x10https://example.test")

    assert separated is not None and separated.alert is True
    assert "about a day" in separated.detail
    assert nearby is not None and nearby.alert is False
    assert eddystone is None


def test_find_hub_replaces_generic_eddystone_and_bare_feaa_does_not(pack):
    separated = protocol_type_hint({}, {"feaa": b"\x41" + b"\x00" * 20}, ("feaa",))
    eddystone = protocol_type_hint({}, {}, ("feaa",))

    assert separated["protocol_type"] == "Find Hub · Separated"
    assert separated["signature_watch"] == "1"
    assert "about a day" in separated["decode_state"]
    assert eddystone["protocol_type"] == "Google Eddystone beacon"
    assert "signature_watch" not in eddystone


def test_remote_id_location_heading_speed_and_pilot():
    location = bytearray(25)
    location[0] = 0x11
    location[1] = 0x20
    location[2] = 90
    location[3] = 16
    location[5:9] = struct.pack("<i", 10_000_000)
    location[9:13] = struct.pack("<i", 20_000_000)
    system = bytearray(25)
    system[0] = 0x41
    system[2:6] = struct.pack("<i", 30_000_000)
    system[6:10] = struct.pack("<i", 40_000_000)
    basic = bytearray(25)
    basic[0] = 0x01
    basic[2:5] = b"ABC"
    pack = bytes([0x04, 0xF1, 25, 3]) + bytes(basic) + bytes(location) + bytes(system)

    report = summarize_remote_id(pack)

    assert report is not None
    assert report.protocol_type == "Remote ID · Airborne"
    assert "90°" in report.summary
    assert "4.0 m/s" in report.summary
    assert "1.00000, 2.00000" in report.summary
    assert "pilot 3.00000, 4.00000" in report.summary
    assert "ID ABC" in report.summary


def test_remote_id_westbound_heading_uses_the_direction_flag():
    message = bytearray(25)
    message[0] = 0x11
    message[1] = 0x02
    message[2] = 10
    report = summarize_remote_id(bytes(message))

    assert report is not None
    assert "190°" in report.summary


def test_beacon_vendor_ie_exposes_remote_id():
    location = bytearray(25)
    location[0] = 0x12
    location[1] = 0x32
    location[2] = 10
    location[3] = 8
    body = b"\xfa\x0b\xbc\x0d\x01\xf1\x19\x01" + bytes(location)
    frame = _build_beacon(ssid="RID-TEST", wpa_vendor_ie=bytes([221, len(body)]) + body)

    parsed = WlanFrameParser.parse_80211_frame(frame, -50)

    assert parsed is not None
    assert parsed.capabilities.remote_id is not None
    assert "Emergency" in parsed.capabilities.remote_id
    assert "190°" in parsed.capabilities.remote_id
    assert parsed.capabilities.signature_watch is True


def test_user_rule_labels_a_name_without_replacing_a_compiled_protocol(pack):
    document = {
        "schema": 1,
        "rules": [{
            "id": "camp-camera",
            "class": "Camera",
            "label": "Camp camera",
            "watch": True,
            "match": {"name_contains": "sparrow"},
        }],
    }
    pack.user_path().write_text(json.dumps(document), encoding="utf-8")
    pack.reload_rules()

    hint = protocol_type_hint({}, {}, (), name="Sparrow Cam")
    ibeacon = protocol_type_hint(
        {0x004C: b"\x02\x15" + b"\x00" * 20}, {}, (), name="Sparrow Cam",
    )

    assert hint["protocol_type"] == "Camp camera"
    assert hint["signature_watch"] == "1"
    assert hint["protocol_category"] == "Camera"
    assert ibeacon["protocol_type"] == "Apple iBeacon"


def test_user_rule_can_point_a_new_uuid_at_the_dult_decoder(pack):
    document = {
        "schema": 1,
        "rules": [{
            "id": "lab-dult",
            "class": "Tracker",
            "label": "Lab tracker",
            "watch": True,
            "decode": "dult",
            "match": {"service_data_uuid": "fc99"},
        }],
    }
    pack.user_path().write_text(json.dumps(document), encoding="utf-8")
    pack.reload_rules()

    hint = protocol_type_hint({}, {"fc99": bytes([0x01, 0x00])}, ())

    assert hint["protocol_type"] == "DULT tracker · Separated"
    assert hint["signature_watch"] == "1"
    assert "Apple" in hint["decode_state"]


def test_import_replaces_user_rules_and_leaves_stock(pack, tmp_path):
    stock = {"schema": 1, "rules": [{
        "id": "stock-camera",
        "class": "Camera",
        "label": "Stock camera",
        "watch": False,
        "match": {"ssid_contains": "yard"},
    }]}
    imported = {"schema": 1, "rules": [{
        "id": "my-camera",
        "class": "Camera",
        "label": "My camera",
        "watch": True,
        "decode": "not-a-decoder",
        "match": {"ssid_contains": "yard"},
    }]}
    pack.stock_path().write_text(json.dumps(stock), encoding="utf-8")
    incoming = tmp_path / "incoming.json"
    incoming.write_text(json.dumps(imported), encoding="utf-8")
    pack.reload_rules()

    status = pack.import_user_pack(incoming)
    notes = pack.describe_wifi("yard-cam", set())

    assert status.ok is True
    assert notes.label == "My camera"
    assert notes.alert is True
    assert "stock-camera" in pack.stock_path().read_text(encoding="utf-8")
    stored = json.loads(pack.user_path().read_text(encoding="utf-8"))
    assert stored["rules"][0]["decode"] == "not-a-decoder"


def test_refresh_stores_a_valid_pack(pack):
    def fetch(_url: str) -> bytes:
        return b'{"schema": 1, "rules": []}'

    status = pack.refresh_stock(fetch=fetch)

    assert status.ok is True
    assert pack.stock_path().is_file()


def test_refresh_download_refuses_a_foreign_redirect():
    import urllib.error
    import urllib.request

    from wifit3.observe.signature_pack import _HostRedirect

    handler = _HostRedirect()
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(
            urllib.request.Request("https://raw.githubusercontent.com/yadox666/wifit3-ng/file"),
            None,
            302,
            "Found",
            {},
            "https://example.test/stock_signatures.json",
        )
