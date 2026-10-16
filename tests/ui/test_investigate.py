"""Investigate explains one radio from live beacons, history, and the catalog."""
from types import SimpleNamespace

from wifit3.models import AccessPoint
from wifit3.models.identity import IdKey, IdSource
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.ui.investigate import (
    investigate_ap,
    report_markdown,
    save_investigation_markdown,
)


def test_uptime_within_two_seconds_groups_a_radio_the_address_does_not():
    heard = 1_700_000_000.0
    guest = AccessPoint(
        bssid="02:10:20:30:40:01",
        ssid="LOBBY",
        channel=6,
        last_seen=heard,
        uptime_us=8_000_000_000,
    )
    same = AccessPoint(
        bssid="06:aa:bb:cc:dd:02",
        ssid="LOBBY-5",
        channel=44,
        last_seen=heard + 20,
        uptime_us=8_000_000_000 + 20_000_000,
    )
    other = AccessPoint(
        bssid="06:aa:bb:cc:dd:03",
        ssid="OTHER-OFFICE",
        channel=11,
        last_seen=heard,
        uptime_us=8_000_000_000 + 5_000_000,
    )
    array = SimpleNamespace(
        access_points={guest.bssid: guest, same.bssid: same, other.bssid: other},
        clients={},
        forged_macs=set(),
    )

    text = investigate_ap(guest, array, None).conclusion

    assert "within 2 seconds" in text
    assert "LOBBY-5" in text
    assert "OTHER-OFFICE" not in text


def test_shared_wps_uuid_joins_and_a_placeholder_does_not():
    anchor = AccessPoint(
        bssid="02:10:20:30:40:10",
        ssid="NORTH",
        channel=1,
        wps_uuid_e="a1b2c3d4e5f60718293a4b5c6d7e8f90",
    )
    anchor.identity.set(IdSource.WSC_BEACON, IdKey.SERIAL_NUMBER, "AB12CD34")
    match = AccessPoint(
        bssid="02:99:88:77:66:55",
        ssid="NORTH-IOT",
        channel=36,
        wps_uuid_e="A1B2C3D4-E5F6-0718-293A-4B5C6D7E8F90",
    )
    blank = AccessPoint(
        bssid="02:99:88:77:66:56",
        ssid="BLANK-UUID",
        channel=11,
        wps_uuid_e="0" * 32,
    )
    array = SimpleNamespace(
        access_points={anchor.bssid: anchor, match.bssid: match, blank.bssid: blank},
        clients={},
        forged_macs=set(),
    )

    text = investigate_ap(anchor, array, None).conclusion

    assert "NORTH-IOT" in text
    assert "WPS UUID" in text
    assert "BLANK-UUID" not in text


def test_related_radio_supplies_catalog_when_this_one_has_none():
    guest = AccessPoint(bssid="02:10:20:30:40:20", ssid=None, channel=44)
    history = SimpleNamespace(
        chassis_access_points=lambda _bssid: [{
            "bssid": "00:10:20:30:40:20",
            "ssid": "PIER",
            "channel": 6,
            "encryption": "WPA2",
        }],
        access_point_dossier=lambda bssid: {
            "bssid": "00:10:20:30:40:20",
            "ssid": "PIER",
            "channel": 6,
            "identity": [
                {"field": "MODEL_NAME", "source": "WSC_BEACON", "value": "HX-100"},
                {"field": "SERIAL_NUMBER", "source": "WSC_BEACON", "value": "1234"},
            ],
            "wps": {"locked": True, "version": "2.0"},
            "capabilities": {
                "catalog_class": "Vehicle",
                "catalog_labels": ["Ferry"],
                "catalog_notes": "Ferry default name.",
                "radio_measurement": True,
            },
        } if str(bssid).casefold() == "00:10:20:30:40:20" else None,
    )

    report = investigate_ap(guest, None, history)
    text = report.conclusion

    assert "class is Vehicle" in text
    assert "family is Ferry" in text
    assert "taken from PIER" in text
    assert "a Ferry vehicle" in text
    assert "1234" not in text
    assert "HX-100" in text
    assert "WPS is locked on PIER" in text
    assert "802.11k is advertised on PIER" in text
    assert len(text.split("\n\n")) >= 2


def test_report_saves_markdown(tmp_path):
    ap = AccessPoint(bssid="02:10:20:30:40:30", ssid="NORTH", channel=6)
    report = investigate_ap(ap, None, None)
    document = report_markdown(report)
    path = save_investigation_markdown(report, tmp_path)

    assert document.startswith("# Investigate")
    assert path.is_file()
    assert path.read_text(encoding="utf-8") == document


def test_dossier_reads_catalog_stored_on_a_related_radio(tmp_path):
    store = ApHistoryStore(tmp_path / "history.sqlite3")
    related = AccessPoint(bssid="00:10:20:30:40:40", ssid="PIER", channel=6)
    related.capabilities.catalog_class = "Vehicle"
    related.capabilities.catalog_labels = ("Ferry",)
    related.capabilities.catalog_notes = "Ferry default name."
    related.capabilities.radio_measurement = True
    related.wps = True
    related.wps_locked = True
    related.wps_version = "2.0"
    assert store.remember(related, force=True)

    record = store.access_point_dossier(related.bssid)

    assert record["capabilities"]["catalog_class"] == "Vehicle"
    assert record["capabilities"]["catalog_labels"] == ["Ferry"]
    assert record["wps"]["locked"] is True
    near = {row["bssid"] for row in store.chassis_access_points("02:10:20:30:40:40")}
    assert related.bssid in near
