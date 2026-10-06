"""Product-family catalog sits beside protocol labels and does not replace them."""
import time
from dataclasses import replace

import pytest

from wifit3.bluetooth.analytics import protocol_type_hint
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models import BluetoothDevice
from wifit3.models.capabilities import AdvertisedCapabilities
from wifit3.observe import product_catalog as catalog
from wifit3.observe.product_catalog import (
    CatalogHit,
    choose_catalog,
    families,
    matching_families,
    match_bluetooth,
    match_wifi,
    prepare_device_catalog,
    supplement_catalog_hit,
)
from wifit3.ui.catalog_format import catalog_chip, catalog_router_markup, catalog_search_text
from wifit3.persist.bluetooth_history import BluetoothHistoryStore

from tests.wlan.test_parser import _build_beacon


@pytest.fixture(autouse=True)
def _stock_catalog_only(monkeypatch, tmp_path):
    path = tmp_path / "product-catalog-user.json"
    monkeypatch.setattr(catalog, "user_catalog_path", lambda: path)
    catalog.reload_catalog()
    yield
    catalog.reload_catalog()


def test_find_my_protocol_stays_while_catalog_names_an_airtag():
    payload = b"\x12\x19" + b"\x00" * 23
    hint = protocol_type_hint({0x004C: payload}, {})
    hit = match_bluetooth({0x004C: payload}, {})

    assert hint["protocol_type"] == "Apple Find My-compatible tracker"
    assert "catalog_labels" not in hint
    assert hit.labels == ("Apple AirTags",)


def test_apple_continuity_name_suppresses_the_airtag_family_only():
    payload = b"\x12\x19" + b"\x00" * 23
    hint = protocol_type_hint({0x004C: payload}, {}, name="iPhone")
    hit = match_bluetooth({0x004C: payload}, {}, name="iPhone")

    assert hint["protocol_type"] == "Apple Find My-compatible tracker"
    assert hit.labels == ("iPhone",)
    assert hit.catalog_class == "Phone"
    assert "Apple AirTags" not in hit.labels
    assert "Apple Device" not in hit.labels


def test_apple_tv_nearby_action_is_not_cataloged_as_a_phone():
    payload = b"\x0f\x02"
    hint = protocol_type_hint({0x004C: payload}, {}, name="Apple TV")
    named = match_bluetooth({0x004C: payload}, {}, name="Apple TV")
    unnamed = match_bluetooth({0x004C: payload}, {}, name="<Unknown>")

    assert hint["protocol_type"] == "Apple Nearby Action device"
    assert "catalog_labels" not in hint
    assert named.labels == ("Apple TV",)
    assert named.catalog_class == "Display"
    assert "Phone" not in named.catalog_class
    assert "Apple Device" not in named.labels
    assert unnamed.labels == ("Apple Device",)
    assert unnamed.catalog_class == "Ambiguous"


def test_sony_le_wf_earbuds_are_not_cataloged_as_epson_printers():
    hit = match_bluetooth({0x012D: b"\x01"}, {}, name="LE_WF-C510")
    assert hit.labels == ("Sony headphones",)
    assert hit.catalog_class == "Audio"
    assert "Epson printer" not in hit.labels


@pytest.mark.parametrize(
    ("name", "label"),
    (
        ("EWA Audio A104", "Speaker"),
        ("KITCHEN SPEAKER", "Speaker"),
        ("portable speaker", "Speaker"),
        ("Galaxy Buds", "Headphones"),
        ("OPPO BUDS", "Headphones"),
        ("Wireless earbuds", "Headphones"),
    ),
)
def test_generic_audio_names_are_cataloged(name, label):
    hit = match_bluetooth({}, {}, name=name)

    assert hit.labels == (label,)
    assert hit.catalog_class == "Audio"


def test_mx_vertical_is_cataloged_as_keyboard_and_mouse():
    hit = match_bluetooth({}, {}, name="MX Vertical")

    assert hit.labels == ("Keyboard and mouse",)
    assert hit.catalog_class == "Peripherals"


def test_gopro_matches_name_gatt_manufacturer_or_service():
    named = match_bluetooth({}, {}, name="GoPro HERO")
    manufacturer = match_bluetooth(
        {},
        {},
        name="<Unknown>",
        gatt_source={"manufacturer_name": "GoPro, Inc."},
    )
    service = match_bluetooth({}, {}, ("fea6",), name="<Unknown>")

    for hit in (named, manufacturer, service):
        assert hit.labels == ("GoPro",)
        assert hit.catalog_class == "Cameras"


def test_ble_mesh_provisioning_service_gets_network_family():
    hit = match_bluetooth({}, {}, ("1827",), name="<Unknown>")
    assert hit.labels == ("Bluetooth Mesh provisioner",)
    assert hit.catalog_class == "Network"


@pytest.mark.parametrize(
    ("service_uuid", "label", "catalog_class"),
    (
        ("110b", "Bluetooth audio output", "Audio"),
        ("1304", "Bluetooth video device", "Display"),
        ("180d", "Health monitor", "Health"),
        ("1816", "Fitness device", "Fitness"),
        ("1812", "Human interface device", "Peripherals"),
        ("181a", "Environmental sensor", "Sensor"),
        ("1116", "Bluetooth network device", "Network"),
        ("1122", "Bluetooth printer", "Printer"),
    ),
)
def test_strong_advertised_services_classify_device(
    service_uuid,
    label,
    catalog_class,
):
    hit = match_bluetooth({}, {}, (service_uuid,), name="<Unknown>")

    assert hit.labels == (label,)
    assert hit.catalog_class == catalog_class


@pytest.mark.parametrize("service_uuid", ("180a", "180f", "1849", "110a"))
def test_generic_or_role_ambiguous_services_do_not_classify(service_uuid):
    hit = match_bluetooth({}, {}, (service_uuid,), name="<Unknown>")

    assert hit.labels == ()
    assert hit.catalog_class == ""


def test_remote_control_service_is_only_a_tv_or_media_candidate():
    candidate = match_bluetooth({}, {}, ("110c",), name="<Unknown>")
    controller_only = match_bluetooth({}, {}, ("110f",), name="<Unknown>")
    known_tv = match_bluetooth({}, {}, ("110c",), name="[TV] Samsung Q80")

    assert candidate.labels == ("TV / media device",)
    assert candidate.catalog_class == "Ambiguous"
    assert controller_only.labels == ()
    assert "Samsung TV" in known_tv.labels
    assert "TV / media device" not in known_tv.labels
    assert known_tv.catalog_class == "Display"


def test_specific_name_family_wins_over_generic_service_family():
    mouse = match_bluetooth({}, {}, ("1812",), name="MX Vertical")
    speaker = match_bluetooth({}, {}, ("110b",), name="EWA Audio A104")

    assert mouse.labels == ("Keyboard and mouse",)
    assert mouse.catalog_class == "Peripherals"
    assert speaker.labels == ("Speaker",)
    assert speaker.catalog_class == "Audio"


def test_samsung_company_id_does_not_make_a_television_a_smarttag():
    samsung = 0x0075
    television = match_bluetooth({samsung: b"\x01"}, {}, name="[TV] Samsung Q80")
    bare = match_bluetooth({samsung: b"\x01"}, {}, name="Samsung")
    tag = match_bluetooth({samsung: b"\x01"}, {}, name="Galaxy SmartTag2")
    unnamed_uuid = match_bluetooth({}, {}, ("fd5a",), name="<Unknown>")
    television_uuid = match_bluetooth({}, {}, ("fd5a",), name="Samsung Smart TV")

    assert television.labels == ("Television", "Samsung TV")
    assert television.catalog_class == "Display"
    assert bare.labels == ()
    assert tag.labels == ("Samsung SmartTags",)
    assert tag.catalog_class == "Finder"
    assert unnamed_uuid.labels == ("Samsung SmartTags",)
    assert television_uuid.labels == ("Samsung TV",)
    stored = type("Previous", (), {
        "catalog_labels": ("Samsung SmartTags",),
        "catalog_class": "Finder",
        "catalog_notes": "",
        "catalog_attention": "",
        "catalog_live": "",
        "catalog_live_strong": False,
        "catalog_sentence": "",
        "name": "[TV] Samsung Q80",
    })()
    assert choose_catalog(CatalogHit(), stored, name="[TV] Samsung Q80").labels == ()
    assert choose_catalog(CatalogHit(), stored, name="Galaxy SmartTag").labels == (
        "Samsung SmartTags",
    )


def test_company_wide_ids_are_not_a_product_and_short_names_stay_whole_words():
    assert match_bluetooth({427: b"\x01"}, {}).labels == ()
    assert match_bluetooth({962: b"\x01"}, {}).labels == ()
    glasses = match_bluetooth({}, {}, name="Ray-Ban Meta")
    assert glasses.labels == ("Ray-Ban / Meta glasses",)
    assert glasses.catalog_class == "Glasses"

    assert match_bluetooth({}, {}, name="Reptile Tracker").labels == ()
    assert match_bluetooth({}, {}, name="Tile").labels == ("Tile Trackers",)

    pairing = match_bluetooth({}, {"fe2c": b"\x01\x02\x03"}, ("fe2c",))
    assert pairing.catalog_class == "Ambiguous"
    assert match_bluetooth({0x08AA: b"\x01"}, {}).catalog_class == "Drone"


def test_airplay_prefix_is_audio_not_a_phone():
    hit = match_bluetooth({0x004C: b"\x0a\x01"}, {})

    assert hit.labels == ("Apple audio",)
    assert hit.catalog_class == "Audio"


def test_airtag_name_keeps_the_family_beside_an_apple_device():
    hit = match_bluetooth(
        {0x004C: b"\x10\x02"},
        {},
        name="AirTag",
    )

    assert "Apple Device" in hit.labels
    assert "Apple AirTags" in hit.labels


def test_penguin_company_is_a_catalog_row_and_not_a_protocol_type():
    hint = protocol_type_hint({0x09C8: b"\x00"}, {}, name="Other")
    hit = match_bluetooth({0x09C8: b"\x00"}, {}, name="Other")

    assert hint == {}
    assert hit.labels == ("Penguin",)
    assert hit.attention


def test_tesla_phone_key_hides_generic_ibeacon_without_changing_the_protocol():
    payload = bytes.fromhex("021574278BDAB64445208F0C720EAF059935") + b"\x00" * 8
    hint = protocol_type_hint({0x004C: payload}, {})
    hit = match_bluetooth({0x004C: payload}, {})

    assert hint["protocol_type"] == "Apple iBeacon"
    assert hit.labels == ("Tesla",)
    assert "iBeacon" not in hit.labels


def test_osmo_model_prefix_wins_over_the_dji_family():
    osmo = match_bluetooth({0x08AA: bytes.fromhex("0600") + b"\x00"}, {})
    aircraft = match_bluetooth({0x08AA: bytes.fromhex("7000") + b"\x00"}, {})

    assert osmo.labels == ("Osmo",)
    assert aircraft.labels == ("DJI",)


def test_find_hub_live_chip_ignores_eddystone_and_keeps_the_protocol_quiet_for_nearby():
    nearby = match_bluetooth({}, {"feaa": b"\x40" + b"\x00" * 8})
    separated = match_bluetooth({}, {"feaa": b"\x41" + b"\x00" * 8})
    eddystone = match_bluetooth({}, {"feaa": b"\x10https://example.test"})
    bare = match_bluetooth({}, {}, ("feaa",))

    assert nearby.labels == ("Google Find Hub",)
    assert nearby.live == "Nearby"
    assert nearby.live_strong is False
    assert "own tag" in nearby.sentence
    assert separated.live == "Separated"
    assert separated.live_strong is True
    assert eddystone.labels == ()
    assert bare.labels == ()


def test_fast_pair_pairing_is_the_strong_chip():
    pairing = match_bluetooth({}, {"fe2c": b"\x01\x02\x03"}, ("fe2c",))
    crowd = match_bluetooth({}, {"fe2c": b"\x00" * 12}, ("fe2c",))

    assert pairing.live == "Fast Pair pairing"
    assert pairing.live_strong is True
    assert crowd.live == "Fast Pair"
    assert crowd.live_strong is False


def test_oppo_phone_wins_over_ambiguous_fast_pair():
    phone = match_bluetooth(
        {},
        {"fe2c": b"\x01\x02\x03"},
        ("fe2c",),
        name="OPPO Reno12",
    )
    generic_phone = match_bluetooth(
        {},
        {"fe2c": b"\x01\x02\x03"},
        ("fe2c",),
        name="OPPO",
    )
    accessory = match_bluetooth(
        {},
        {"fe2c": b"\x01\x02\x03"},
        ("fe2c",),
        name="OPPO Enco Air",
    )

    assert phone.labels == ("OPPO smartphone",)
    assert phone.catalog_class == "Phone"
    assert generic_phone.labels == ("OPPO smartphone",)
    assert generic_phone.catalog_class == "Phone"
    assert accessory.labels == ("Fast Pair",)
    assert accessory.catalog_class == "Ambiguous"


def test_catbint_caterpillar_device_is_a_smartphone():
    named = match_bluetooth(
        {},
        {"fe2c": b"\x01\x02\x03"},
        ("fe2c",),
        name="CATBINT",
        gatt_source={"manufacturer_name": "Caterpillar"},
    )
    gatt_model = match_bluetooth(
        {},
        {},
        name="<Unknown>",
        gatt_source={
            "manufacturer_name": "Caterpillar",
            "model_number": "CATBINT",
        },
    )

    assert named.labels == ("Caterpillar smartphone",)
    assert named.catalog_class == "Phone"
    assert gatt_model.labels == ("Caterpillar smartphone",)
    assert gatt_model.catalog_class == "Phone"


def test_axon_service_data_matches_byte_reversed_marker():
    marker = bytes.fromhex("425743444556494345")
    forward = match_bluetooth({}, {"fe6b": marker})
    reverse = match_bluetooth({}, {"abcd": marker[::-1]})

    assert forward.labels == ("Axon",)
    assert reverse.labels == ("Axon",)


def test_locally_administered_bssid_matches_the_universal_oui():
    hit = match_wifi("", "B6:1E:52:00:00:01", set())

    assert hit.labels == ("Flock Safety Cameras",)


def test_protocol_oui_in_a_vendor_ie_is_not_a_family():
    hit = match_wifi("Cafe", "11:22:33:44:55:66", {"00:50:F2", "00:0F:AC"})

    assert hit.labels == ()


def test_home_router_stock_clues_are_wifi_scoped():
    family = next(item for item in families() if item.id == "home-router-isp")
    assert family.clues
    assert all("Wi‑Fi" in clue for clue in family.clues)


def test_isp_home_router_ssids_do_not_match_ble():
    for name in (
        "MOVISTAR-WIFI6-A250",
        "DIGIFIBRA-C274",
        "Livebox-6A12",
        "Vodafone Station",
        "TP-Link_ABC",
    ):
        hit = match_bluetooth({}, {}, name=name)
        assert hit.labels != ("Home router",)
        assert hit.catalog_class != "Home router"


def test_european_isp_home_router_ssids():
    movistar = match_wifi("MOVISTAR-WIFI6-A250", "11:22:33:44:55:66", set())
    digi = match_wifi("DIGIFIBRA-C274", "11:22:33:44:55:66", set())
    livebox = match_wifi("Livebox-6A12", "11:22:33:44:55:66", set())
    smartbox = match_wifi("SMARTBOX-ABCD", "11:22:33:44:55:66", set())

    assert movistar.labels == ("Home router",)
    assert movistar.catalog_class == "Home router"
    assert digi.labels == ("Home router",)
    assert livebox.labels == ("Home router",)
    assert smartbox.labels == ("Home router",)
    assert match_wifi("WLAN_A1B2C3", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("MiFibra_9F88", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("MiFibra-8441", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("MiFibra-8441-5G", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("MIWIFI_5G_ABCD", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("REDWIFI_1234", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("Sagemcom-F3896LG", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("Lowi-AB12CD", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("Sercomm_ABC123", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("TP-LINK_A1B2", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("TP-Link_5G_Home", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("TP-Link-8441", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("Tenda_123456", "11:22:33:44:55:66", set()).labels == (
        "Home router",
    )
    assert match_wifi("My Cafe WiFi", "11:22:33:44:55:66", set()).labels == ()


def test_field_ssid_clues_from_user_db():
    assert match_wifi("AI-THINKER_018D55", "11:22:33:44:55:66", set()).labels == (
        "Ai-Thinker ESP soft AP",
    )
    assert match_wifi("A17 de Ana", "11:22:33:44:55:66", set()).catalog_class == "Phone"
    assert match_wifi("S23+ de Luis", "11:22:33:44:55:66", set()).catalog_class == "Phone"
    assert match_wifi("[washer]_A1B2", "11:22:33:44:55:66", set()).catalog_class == (
        "Cleaning device",
    )
    assert match_wifi("Samsung Washer", "11:22:33:44:55:66", set()).labels == (
        "Robot vacuum / mop",
    )
    assert match_wifi("Samsung Washer_AB12", "11:22:33:44:55:66", set()).labels == (
        "Robot vacuum / mop",
    )
    assert match_wifi("EnMGMT1A2B-Cloud_ERR", "11:22:33:44:55:66", set()).labels == (
        "EnGenius cloud AP (setup)",
    )
    assert match_wifi("EC520_ABC", "11:22:33:44:55:66", set()).catalog_class == "Printer"
    assert match_wifi("pm_wireless_01", "11:22:33:44:55:66", set()).catalog_class == (
        "Printer",
    )
    assert match_wifi("TP-Link_", "11:22:33:44:55:66", set()).labels == ("Home router",)
    assert match_wifi("S23 Ultra de Maria", "11:22:33:44:55:66", set()).catalog_class == (
        "Phone",
    )
    assert match_wifi("Dash-5574", "11:22:33:44:55:66", set()).catalog_class == "Camera"
    assert match_wifi("B46P-08BB51", "94:ba:06:08:bb:51", set()).labels == (
        "Dashcam Wi-Fi",
    )
    assert match_wifi("YantopCam-ABCDEF", "11:22:33:44:55:66", set()).labels == (
        "Dashcam Wi-Fi",
    )
    assert match_wifi("GPLUSPR_1234", "11:22:33:44:55:66", set()).catalog_class == (
        "Printer",
    )
    assert match_wifi("HS-004716", "11:22:33:44:55:66", set()).catalog_class == "Printer"
    assert match_wifi("iRobot-ROOMBA", "11:22:33:44:55:66", set()).catalog_class == (
        "Cleaning device"
    )
    assert match_wifi("MTDVR1234", "11:22:33:44:55:66", set()).catalog_class == "Camera"
    assert match_wifi("MT-90210", "11:22:33:44:55:66", set()).catalog_class == "Camera"
    assert match_wifi("SNM941-60-ABC", "11:22:33:44:55:66", set()).labels == (
        "Trimble SNM941 gateway",
    )


def test_name_regex_clue_matches_fixed_width_ssid():
    hit = match_wifi("ST-1440LDW", "11:22:33:44:55:66", set())
    assert hit.labels == ("Projector",)
    assert hit.catalog_class == "Display"
    assert match_wifi("PROJ-ROOM-A", "11:22:33:44:55:66", set()).labels == (
        "Projector",
    )
    assert match_wifi("st-1440ldw", "11:22:33:44:55:66", set()).labels == ()


def test_lorawan_lpwan_iot_family():
    rak = match_wifi("RAK7268_A1B2", "11:22:33:44:55:66", set())
    dragino = match_wifi("dragino-a1b2c3", "11:22:33:44:55:66", set())
    kerlink = match_wifi("klk-wifc-1A2B3C", "11:22:33:44:55:66", set())
    sensor = match_bluetooth({}, {}, name="Dragino LHT65")
    uart = match_bluetooth({}, {}, name="HC-06")

    assert rak.labels == ("LoRaWAN / LPWAN",)
    assert rak.catalog_class == "IoT"
    assert dragino.labels == ("LoRaWAN / LPWAN",)
    assert kerlink.labels == ("LoRaWAN / LPWAN",)
    assert sensor.labels == ("LoRaWAN / LPWAN",)
    assert uart.labels == ("LoRaWAN / LPWAN",)


def test_pioneer_car_stereo_ssid():
    hit = match_wifi("SPH-DA77DAB-952", "11:22:33:44:55:66", set())

    assert hit.labels == ("Pioneer car stereo",)
    assert hit.catalog_class == "Vehicle"


def test_byd_bluetooth_name_is_a_vehicle():
    bt_hit = match_bluetooth({}, {}, name="BYD")
    wifi = match_wifi("BYD ATTO 3", "11:22:33:44:55:66", set())

    assert bt_hit.labels == ("BYD vehicle",)
    assert bt_hit.catalog_class == "Vehicle"
    assert wifi.labels == ("BYD vehicle",)
    assert wifi.catalog_class == "Vehicle"


def test_wifi_direct_printer_ssids():
    hp = match_wifi("DIRECT-72-HP OfficeJet Pro 6970", "11:22:33:44:55:66", set())
    epson = match_wifi("DIRECT-1A2B3C4D", "11:22:33:44:55:66", set())
    legacy_hp = match_wifi("HP-Print-9A-Deskjet", "11:22:33:44:55:66", set())

    assert hp.labels == ("Wi-Fi Direct printer",)
    assert hp.catalog_class == "Printer"
    assert epson.labels == ("Wi-Fi Direct printer",)
    assert legacy_hp.labels == ("Wi-Fi Direct printer",)


def test_phone_wifi_tether_ssids():
    android = match_wifi("AndroidAP_4829", "11:22:33:44:55:66", set())
    android_default = match_wifi("AndroidAP", "11:22:33:44:55:66", set())
    custom = match_wifi("Hotspot_7F2A", "11:22:33:44:55:66", set())

    assert android.labels == ("Phone / tablet hotspot",)
    assert android.catalog_class == "Phone"
    assert android_default.catalog_class == "Phone"
    assert match_wifi("AndroidAuto-Guest", "11:22:33:44:55:66", set()).catalog_class == "Vehicle"
    assert custom.labels == ("Phone / tablet hotspot",)
    redmi = match_wifi("Redmi Note 12 Pro", "11:22:33:44:55:66", set())
    assert redmi.catalog_class == "Phone"
    assert match_wifi("Redmi 13C", "11:22:33:44:55:66", set()).catalog_class == "Phone"
    assert match_wifi("Xiaomi 14", "11:22:33:44:55:66", set()).catalog_class == "Phone"

    vag = match_wifi("Hotspot de Audi", "11:22:33:44:55:66", set())
    assert vag.labels == ("VAG infotainment hotspot",)
    assert "Phone / tablet hotspot" not in vag.labels


def test_printer_class_is_searchable():
    rows = matching_families(catalog_class="Printer")
    ids = {family.id for family in rows}
    assert ids == {
        "printer-wifi-direct",
        "epson-printer-ble",
        "service-printer",
    }


def test_cleaning_device_roomba_ssids():
    roomba = match_wifi("Roomba-9A12BC", "11:22:33:44:55:66", set())
    irobot = match_wifi("iRobot-C2D0", "11:22:33:44:55:66", set())
    assert roomba.labels == ("Robot vacuum / mop",)
    assert roomba.catalog_class == "Cleaning device"
    assert irobot.catalog_class == "Cleaning device"


def test_hospitality_venue_wifi_ssids():
    hotel = match_wifi("Gran Hotel Las Palmas", "11:22:33:44:55:66", set())
    apt = match_wifi("APARTAMENTO_4B_WIFI", "11:22:33:44:55:66", set())
    chill = match_wifi("LAVENTURACHILLOUT_PLUS", "11:22:33:44:55:66", set())
    cafe = match_wifi("Cafe del Mar Guests", "11:22:33:44:55:66", set())

    assert hotel.catalog_class == "Hospitality"
    assert hotel.labels == ("Hospitality venue",)
    assert apt.catalog_class == "Hospitality"
    assert chill.catalog_class == "Hospitality"
    assert cafe.catalog_class == "Hospitality"
    assert match_wifi("NORMAL_BURGER", "11:22:33:44:55:66", set()).catalog_class == (
        "Hospitality"
    )
    assert match_wifi("HOTEL_ROOMS_GUEST", "11:22:33:44:55:66", set()).catalog_class == (
        "Hospitality"
    )
    assert match_wifi("WIFI_HABITACIONES", "11:22:33:44:55:66", set()).catalog_class == (
        "Hospitality"
    )
    assert match_wifi("MOVISTAR-WIFI6", "11:22:33:44:55:66", set()).catalog_class != (
        "Hospitality"
    )


def test_securitas_direct_alarm_oui_and_random_ssid():
    hit = match_wifi(
        "Nj87zw5Wcx7v0HEC4ZoVXHaNpKwaXwPO",
        "58:b5:68:5a:c8:c2",
        set(),
    )
    assert hit.labels == ("Securitas Direct / Verisure",)
    assert hit.catalog_class == "Alarm"
    nordic = match_wifi("MyWiFi", "24:C3:F9:11:22:33", set())
    assert nordic.labels == ("Securitas Direct / Verisure",)


def test_offline_db_inspired_wifi_clues():
    assert match_wifi("Iberdrola_ICE_5G", "11:22:33:44:55:66", set()).catalog_class == (
        "Home router"
    )
    assert match_wifi("Share_RENAULT_HotSpot_6212", "11:22:33:44:55:66", set()).labels == (
        "Renault in-car Wi-Fi",
    )
    assert match_wifi("Galaxy S21 babayaga", "11:22:33:44:55:66", set()).catalog_class == "Phone"
    assert match_wifi("70mai_M310_ba15", "11:22:33:44:55:66", set()).catalog_class == "Camera"
    assert match_wifi("DIRECT-0a", "11:22:33:44:55:66", set()).catalog_class == "Printer"


def test_offline_db_inspired_ble_clues():
    tv = match_bluetooth({}, {}, name="[TV] Samsung Q9 Series (55)")
    assert tv.catalog_class == "Display"
    sony = match_bluetooth({}, {}, name="LE_WH-1000XM4")
    assert sony.catalog_class == "Audio"


def test_european_vehicle_wifi_ssids():
    vag = match_wifi("AUDI_AU_1234", "11:22:33:44:55:66", set())
    android = match_wifi("AndroidAuto-Guest", "11:22:33:44:55:66", set())
    uconnect = match_wifi("Uconnect-Jeep", "11:22:33:44:55:66", set())

    assert vag.labels == ("VAG infotainment hotspot",)
    assert android.labels == ("Android Auto Wi-Fi",)
    assert uconnect.labels == ("Stellantis Uconnect",)
    assert match_wifi("VW Golf 8", "11:22:33:44:55:66", set()).labels == (
        "VAG infotainment hotspot",
    )
    assert match_wifi("Hyunday_9F2A", "11:22:33:44:55:66", set()).labels == (
        "Hyundai / Kia in-car Wi-Fi",
    )
    assert match_wifi("Toyota Corolla", "11:22:33:44:55:66", set()).labels == (
        "Toyota in-car Wi-Fi",
    )
    assert match_wifi("MOVISTAR_0CE6", "86:aa:9c:2c:0c:ef", set()).labels == (
        "Home router",
    )


def test_home_router_class_is_searchable():
    rows = matching_families(catalog_class="Home router")
    ids = {family.id for family in rows}
    assert ids == {"home-router-isp"}
    assert "tesla" not in ids


def test_beacon_catalog_does_not_replace_the_signature_label():
    frame = _build_beacon(ssid="Flock-ABC123")
    parsed = WlanFrameParser.parse_80211_frame(frame, -40)

    assert parsed is not None
    assert parsed.capabilities.signature_label is None
    assert parsed.capabilities.catalog_labels == ("Flock Safety Cameras",)
    assert parsed.capabilities.signature_watch is True


def test_capability_merge_keeps_a_family_when_the_next_beacon_has_none():
    current = AdvertisedCapabilities(
        catalog_labels=("Flock Safety Cameras",),
        catalog_class="Surveillance",
        catalog_attention="Roadside camera match.",
        signature_label="Camp camera",
    )
    current.merge(AdvertisedCapabilities(signature_label="Camp camera"))

    assert current.catalog_labels == ("Flock Safety Cameras",)
    assert current.signature_label == "Camp camera"


def test_prepare_device_catalog_uses_last_advertisement_payloads():
    device = BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="<Unknown>",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=2,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=0.0,
    )
    patch = prepare_device_catalog(
        device,
        manufacturer_data={0x004C: bytes.fromhex("1005")},
        service_data={},
    )
    assert patch["catalog_labels"] == ("Apple Device",)


def test_history_keeps_protocol_and_does_not_drop_a_stored_family(tmp_path):
    store = BluetoothHistoryStore(tmp_path / "bluetooth.sqlite3")
    now = time.time()
    first = BluetoothDevice(
        identifier="B4:1E:52:10:20:30",
        name="Flock-1",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(0x09C8,),
        manufacturer_data_bytes=1,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        protocol_type="Flock Safety camera/accessory",
        protocol_category="Sensor",
        catalog_labels=("Flock Safety Cameras", "Penguin"),
        catalog_class="Surveillance",
        catalog_attention="Roadside camera match.",
    )
    assert store.remember(first, force=True)
    later = BluetoothDevice(
        identifier="B4:1E:52:10:20:30",
        name="Flock-1",
        rssi=-48,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(0x09C8,),
        manufacturer_data_bytes=1,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=2,
        advertisement_interval=1.0,
        first_seen=now,
        last_seen=now + 5,
        protocol_type="Flock Safety camera/accessory",
        protocol_category="Sensor",
    )
    assert store.remember(later, force=True)
    restored = BluetoothDevice(
        identifier="B4:1E:52:10:20:30",
        name="<Unknown>",
        rssi=-48,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now + 5,
    )
    store.enrich(restored, classify=False)

    assert restored.protocol_type == "Flock Safety camera/accessory"
    assert restored.catalog_labels == ("Flock Safety Cameras", "Penguin")
    assert restored.name == "Flock-1"
    store.close()


def test_ble_tv_bracket_prefix_is_display():
    generic = match_bluetooth({}, {}, name="[TV] Living room")
    assert generic.catalog_class == "Display"
    assert "Television" in generic.labels
    samsung = match_bluetooth({}, {}, name="[TV] Samsung 8 Series (65)")
    assert samsung.catalog_class == "Display"
    assert "Television" in samsung.labels
    assert "Samsung TV" in samsung.labels
    oled = match_bluetooth({}, {}, name="LG OLED C3 Living room")
    assert oled.catalog_class == "Display"
    assert "Television" in oled.labels
    quoted = match_bluetooth({}, {}, name='55" OLED')
    assert quoted.catalog_class == "Display"
    assert "Television" in quoted.labels


def test_windows_desktop_ble_name_is_computer():
    hit = match_bluetooth({}, {}, name="DESKTOP-JOI2SAP")
    assert hit.catalog_class == "Computer"
    assert "Windows PC" in hit.labels


def test_descodificador_name_is_television():
    hit = match_bluetooth({}, {}, name="Descodificador Orange TV")
    assert hit.catalog_class == "Display"
    assert "Television" in hit.labels


def test_supplement_catalog_uses_ble_television_appearance():
    device = BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="Orange box",
        rssi=-80,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=0.0,
        appearance=0x0A01,
    )
    hit = supplement_catalog_hit(CatalogHit(), device)
    assert hit.catalog_class == "Display"
    assert hit.labels == ("Television",)


def test_catalog_uses_gatt_model_when_advertisement_name_is_generic():
    unnamed_mac = BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="<Unknown>",
        rssi=-50,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=2,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=0.0,
        last_seen=0.0,
        model_number="Mac15,3",
        manufacturer_name="Apple Inc.",
    )
    hit = match_bluetooth(
        {0x004C: b"\x10\x02"},
        {},
        name="<Unknown>",
        gatt_source=unnamed_mac,
    )
    assert hit.catalog_class == "Computer"
    assert "Mac" in hit.labels
    assert "Apple Device" not in hit.labels

    unnamed_phone = replace(
        unnamed_mac,
        model_number="iPhone14,5",
    )
    phone = match_bluetooth(
        {0x004C: b"\x10\x02"},
        {},
        name="iPhone",
        gatt_source=unnamed_phone,
    )
    assert phone.catalog_class == "Phone"
    assert "iPhone" in phone.labels


def test_bluetooth_catalog_matches_common_saved_device_names():
    cases = (
        ("[TV] Samsung 8 Series (65)", "Samsung TV", "Display"),
        ("HUAWEI WATCH FIT 3-2D9", "Huawei wearable", "Wearable"),
        ("HUAWEI Band 9-7A1", "Huawei wearable", "Wearable"),
        ("WH-1000XM4", "Sony headphones", "Audio"),
        ("WH-CH720N", "Sony headphones", "Audio"),
        ("LE_WF-C510", "Sony headphones", "Audio"),
        ("Xiaomi Mi Color S 1837", "Redmi / Xiaomi wearable", "Wearable"),
        ("Epson WF-2910 Series", "Epson printer", "Printer"),
    )
    for name, label, catalog_class in cases:
        hit = match_bluetooth({}, {}, name=name)
        assert label in hit.labels, name
        assert hit.catalog_class == catalog_class, name


def test_stock_families_define_a_catalog_class():
    missing = [family.id for family in families() if not family.catalog_class]
    assert missing == []


def test_catalog_family_select_options_sorted_by_class_then_label():
    from wifit3.observe.product_catalog import (
        catalog_family_select_options,
        families,
    )

    options = catalog_family_select_options()
    assert options[0] == ("All families", "")
    expected = [("All families", "")]
    for family in sorted(
        families(),
        key=lambda item: (
            (item.catalog_class or "").casefold(),
            item.label.casefold(),
            item.id,
        ),
    ):
        cls = family.catalog_class or "·"
        expected.append((f"{cls} - {family.label}", family.id))
    assert options == tuple(expected)


def test_stock_families_are_searchable_without_replacing_protocol_hits():
    names = {family.label for family in families()}
    assert "Flock Safety Cameras" in names
    assert "Penguin" in names
    flock = matching_families("roadside")
    assert [family.id for family in flock] == ["flock-cameras"]
    assert "OUI B4:1E:52" in flock[0].clues
    surveillance = matching_families(catalog_class="Surveillance")
    assert "flock-cameras" in {family.id for family in surveillance}
    assert "apple-airtag" not in {family.id for family in surveillance}

    chip = catalog_chip(type("Hit", (), {
        "catalog_labels": ("Flock Safety Cameras",),
        "catalog_class": "Surveillance",
        "catalog_live": "",
        "catalog_live_strong": False,
        "catalog_attention": "Roadside camera match.",
        "catalog_notes": "",
        "catalog_sentence": "",
    })())
    assert "Flock Safety Cameras" in chip.plain
    assert chip.plain.startswith("◆")
    assert catalog_chip(type("Empty", (), {
        "catalog_labels": (),
        "catalog_class": "",
        "catalog_live": "",
        "catalog_live_strong": False,
        "catalog_attention": "",
        "catalog_notes": "",
        "catalog_sentence": "",
    })()).plain == ""
    markup = catalog_router_markup(type("Hit", (), {
        "catalog_labels": ("Flock Safety Cameras",),
        "catalog_class": "Surveillance",
        "catalog_live": "",
        "catalog_live_strong": False,
        "catalog_attention": "Roadside camera match.",
        "catalog_notes": "",
        "catalog_sentence": "",
    })())
    assert "black on yellow" in markup
    assert catalog_search_text({
        "catalog": {"labels": ["Penguin"], "class": "Surveillance"},
    }) == "Penguin Surveillance"
