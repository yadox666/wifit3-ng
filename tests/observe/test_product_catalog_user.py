import json

import pytest

from wifit3.observe import product_catalog as catalog


@pytest.fixture
def user_catalog_path(tmp_path, monkeypatch):
    path = tmp_path / "product-catalog-user.json"
    monkeypatch.setattr(catalog, "user_catalog_path", lambda: path)
    catalog.reload_catalog()
    yield path
    catalog.reload_catalog()


def test_user_family_overrides_stock_label(user_catalog_path):
    ok, _message = catalog.save_catalog_family({
        "id": "penguin",
        "label": "My Penguin Override",
        "class": "Surveillance",
        "notes": "custom",
        "attention": "",
        "rules": [{"kind": "name_contains", "text": "Penguin"}],
    })
    assert ok
    match = next(f for f in catalog.families() if f.id == "penguin")
    assert match.label == "My Penguin Override"
    assert match.user_owned


def test_hidden_stock_family_is_removed(user_catalog_path):
    catalog.delete_catalog_family("penguin")
    assert not any(f.id == "penguin" for f in catalog.families())


def test_prepare_device_catalog_rematches_on_gatt(user_catalog_path):
    from wifit3.models import BluetoothDevice
    from wifit3.observe.product_catalog import prepare_device_catalog

    catalog.save_catalog_family({
        "id": "iphone-12-pro-max-gatt",
        "label": "iPhone 12 Pro Max (GATT)",
        "class": "Phone",
        "notes": "",
        "attention": "",
        "rules": [{"kind": "gatt_submodel_contains", "text": "iPhone13,4"}],
    })
    device = BluetoothDevice(
        identifier="aa:bb:cc:dd:ee:ff",
        name="<Unknown>",
        rssi=-50,
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
        model_number="iPhone13,4",
        manufacturer_name="Apple Inc.",
    )
    patch = prepare_device_catalog(device)
    assert patch["catalog_labels"] == ("iPhone 12 Pro Max (GATT)",)


def test_gatt_submodel_rule_matches_after_enrichment(user_catalog_path):
    catalog.save_catalog_family({
        "id": "iphone-12-pro-max-gatt",
        "label": "iPhone 12 Pro Max (GATT)",
        "class": "Phone",
        "notes": "",
        "attention": "",
        "rules": [{"kind": "gatt_submodel_contains", "text": "iPhone13,4"}],
    })
    hit = catalog.match_bluetooth(
        {},
        {},
        name="<Unknown>",
        gatt_source={"model_number": "iPhone13,4", "manufacturer_name": "Apple Inc."},
    )
    assert hit.labels == ("iPhone 12 Pro Max (GATT)",)


def test_match_uses_user_family(user_catalog_path):
    catalog.save_catalog_family({
        "id": "lab-gadget",
        "label": "Lab Gadget",
        "class": "Sensor",
        "notes": "",
        "attention": "",
        "rules": [{"kind": "name_contains", "text": "GadgetLab"}],
    })
    hit = catalog.match_bluetooth({}, {}, name="GadgetLab")
    assert hit.labels == ("Lab Gadget",)


def test_catalog_hit_for_family_id():
    hit = catalog.catalog_hit_for_family_id("home-router-isp")
    assert hit.present
    assert hit.catalog_class == "Home router"
    assert hit.labels == ("Home router",)
    assert not catalog.catalog_hit_for_family_id("not-a-real-id").present


def test_name_regex_syntax_error():
    assert catalog.name_regex_syntax_error("(?i)^PROJ[0-9A-Za-z_-]{0,28}$") is None
    assert catalog.name_regex_syntax_error("[invalid") is not None
    assert catalog.name_regex_syntax_error("", "s") == "Pattern is empty"


def test_name_regex_try_worked_examples():
    ok_a, ok_b = catalog.name_regex_try_worked_examples(
        "(?i)^PROJ[0-9A-Za-z_-]{0,28}$",
    )
    assert ok_a is True
    assert ok_b is False
    ok_a, ok_b = catalog.name_regex_try_worked_examples(
        "^ST-[0-9]{4}[A-Z]{3}$",
        "s",
    )
    assert ok_a is False
    assert ok_b is True


def test_manufacturer_clue_matches_bssid_oui(user_catalog_path):
    catalog.save_catalog_family({
        "id": "acme-by-oui",
        "label": "Acme OUI",
        "class": "Other",
        "notes": "",
        "attention": "",
        "rules": [{"kind": "manufacturer", "text": "00:11:22", "radio": "wifi"}],
    })
    hit = catalog.match_wifi("AnySSID", "00:11:22:33:44:55", set())
    assert hit.labels == ("Acme OUI",)


def test_manufacturer_clue_matches_vendor_name(user_catalog_path, monkeypatch):
    from wifit3.id import oui_db

    prior = dict(oui_db.mapping())
    oui_db.install({"001122": "Acme Networks"})
    try:
        catalog.save_catalog_family({
            "id": "acme-by-name",
            "label": "Acme Name",
            "class": "Other",
            "notes": "",
            "attention": "",
            "rules": [{"kind": "manufacturer", "text": "acme networks", "radio": "wifi"}],
        })
        hit = catalog.match_wifi("AnySSID", "00:11:22:aa:bb:cc", set())
        assert hit.labels == ("Acme Name",)
        assert catalog.match_bluetooth(
            {}, {}, mac="00:11:22:33:44:55", name="x",
        ).labels == ()
    finally:
        oui_db.install(prior)


def test_build_rule_dict_manufacturer():
    rule = catalog.build_rule_dict("manufacturer", "Sagemcom", radio="wifi")
    assert rule == {"kind": "manufacturer", "text": "Sagemcom", "radio": "wifi"}
    assert catalog.build_rule_dict("manufacturer", "") is None


def test_build_rule_dict_name_regex():
    rule = catalog.build_rule_dict(
        "name_regex",
        "^PROJ[0-9]+$",
        prefix="s",
        radio="wifi",
    )
    assert rule == {
        "kind": "name_regex",
        "text": "^PROJ[0-9]+$",
        "radio": "wifi",
        "flags": "s",
    }
    assert catalog.build_rule_dict("name_regex", "[invalid") is None


def test_build_rule_dict_company_id():
    rule = catalog.build_rule_dict(
        "manufacturer_id",
        company_id="0x09C8",
    )
    assert rule == {"kind": "manufacturer_id", "company_id": 0x09C8, "radio": ""}


def test_user_catalog_persists(user_catalog_path):
    catalog.save_catalog_family({
        "id": "custom-row",
        "label": "Custom",
        "class": "Other",
        "notes": "note",
        "attention": "look",
        "rules": [{"kind": "name_contains", "text": "Custom"}],
    })
    catalog.reload_catalog()
    stored = json.loads(user_catalog_path.read_text(encoding="utf-8"))
    assert stored["families"][0]["id"] == "custom-row"
    record = catalog.catalog_family_record("custom-row")
    assert record is not None
    assert record["notes"] == "note"
