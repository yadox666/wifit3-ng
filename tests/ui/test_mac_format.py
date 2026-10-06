from rich.text import Text

from types import SimpleNamespace

from wifit3.ui.mac_format import bluetooth_identifier_text, mac_address_text


def test_mac_address_text_disables_emoji_shortcodes() -> None:
    mac = "00:11:22:ab:44:55"
    rendered = mac_address_text(mac)
    assert isinstance(rendered, Text)
    assert str(rendered) == mac
    assert rendered.cell_len == len(mac)


def test_bluetooth_identifier_text_shows_resolved_mac_above_uuid() -> None:
    device = SimpleNamespace(
        identifier="356CF960-45E2-5E8F-DE3B-EDA564085A97",
        ble_mac="AA:BB:CC:DD:EE:FF",
    )
    rendered = bluetooth_identifier_text(device, shortener=lambda value: value[:8])
    assert "AA:BB:CC:DD:EE:FF" in str(rendered)
    assert "356CF960" in str(rendered)


def test_mac_address_text_differs_from_default_emoji_markup() -> None:
    mac = "00:11:22:ab:44:55"
    with_emoji = Text.from_markup(mac)
    without = mac_address_text(mac)
    assert str(with_emoji) != str(without)
    assert str(without) == mac
