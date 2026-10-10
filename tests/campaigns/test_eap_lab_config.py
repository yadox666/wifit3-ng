from pathlib import Path

from types import SimpleNamespace

from wifit3.campaigns.eap_lab_config import (
    EapLabLaunchConfig,
    advertised_lab_ssid,
    channels_for_lab_iface,
    default_lab_channel,
    distinct_lab_ssid,
    lab_host_ifaces,
    parse_lab_identities,
    read_eap_lab_user,
    resolve_lab_identities,
    resolve_lab_radio,
)
from wifit3.chips.driver import FakeMacSupport


def test_parse_lab_identities_drops_secrets_and_duplicates():
    assert parse_lab_identities(
        "labuser, lab-probe@eap-lab.local, labuser, PASS=secret, token=abc"
    ) == ("labuser", "lab-probe@eap-lab.local")


def test_read_eap_lab_user_ignores_password_keys(tmp_path: Path):
    env = tmp_path / "lab.env"
    env.write_text(
        "LAB_PASS=not-this\n"
        "LAB_USER=labuser\n"
        "LAB_RADIUS_SECRET=also-not\n",
        encoding="utf-8",
    )
    assert read_eap_lab_user(env) == "labuser"


def test_resolve_lab_identities_prefers_dialog_text():
    assert resolve_lab_identities("custom, other") == ("custom", "other")


def test_record_pcap_defaults_on():
    assert EapLabLaunchConfig(timeout=30).record_pcap is True


def test_eviction_defaults_off_for_voluntary_lab_join():
    assert EapLabLaunchConfig(timeout=30).eviction is False


def test_request_client_cert_defaults_off_for_peap_password_path():
    assert EapLabLaunchConfig(timeout=30).request_client_cert is False


def test_inner_pap_probe_defaults_on_for_client_vuln_test():
    assert EapLabLaunchConfig(timeout=30).probe_inner_pap is True


def test_distinct_lab_ssid_is_visible_on_phones():
    assert distinct_lab_ssid("EAP-TEST") == "EAP-TEST-LAB"
    assert advertised_lab_ssid("EAP-TEST", EapLabLaunchConfig(timeout=30)) == "EAP-TEST-LAB"
    same = EapLabLaunchConfig(timeout=30, distinct_ssid=False, lab_ssid="EAP-TEST")
    assert advertised_lab_ssid("EAP-TEST", same) == "EAP-TEST"


def _card(name: str, channels: tuple[int, ...], *, spoofable: bool = True):
    return SimpleNamespace(
        name=name,
        supported_channels=list(channels),
        driver=SimpleNamespace(
            FAKE_MAC=FakeMacSupport.SPOOFABLE if spoofable else FakeMacSupport.NONE
        ),
    )


def test_lab_host_ifaces_are_spoofable_only():
    usable = _card("wlan0", (1, 6, 11))
    other = _card("wlan1", (36, 40), spoofable=False)
    assert lab_host_ifaces((usable, other)) == (usable,)


def test_default_lab_channel_stays_on_target_when_supported():
    card = _card("wlan0", (1, 6, 11))
    assert channels_for_lab_iface(card, 1) == (1, 6, 11)
    assert default_lab_channel(card, 1) == 1
    assert default_lab_channel(card, 36) == 1


def test_resolve_lab_radio_uses_card_and_supported_channel():
    two_g = _card("wlan0", (1, 6, 11))
    five_g = _card("wlan1", (36, 40, 44))
    picked, channel = resolve_lab_radio(
        (two_g, five_g),
        iface_name="wlan1",
        lab_channel=40,
        target_channel=1,
    )
    assert picked is five_g
    assert channel == 40


def test_resolve_lab_radio_clamps_channel_to_the_card():
    two_g = _card("wlan0", (1, 6, 11))
    picked, channel = resolve_lab_radio(
        (two_g,),
        iface_name="wlan0",
        lab_channel=36,
        target_channel=1,
    )
    assert picked is two_g
    assert channel == 1
