"""Logic-only tests for FocusViewV2 state derivations."""

from types import SimpleNamespace
from unittest.mock import patch

from wifit3.dot11.dhcp import DhcpOffer
from wifit3.campaigns.fake_connect import ConnectivityResult
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.persist.network_metadata import NetworkMetadataStore
from wifit3.persist.vault import Vault
from tests.wlan.mocks import build_ap, mock_array
from wifit3.ui import focus_model as fm
from wifit3.campaigns.pmkid import PmkidHarvestAttack
from wifit3.campaigns.deauth import DeauthCampaign
from wifit3.campaigns.eviltwin import EvilTwinCampaign
from wifit3.campaigns.wep import WepCampaign
from wifit3.campaigns.pin import WpsCampaign
from wifit3.ui.screens.focus_v2.screen import FocusViewV2


def test_recovered_wps_psk_shows_in_status():
    """After a WPS PBC/PIN win the recovered PSK lives on the AP; the status headline
    shows a terminal banner instead of decaying back to 'Listening'."""
    ap = build_ap()
    array = mock_array(cards=1)
    ap.wps_pbc_psk = "hunter2"  # as set by a successful PBC capture

    # We pass None for vault as it's unused in this branch of status_headlines
    lines = fm.status_headlines(ap, array, vault=Vault())
    status_text = "".join(lines)
    assert "PSK recovered" in status_text


def test_pmf_required_disables_deauth():
    """A PMF-Required AP refuses unauthenticated deauth."""
    ap = build_ap()
    ap.pmf_required = True

    # DeauthCampaign block reason should be non-empty (truthy) when blocked
    blocked = fm.deauth_blocked(ap)
    assert blocked is True, "PMF Required AP should block deauth"


def test_campaign_visibility_for_wpa2():
    """The attack buttons are encryption-conditional. For a WPA2 AP (no WPS, not WPA3): 
    PMKID + Deauth + EvilTwin apply. The rest hide."""
    ap = build_ap(encryption="WPA2")
    ap.wpa3 = False
    ap.wps = False

    # These should be visible
    assert PmkidHarvestAttack.visible(ap) is True
    assert DeauthCampaign.visible(ap) is True
    assert EvilTwinCampaign.visible(ap) is True

    # These should be hidden
    assert WepCampaign.visible(ap) is False
    assert WpsCampaign.visible(ap) is False


def test_fake_connect_offer_updates_network_database_without_pcap(tmp_path):
    screen = FocusViewV2()
    history = ApHistoryStore(tmp_path / "history.sqlite3")
    store = NetworkMetadataStore(
        history, "b4:0f:3b:14:fc:64", "Tenda_14FC60",
    )
    screen._network_store = store
    campaign = SimpleNamespace(
        dhcp_offer=DhcpOffer(
            offered_ip="192.168.0.161",
            server="192.168.0.1",
            subnet_mask="255.255.255.0",
            routers=("192.168.0.1",),
            dns_servers=("192.168.0.1", "192.168.0.1"),
            domain=None,
            portal=None,
            lease_seconds=3600,
        ),
        client_mac="02:11:bc:5e:ec:2c",
        metadata_recorded=False,
        dhcp_lease=None,
        lease_recorded=False,
        connectivity_result=ConnectivityResult(
            status="internet_confirmed",
            checked_at=1000,
            detail="Expected HTTP 204 received",
            gateway="192.168.0.1",
            gateway_reachable=True,
            dns_server="192.168.0.1",
            dns_reachable=True,
            tcp_reachable=True,
            http_status=204,
        ),
        connectivity_recorded=False,
    )

    with patch.object(screen, "_refresh_network_metadata"):
        screen._record_fake_connect_offer(campaign)

    payload = history.network_metadata_payload("b4:0f:3b:14:fc:64")
    assert payload["facts"]["ipv4_networks"][0]["value"] == "192.168.0.0/24"
    assert payload["facts"]["gateways"][0]["value"] == "192.168.0.1"
    assert payload["facts"]["dns_servers"][0]["value"] == "192.168.0.1"
    assert payload["clients"]["02:11:bc:5e:ec:2c"]["facts"][
        "ipv4_addresses"
    ][0]["value"] == "192.168.0.161"
    assert payload["facts"]["connectivity"][0]["value"] == "internet_confirmed"
    assert campaign.metadata_recorded is True
    assert campaign.connectivity_recorded is True
