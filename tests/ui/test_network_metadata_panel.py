import pytest
from textual.app import App, ComposeResult

from wifit3.ui.network_metadata_panel import (
    NetworkMetadataPanel,
    client_network_details,
)
from wifit3.wlan.network_metadata import NetworkMetadata


class _Host(App):
    def compose(self) -> ComposeResult:
        yield NetworkMetadataPanel(id="network")


@pytest.mark.asyncio
async def test_panel_summarizes_and_expands_evidence():
    metadata = NetworkMetadata("aa:bb:cc:dd:ee:ff", "Cafe")
    metadata.add(
        "ipv4_networks", "192.168.8.0/24", source="dhcp_ack",
        confidence="inferred", now=100,
    )
    metadata.add(
        "gateways", "192.168.8.1", source="dhcp_ack",
        confidence="advertised", now=100,
    )
    metadata.add(
        "captive_portals", "https://portal.example", source="http_redirect",
        confidence="observed", now=100,
    )
    for index in range(12):
        metadata.observe_website(
            f"http://site-{index}.example/path",
            hostname=f"site-{index}.example",
            source="http_request", now=101 + index,
            client_mac="02:11:22:33:44:55",
        )
    app = _Host()
    async with app.run_test(size=(100, 24)) as pilot:
        panel = app.query_one("#network", NetworkMetadataPanel)
        panel.set_metadata(metadata, live=True)
        await pilot.pause(0)

        summary = str(panel.query_one(".network-toggle").label)
        assert "PORTAL OBSERVED" in summary
        assert "99%" in summary
        assert "Websites" in summary and "12" in summary
        assert panel.query_one(".network-details").display is False

        await pilot.click(".network-toggle")

        assert panel.expanded is True
        assert panel.query_one(".network-details").display is True
        rendered = str(panel.query_one(".network-details-content").render())
        assert "192.168.8.1" in rendered
        assert "http://site-0.example/path" in rendered
        assert "http://site-11.example/path" in rendered


@pytest.mark.asyncio
async def test_panel_shows_confirmed_internet_and_low_portal_likelihood():
    metadata = NetworkMetadata("aa:bb:cc:dd:ee:ff", "Cafe")
    metadata.add(
        "connectivity", "internet_confirmed",
        source="active_connectivity_probe", confidence="observed", now=100,
    )
    metadata.add(
        "portal_status", "not_detected",
        source="http_204", confidence="observed", now=100,
    )
    app = _Host()
    async with app.run_test(size=(100, 24)) as pilot:
        panel = app.query_one("#network", NetworkMetadataPanel)
        panel.set_metadata(metadata, live=False)
        await pilot.pause(0)

        summary = str(panel.query_one(".network-toggle").label)
        assert "INTERNET" in summary
        assert "NO CAPTIVE PORTAL DETECTED" in summary


def test_client_popup_details_include_client_ip_and_network_evidence():
    mac = "02:11:22:33:44:55"
    metadata = NetworkMetadata("aa:bb:cc:dd:ee:ff", "Cafe")
    for kind, value in (
        ("ipv4_addresses", "192.168.8.42"),
        ("ipv4_networks", "192.168.8.0/24"),
        ("gateways", "192.168.8.1"),
        ("dns_servers", "1.1.1.1"),
        ("websites", "http://example.com/audit"),
        ("connectivity", "internet_confirmed"),
    ):
        metadata.add(
            kind, value, source="test", confidence="observed",
            now=100, client_mac=mac,
        )
    for index in range(12):
        metadata.observe_website(
            f"http://client-{index}.example/path",
            hostname=f"client-{index}.example",
            source="http_request", now=101 + index, client_mac=mac,
        )

    details = client_network_details(metadata, mac)

    assert "NETWORK" in details
    assert "IPv4:" in details and "192.168.8.42" in details
    assert "IPv4 ranges:" in details and "192.168.8.0/24" in details
    assert "Gateways:" in details and "192.168.8.1" in details
    assert "DNS servers:" in details and "1.1.1.1" in details
    assert "Websites (13):" in details
    assert "http://example.com/audit" in details
    assert "http://client-0.example/path" in details
    assert "http://client-11.example/path" in details
    assert "Internet confirmed" in details


def test_client_popup_details_has_clear_empty_state():
    assert "No network observations" in client_network_details(None, "00:11:22:33:44:55")


def test_client_popup_shows_arp_sweep_ipv4():
    metadata = NetworkMetadata("aa:bb:cc:dd:ee:ff", "Cafe")
    mac = "6a:a9:f9:87:7e:d1"
    metadata.observe_arp_neighbors([("192.168.0.84", mac)], now=200)

    details = client_network_details(metadata, mac)

    assert "192.168.0.84" in details
    assert "No network observations" not in details
