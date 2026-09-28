from textual.app import App
from textual.widgets import Button

from wifit3.models import (
    AccessPoint,
    EnterpriseCertificate,
    EnterpriseProbeEvent,
    EnterpriseProbeRun,
    EnterpriseSession,
)
from wifit3.ui.screens.focus_v2.enterprise_panel import (
    EnterprisePanel,
    _infrastructure_summary,
    _system_summary,
)
from wifit3.ui.screens.focus_v2.screen import FocusViewV2


def _enterprise_ap() -> AccessPoint:
    return AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="Corp",
        channel=36,
        encryption="WPA2",
        akms=["EAP"],
        pairwise_ciphers=["CCMP"],
        pmf_capable=True,
    )


def test_enterprise_summary_explains_observations_and_remaining_gaps():
    ap = _enterprise_ap()
    ap.enterprise.server_eap_types.add(25)
    ap.enterprise.client_eap_types.add(25)
    ap.enterprise.nak_eap_types.update({13, 55})
    ap.enterprise.eap_packets = 4
    ap.enterprise.eap_requests = 2
    ap.enterprise.eap_responses = 2
    ap.enterprise.tls_versions.add("TLS 1.2")
    ap.enterprise.tls_client_versions.update({"TLS 1.2", "TLS 1.3"})
    ap.enterprise.tls_client_cipher_suites.add(0x1301)
    ap.enterprise.probe_attempts = 1
    ap.enterprise.probe_last_status = "complete"
    ap.enterprise.probe_last_detail = "outer TLS completed"
    ap.enterprise.probe_last_seen = 2
    ap.enterprise.probe_history.append(EnterpriseProbeRun(
        started_at=1,
        ended_at=2,
        status="complete",
        detail="outer TLS completed",
        association_ok=True,
        eap_method=25,
        events=[EnterpriseProbeEvent(
            timestamp=1.5,
            phase="tls",
            detail="Observed outer TLS metadata",
            direction="local",
        )],
    ))
    ap.enterprise.sessions.append(EnterpriseSession(
        client_id="0123456789abcdef",
        first_seen=1,
        last_seen=2,
        eap_packets=4,
        server_eap_types={25},
        client_eap_types={25},
        outcome="success",
    ))

    summary = _system_summary(ap)

    assert "PEAP" in summary
    assert "EAP-TLS, TEAP" in summary
    assert "TLS 1.2" in summary
    assert "TLS 1.3" in summary
    assert "TLS-AES-128-GCM-SHA256" in summary
    assert "RADIUS certificate" in summary
    assert "0123456789abcdef · passive · success" in summary
    assert "outer TLS completed" in summary
    assert "Latest probe timeline" in summary
    assert "client certificate validation remain unknown" in summary


def test_enterprise_panel_action_is_available_only_for_enterprise_targets():
    screen = FocusViewV2()
    screen._target_ap = _enterprise_ap()
    assert screen.check_action("enterprise", ()) is True

    screen._target_ap = AccessPoint(
        bssid="00:11:22:33:44:55",
        ssid="Personal",
        akms=["PSK"],
    )
    assert screen.check_action("enterprise", ()) is False
    assert any(
        binding.key == "e" and binding.action == "enterprise"
        for binding in FocusViewV2.BINDINGS
    )


def test_infrastructure_summary_correlates_variance_and_radius_pool():
    first = _enterprise_ap()
    second = _enterprise_ap()
    second.bssid = "00:11:22:33:44:55"
    second.channel = 44
    second.pmf_capable = False
    first.enterprise.server_eap_types.add(25)
    second.enterprise.server_eap_types.add(13)
    for ap in (first, second):
        certificate = EnterpriseCertificate(fingerprint="a" * 64)
        ap.enterprise.certificates[certificate.fingerprint] = certificate

    summary = _infrastructure_summary((first, second))

    assert "channels: 36, 44" in summary
    assert "Configuration variance" in summary
    assert "PMF posture differs" in summary
    assert "Shared RADIUS leaf certificate" in summary


async def test_enterprise_panel_exposes_probe_action_and_running_state():
    app = App()
    async with app.run_test() as pilot:
        await app.push_screen(EnterprisePanel([_enterprise_ap()], probing=True))
        await pilot.pause()

        probe = app.screen.query_one("#enterprise-probe", Button)
        assert probe.disabled is False
        assert "cancel" in str(probe.label).lower()
        assert app.screen.query_one("#enterprise-save-report", Button).disabled is False
