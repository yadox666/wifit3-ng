from types import SimpleNamespace

from wifit3.crack.mschapv2 import MsChapV2Capture
from wifit3.ui.eap_lab_runtime import attach_eap_lab_campaign, poll_eap_lab_campaign


def test_focus_and_scanner_each_see_every_event():
    campaign = SimpleNamespace(
        stats=SimpleNamespace(events=["one", "two"]),
        pending_captures=[],
        done=False,
        target_ap=None,
        ap=None,
    )
    app = SimpleNamespace()
    attach_eap_lab_campaign(app, campaign)
    focus, scanner = [], []
    poll_eap_lab_campaign(app, focus.append, listener="focus")
    campaign.stats.events.append("three")
    poll_eap_lab_campaign(app, scanner.append, listener="scanner")
    poll_eap_lab_campaign(app, focus.append, listener="focus")
    assert any("one" in line for line in focus)
    assert any("three" in line for line in focus)
    assert any("one" in line for line in scanner)
    assert any("three" in line for line in scanner)


def test_incomplete_mschap_is_not_sent_to_vault():
    incomplete = MsChapV2Capture(
        username="labuser",
        server_challenge=b"\x01" * 16,
        peer_challenge=b"\x02" * 16,
        nt_response=b"\x00" * 24,
        flags=0,
    )
    campaign = SimpleNamespace(
        stats=SimpleNamespace(events=[]),
        pending_captures=[incomplete],
        done=False,
        target_ap=SimpleNamespace(bssid="aa:bb:cc:dd:ee:ff", ssid="EAP-TEST"),
        ap=None,
        bssid_text="02:15:6d:7c:f1:91",
    )
    saved = []

    class _Vault:
        def save_mschapv2(self, *args, **kwargs):
            saved.append((args, kwargs))
            raise AssertionError("incomplete MS-CHAPv2 must not reach Vault")

    app = SimpleNamespace(vault=_Vault())
    attach_eap_lab_campaign(app, campaign)
    poll_eap_lab_campaign(app, lambda _line: None, listener="focus")
    assert saved == []
    assert campaign.pending_captures == []


def test_inner_pap_credential_is_saved_to_vault(tmp_path, monkeypatch):
    monkeypatch.setattr("wifit3.persist.save.Config.captures_dir", str(tmp_path))
    from wifit3.models import AccessPoint

    ap = AccessPoint(bssid="00:15:6d:7c:f1:90", ssid="EAP-TEST")
    saved_calls = []

    class _Vault:
        def save_captive_password(self, *args, **kwargs):
            saved_calls.append((args, kwargs))
            from wifit3.persist.vault import Vault

            return Vault().save_captive_password(*args, **kwargs)

    campaign = SimpleNamespace(
        stats=SimpleNamespace(events=[]),
        pending_captures=[],
        pending_credentials=[("labuser", "not-a-real-password")],
        done=False,
        target_ap=ap,
        ap=None,
        bssid_text="02:15:6d:7c:f1:91",
        ssid="EAP-TEST-LAB",
    )
    app = SimpleNamespace(vault=_Vault(), notify=lambda *args, **kwargs: None)
    attach_eap_lab_campaign(app, campaign)
    poll_eap_lab_campaign(app, lambda _line: None, listener="focus")
    assert campaign.pending_credentials == []
    assert len(saved_calls) == 1
    assert saved_calls[0][1]["source"] == "eap_lab_inner_pap"
    assert saved_calls[0][1]["lab_bssid"] == "02:15:6d:7c:f1:91"
    assert saved_calls[0][1]["allow_empty_password"] is True
