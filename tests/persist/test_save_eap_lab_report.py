import json
from pathlib import Path

from wifit3.campaigns.eap_lab_assessment import ClientOutcome, EapLabClientRecord
from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig
from wifit3.models import AccessPoint
from wifit3.persist import save


def test_save_eap_lab_report_writes_json(tmp_path, monkeypatch):
    monkeypatch.setattr(save.Config, "captures_dir", str(tmp_path))
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="Corp", channel=36)
    launch = EapLabLaunchConfig(timeout=300)
    clients = (
        EapLabClientRecord(
            client_mac="02:11:22:33:44:55",
            outcome=ClientOutcome.INNER_PAP,
            findings=["inner_pap_accepted"],
        ),
    )
    result = save.save_eap_lab_report(
        ap,
        lab_bssid="aa:bb:cc:dd:ee:01",
        launch=launch,
        clients=clients,
        campaign_result="misconfigured",
    )
    assert result is not None
    data = json.loads(Path(result.path).read_text(encoding="utf-8"))
    assert data["report_type"] == "eap_lab_client_assessment"
    assert data["clients"][0]["outcome"] == "inner_pap_accepted"
