from pathlib import Path

from wifit3.campaigns.eap_lab_radius_correlate import correlate_probe_with_radius_log


def test_correlate_extracts_peap_failure_diagnosis(tmp_path: Path):
    log = tmp_path / "radiusd.log"
    log.write_text(
        '(47) Received Access-Request Id 44 from 192.168.1.206:2049\n'
        '(47)   Calling-Station-Id = "02-EF-5F-22-B9-DE"\n'
        '(47)   Called-Station-Id = "00-15-6D-7C-F1-90:EAP-TEST"\n'
        '(48) Received Access-Request Id 45 from 192.168.1.206:2049\n'
        '(48)   Calling-Station-Id = "02-EF-5F-22-B9-DE"\n'
        '(48) eap_peap: PEAP state WAITING FOR INNER IDENTITY\n'
        '(48) eap_peap: Received unexpected EAP-Response, rejecting the session.\n'
        '(48) eap_peap: ERROR: Tunneled data is invalid\n'
        '(48) Sent Access-Reject Id 45 from 192.168.1.235:1812\n',
        encoding="utf-8",
    )
    out = correlate_probe_with_radius_log(
        log_path=log,
        client_mac="02:ef:5f:22:b9:de",
        ssid="EAP-TEST",
        started_at=1.0,
        ended_at=2.0,
    )
    assert out is not None
    assert out["diagnosis"] is not None
    assert "invalid inner eap" in out["diagnosis"].lower()
    assert any("Tunneled data is invalid" in line for line in out["highlights"])


def test_correlate_extracts_mschapv2_challenge_from_eap_message(tmp_path: Path):
    log = tmp_path / "radiusd.log"
    log.write_text(
        '(145) Received Access-Request Id 142 from 192.168.1.206:2049\n'
        '(145)   Calling-Station-Id = "02-FC-73-70-D3-B7"\n'
        '(145)   Called-Station-Id = "00-15-6D-7C-F1-90:EAP-TEST"\n'
        '(145) eap_peap: Got tunneled Access-Challenge\n'
        '(145) eap_peap:   EAP-Message = 0x01dd002b1a01dd002610bee8766b074f7aebed2e268e02d67173667265657261646975732d332e322e3130\n'
        '(145) Sent Access-Challenge Id 142 from 192.168.1.235:1812\n',
        encoding="utf-8",
    )
    out = correlate_probe_with_radius_log(
        log_path=log,
        client_mac="02:fc:73:70:d3:b7",
        ssid="EAP-TEST",
        started_at=1.0,
        ended_at=2.0,
    )
    assert out is not None
    assert out["mschap_challenge_hex"] == "bee8766b074f7aebed2e268e02d67173"
    assert "MS-CHAPv2 server challenge" in (out["diagnosis"] or "")
    assert out["requests"][-1]["ssid"] == "EAP-TEST"
    assert out["requests"][-1]["outcome"] == "challenge"


def test_correlate_keeps_per_request_user_names(tmp_path: Path):
    log = tmp_path / "radiusd.log"
    log.write_text(
        '(47) Received Access-Request Id 44 from 192.168.1.206:2049\n'
        '(47)   Calling-Station-Id = "02-EF-5F-22-B9-DE"\n'
        '(47)   User-Name = "anonymous"\n'
        '(47)   Called-Station-Id = "00-15-6D-7C-F1-90:EAP-TEST"\n'
        '(47) Sent Access-Reject Id 44 from 192.168.1.235:1812\n'
        '(48) Received Access-Request Id 45 from 192.168.1.206:2049\n'
        '(48)   Calling-Station-Id = "02-EF-5F-22-B9-DE"\n'
        '(48)   User-Name = "labuser"\n'
        '(48)   Called-Station-Id = "00-15-6D-7C-F1-90:EAP-TEST"\n'
        '(48) eap_peap: Got tunneled Access-Challenge\n'
        '(48) Sent Access-Challenge Id 45 from 192.168.1.235:1812\n',
        encoding="utf-8",
    )
    out = correlate_probe_with_radius_log(
        log_path=log,
        client_mac="02:ef:5f:22:b9:de",
        ssid="EAP-TEST",
        started_at=1.0,
        ended_at=2.0,
    )
    assert out is not None
    assert [item["user_name"] for item in out["requests"]] == ["anonymous", "labuser"]
    assert out["requests"][0]["outcome"] == "reject"
    assert out["requests"][1]["outcome"] == "challenge"
    assert not any("Access-Reject" in line for line in out["requests"][1]["highlights"])
