from wifit3.campaigns.eap_lab_assessment import (
    ClientOutcome,
    EapLabClientRecord,
    is_empty_nt_response,
    order_eap_methods,
)
from wifit3.dot11.eap import EAP_TYPE_PEAP, EAP_TYPE_TLS, EAP_TYPE_TTLS


def test_order_eap_methods_weak_first():
    methods = (EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TYPE_TLS)
    assert order_eap_methods(methods, weak_outer_first=True) == (
        EAP_TYPE_TLS,
        EAP_TYPE_TTLS,
        EAP_TYPE_PEAP,
    )


def test_is_empty_nt_response():
    assert is_empty_nt_response(bytes(24))
    assert not is_empty_nt_response(bytes(24).replace(b"\x00", b"\x01", 1))


def test_client_record_report_pseudonym():
    record = EapLabClientRecord(
        client_mac="02:11:22:33:44:55",
        outcome=ClientOutcome.INNER_PAP,
        findings=["inner_pap_accepted"],
    )
    payload = record.to_report_dict(lab_bssid="aa:bb:cc:dd:ee:ff")
    assert payload["outcome"] == "inner_pap_accepted"
    assert payload["client_id"]
    assert "02:11" not in payload["client_id"]
