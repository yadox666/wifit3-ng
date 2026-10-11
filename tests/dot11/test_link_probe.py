"""Link-probe frame builders."""
from wifit3.dot11.link_probe import ap_link_probe_req, client_link_null
from wifit3.dot11.mac import str_to_mac


def test_ap_link_probe_is_directed_mgmt():
    ap = str_to_mac("aa:bb:cc:dd:ee:01")
    sta = str_to_mac("02:11:22:33:44:55")
    frame = ap_link_probe_req(ap, sta, "Test")
    assert frame[0] == 0x40


def test_client_link_null_from_ap():
    ap = str_to_mac("aa:bb:cc:dd:ee:01")
    client = str_to_mac("11:22:33:44:55:66")
    frame = client_link_null(ap, client)
    assert frame[0:2] == b"\x08\x01"
    assert frame[4:10] == client
    assert frame[10:16] == ap
