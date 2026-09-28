from wifit3.dot11.dhcp import (
    build_discover,
    build_lab_ack,
    build_lab_offer,
    lab_dhcp_client_ip,
    parse_client_dhcp,
    parse_offer,
)
from wifit3.dot11.mac import str_to_mac

_BSSID = str_to_mac("aa:bb:cc:dd:ee:01")
_CLIENT = str_to_mac("02:11:22:33:44:55")


def test_lab_dhcp_offer_and_ack_roundtrip():
    xid = 0x12345678
    discover = build_discover(_BSSID, _CLIENT, xid)
    parsed = parse_client_dhcp(discover, _CLIENT)
    assert parsed == ("discover", xid)
    offered = lab_dhcp_client_ip(_CLIENT)
    offer = build_lab_offer(_BSSID, _CLIENT, xid, offered_ip=offered)
    lease = parse_offer(offer, xid, _CLIENT)
    assert lease is not None
    assert lease.offered_ip == offered
    ack = build_lab_ack(_BSSID, _CLIENT, xid, offered)
    assert len(ack) > 32
