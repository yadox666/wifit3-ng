"""Low-impact unicast frames for link ACK probing (AntennaTune)."""
from __future__ import annotations

from wifit3.dot11.mac import mac_header
from wifit3.dot11.probe import probe_req


def ap_link_probe_req(ap_bssid: bytes, sta_mac: bytes, ssid: str = "") -> bytes:
    """Directed Probe Request to the AP (expects an immediate Ack from the AP)."""
    return probe_req(ap_bssid, sta_mac, ssid)


def client_link_null(ap_bssid: bytes, client_mac: bytes) -> bytes:
    """FromDS Null data AP → client (expects an Ack from an awake associated STA)."""
    return mac_header(b"\x08\x01", client_mac, ap_bssid, ap_bssid)
