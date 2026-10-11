"""Shared helpers for choosing deauthentication targets on an AP."""
from __future__ import annotations

import time
from typing import Iterable, Optional


def associated_client_macs(
    array,
    ap_bssid: str,
    *,
    exclude_forged: bool = True,
    exclude_fake: bool = False,
    live_within_sec: Optional[float] = None,
    now: Optional[float] = None,
) -> list[str]:
    """MACs associated to ``ap_bssid``, strongest RSSI first (then MAC for stability).

    When ``live_within_sec`` is set, drop stations whose ``last_seen`` is older than that
    window (unless ``is_fake``).
    """
    target = ap_bssid.lower()
    own = array.forged_macs if exclude_forged else set()
    now = time.time() if now is None else now
    rows: list[tuple[int, str]] = []
    for mac, client in array.clients.items():
        if exclude_forged and mac in own:
            continue
        if exclude_fake and getattr(client, "is_fake", False):
            continue
        if (getattr(client, "bssid", None) or "").lower() != target:
            continue
        if live_within_sec is not None and not getattr(client, "is_fake", False):
            if now - getattr(client, "last_seen", 0.0) > live_within_sec:
                continue
        signal = getattr(client, "signal", -100)
        rows.append((signal, mac))
    rows.sort(key=lambda pair: (-pair[0], pair[1].casefold()))
    return [mac for _, mac in rows]


def sort_macs_by_signal(array, macs: Iterable[str]) -> list[str]:
    """Order ``macs`` by current client RSSI (best first); unknown MACs trail."""
    signal_by_mac = {
        mac.casefold(): getattr(client, "signal", -100)
        for mac, client in array.clients.items()
    }
    unique = list(dict.fromkeys(macs))
    unique.sort(
        key=lambda mac: (-signal_by_mac.get(mac.casefold(), -100), mac.casefold()),
    )
    return unique
