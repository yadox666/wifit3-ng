"""AntennaTune: live RF / traffic samples for the Focus AntennaTune dialog."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from typing import TYPE_CHECKING

from wifit3.dot11.mac import str_to_mac
from wifit3.ui import focus_model as fm

if TYPE_CHECKING:
    from wifit3.ui.antenna_tune_probe import AntennaTuneSession

SampleProvider = Callable[[], Optional["AntennaTuneSample"]]

_RATE_WINDOW_S = 1.0


def frames_per_second(
    history: deque[tuple[float, dict[str, int]]],
    now: float,
    totals: dict[str, int],
    *,
    window_s: float = _RATE_WINDOW_S,
) -> dict[str, float]:
    """Frames per second over the last ``window_s`` of cumulative counters.

    One frame is 1/s. A short tick must not turn that frame into ``1 / tick``
    (a beacon in a 120 ms sample is not 8 beacons/s). Until the window is
    full, the count so far is still quoted per second of the full window.
    """
    history.append((now, dict(totals)))
    cutoff = now - window_s
    while len(history) > 1 and history[1][0] <= cutoff:
        history.popleft()
    oldest_t, oldest = history[0]
    span = now - oldest_t
    if span <= 0:
        return {key: 0.0 for key in totals}
    divisor = span if span >= window_s else window_s
    rates: dict[str, float] = {}
    for key in set(oldest) | set(totals):
        delta = totals.get(key, 0) - oldest.get(key, 0)
        rates[key] = (delta if delta > 0 else 0) / divisor
    return rates


@dataclass
class AntennaTuneSample:
    """One live reading; the modal diffs ``packet_totals`` across ticks."""

    heading: str
    subheading: str
    dbm: int
    beacon_rate: float | None
    rows: list[fm.DashboardRow]
    packet_totals: dict[str, int]
    tx_frames: int
    ack_total: int
    card_label: str
    probe_sent: int = 0
    probe_acked: int = 0
    probe_mode: str = "idle"
    probe_mac: str = ""
    probe_status: str = ""
    sample_time: float = field(default_factory=time.time)


def resolve_tune_iface(array, channel: int | None, session: AntennaTuneSession | None = None):
    """Card used for AntennaTune TX/RSSI: the dialog pick if it can reach ``channel``."""
    if array is None:
        return None
    picked = getattr(session, "iface", None) if session is not None else None
    supported = getattr(picked, "supported_channels", None) if picked is not None else None
    if picked is not None and (channel is None or supported is None or channel in supported):
        return picked
    if channel is None:
        return None
    return array.select_iface(channel)


def card_signal(target, iface) -> int | None:
    """Per-card RSSI when the sink has heard this adapter; None if unknown."""
    if target is None or iface is None:
        return None
    by_card = getattr(target, "signal_by_card", None) or {}
    for key in (getattr(iface, "name", None), getattr(iface, "chipset", None)):
        if key and key in by_card:
            return by_card[key]
    return None


def _ack_total(array, iface) -> int:
    if array is None or iface is None:
        return 0
    total = 0
    for mac in array.forged_macs:
        try:
            total += iface.acks_seen(str_to_mac(mac))
        except (ValueError, TypeError):
            continue
    return total


def _probe_fields(session: AntennaTuneSession | None) -> dict:
    if session is None or session.probe is None:
        return dict(
            probe_sent=0, probe_acked=0, probe_mode="idle",
            probe_mac="", probe_status="",
        )
    st = session.probe.stats
    return dict(
        probe_sent=st.sent,
        probe_acked=st.acked,
        probe_mode=st.mode,
        probe_mac=st.mac,
        probe_status=st.status,
    )


def ap_sample_provider(
    app,
    beacon_samples,
    session: AntennaTuneSession | None = None,
) -> SampleProvider:
    """Build snapshots for AP Focus from the current target + array."""

    def _sample() -> Optional[AntennaTuneSample]:
        ap = getattr(app, "target_ap", None)
        array = getattr(app, "array", None)
        if ap is None or array is None:
            return None
        display_ssid, _source = fm.display_ssid(ap, array)
        title = display_ssid or "‹hidden›"
        rate, _count = fm.beacon_rate(ap, beacon_samples, time.time())
        iface = resolve_tune_iface(array, ap.channel, session)
        card = "no card"
        tx = 0
        acks = 0
        if iface is not None:
            card = iface.product_name or iface.chipset or iface.name
            tx = iface.transmitted_frames
            acks = _ack_total(array, iface)
        dbm = card_signal(ap, iface)
        if dbm is None:
            dbm = ap.signal
        return AntennaTuneSample(
            heading="AntennaTune",
            subheading=f"{title}  ·  {ap.bssid}  ·  {fm.channel_plain_summary(ap)}",
            dbm=dbm,
            beacon_rate=rate,
            rows=fm.dashboard_rows(ap),
            packet_totals=array.packet_stats.snapshot(ap.bssid),
            tx_frames=tx,
            ack_total=acks,
            card_label=card,
            **_probe_fields(session),
        )

    return _sample


def client_sample_provider(
    app,
    session: AntennaTuneSession | None = None,
) -> SampleProvider:
    """Build snapshots for Client Focus (associated AP traffic when linked)."""

    def _sample() -> Optional[AntennaTuneSample]:
        client = getattr(app, "target_client", None)
        array = getattr(app, "array", None)
        if client is None or array is None:
            return None
        ap = None
        if client.bssid:
            ap = array.access_points.get(client.bssid.lower())
        bssid = fm.client_dashboard_bssid(client, ap)
        rows = fm.client_dashboard_rows(client, ap)
        iface = resolve_tune_iface(array, ap.channel if ap else None, session)
        card = "no card"
        tx = 0
        acks = 0
        if iface is not None:
            card = iface.product_name or iface.chipset or iface.name
            tx = iface.transmitted_frames
            acks = _ack_total(array, iface)
        totals = array.packet_stats.snapshot(bssid) if bssid else {r.key: 0 for r in rows}
        dbm = card_signal(client, iface)
        if dbm is None:
            dbm = client.signal
        if ap is not None:
            sub = f"{client.mac}  ·  on {ap.ssid or '‹hidden›'} ({ap.bssid})"
            beacon_rate = None
        else:
            sub = f"{client.mac}  ·  unassociated"
            beacon_rate = None
        return AntennaTuneSample(
            heading="AntennaTune",
            subheading=sub,
            dbm=dbm,
            beacon_rate=beacon_rate,
            rows=rows,
            packet_totals=totals,
            tx_frames=tx,
            ack_total=acks,
            card_label=card,
            **_probe_fields(session),
        )

    return _sample
