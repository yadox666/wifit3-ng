"""Score nearby Wi-Fi attacks from frames the scanner already receives.

One event per BSS (or one flood event), not one event per frame. Frames this
process just transmitted are ignored via the transmit ledger.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

from wifit3.dot11.ie import iter_information_elements
from wifit3.dot11.packet import BeaconPacket, Packet
from wifit3.id.common import vendor_for_mac
from wifit3.wlan.tx_ledger import is_own_transmission, recent_beacon_bssids

_BROADCAST = "ff:ff:ff:ff:ff:ff"
_DEAUTH = 0x0C
_DISASSOC = 0x0A
_BURST_WINDOW_S = 3.0
_BURST_MIN = 10
_SEQ_GAP = 32
_RECONNECT_S = 15.0
# One channel dwell. A normal channel rarely introduces this many new names at once.
_FLOOD_WINDOW_S = 4.0
_FLOOD_MIN = 20
_FLOOD_HIGH = 36
_CHANNEL_WARMUP_S = 12.0
# Normal hopping discovers many SSIDs per channel in the first minutes; not a flood attack.
_SESSION_WARMUP_S = 180.0
_RSSI_DELTA = 18
_MULTI_AP_SSID_PEERS = 2
_COOLDOWN_S = 60.0
_LEVEL_RANK = {"low": 1, "medium": 2, "high": 3}
_CSA = 0x25
_QUIET = 0x28
_ECSA = 0x3C


@dataclass(frozen=True)
class ThreatEvent:
    kind: str
    level: str
    bssid: str
    ssid: str
    channel: int
    title: str
    body: str

    @property
    def severity(self) -> str:
        return "error" if self.level == "high" else "warning"


@dataclass
class _Disconnect:
    at: float
    dest: str
    from_ap: bool
    reason: int | None
    seq: int
    seq_gap: int | None
    protected: bool
    deauth: bool


def notify_threats(notify, events: list[ThreatEvent]) -> None:
    """Show each event once through the app notification bell."""
    for event in events:
        notify(event.body, title=event.title, severity=event.severity, timeout=12)


class ThreatWatcher:
    """Fold parsed frames into scored nearby-threat events."""

    def __init__(self) -> None:
        self._disconnects: dict[str, list[_Disconnect]] = defaultdict(list)
        self._beacon_seq: dict[str, int] = {}
        self._channel: dict[str, int] = {}
        self._ssid_bssids: dict[str, dict[str, tuple[int, str | None]]] = defaultdict(dict)
        self._new_ssids: deque[tuple[float, str, int]] = deque()
        self._channel_first_seen: dict[int, float] = {}
        self._session_started: float | None = None
        self._burst_at: dict[str, float] = {}
        self._announced: dict[tuple[str, str], tuple[int, float]] = {}
        self._pending: list[ThreatEvent] = []

    def drain(self) -> list[ThreatEvent]:
        pending = self._pending
        self._pending = []
        return pending

    def observe(
        self,
        pkt: Packet,
        *,
        pmf_required: bool = False,
        ssid: str | None = None,
        channel: int = 0,
        listening_channel: int = 0,
        own_fake: bool = False,
        own_macs: frozenset[str] = frozenset(),
        same_ssid_peer_count: int = 0,
        now: float | None = None,
    ) -> None:
        moment = time.monotonic() if now is None else now
        if self._session_started is None:
            self._session_started = moment
        raw = pkt.raw or b""
        if raw and is_own_transmission(raw, now=moment):
            return
        bssid = (pkt.bssid or "").casefold()
        if not bssid or bssid == _BROADCAST:
            return
        if pkt.subtype_id in (_DEAUTH, _DISASSOC) or pkt.type == "deauth":
            self._on_disconnect(pkt, bssid, pmf_required, ssid or "", channel, moment)
            return
        if pkt.type == "eapol":
            self._on_eapol(pkt, bssid, ssid or "", channel, own_macs, moment)
            return
        if pkt.type in ("beacon", "probe_resp"):
            self._on_beacon(
                pkt,
                bssid,
                ssid,
                channel,
                listening_channel,
                own_fake,
                same_ssid_peer_count,
                moment,
            )

    def _on_disconnect(
        self,
        pkt: Packet,
        bssid: str,
        pmf_required: bool,
        ssid: str,
        channel: int,
        now: float,
    ) -> None:
        raw = pkt.raw or b""
        protected = len(raw) > 1 and bool(raw[1] & 0x40)
        if protected:
            return
        seq = _seq(raw)
        baseline = self._beacon_seq.get(bssid)
        gap = None if baseline is None else _seq_gap(seq, baseline)
        row = _Disconnect(
            at=now,
            dest=(pkt.dest or "").casefold(),
            from_ap=(pkt.source or "").casefold() == bssid,
            reason=getattr(pkt, "reason", None),
            seq=seq,
            seq_gap=gap,
            protected=False,
            deauth=pkt.subtype_id == _DEAUTH or pkt.type == "deauth",
        )
        rows = [item for item in self._disconnects[bssid] if now - item.at <= _BURST_WINDOW_S]
        rows.append(row)
        self._disconnects[bssid] = rows
        level = _disconnect_level(rows, pmf_required=pmf_required)
        if level is None:
            return
        self._burst_at[bssid] = now
        broadcast = any(item.dest == _BROADCAST for item in rows)
        both = any(item.from_ap for item in rows) and any(not item.from_ap for item in rows)
        kind_word = "Deauth" if any(item.deauth for item in rows) else "Disassoc"
        detail = [f"{len(rows)} frames"]
        if broadcast:
            detail.append("broadcast")
        if both:
            detail.append("both directions")
        if pmf_required:
            detail.append("unprotected on a protected BSS")
        name = ssid or bssid
        where = f"channel {channel}" if channel else "nearby"
        self._emit(ThreatEvent(
            kind="deauth",
            level=level,
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            title=f"{kind_word} burst",
            body=f"{name} ({bssid}), {', '.join(detail)}, {where}",
        ), now)

    def _on_eapol(
        self,
        pkt: Packet,
        bssid: str,
        ssid: str,
        channel: int,
        own_macs: frozenset[str],
        now: float,
    ) -> None:
        burst = self._burst_at.get(bssid)
        if burst is None or now - burst > _RECONNECT_S:
            return
        client = (pkt.client_mac or "").casefold()
        if not client or client in own_macs:
            return
        name = ssid or bssid
        where = f"channel {channel}" if channel else "nearby"
        self._emit(ThreatEvent(
            kind="forced_reconnect",
            level="high",
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            title="Forced reconnect",
            body=f"{name} ({bssid}) had a disconnect burst, then a handshake from {client}, {where}",
        ), now)

    def _on_beacon(
        self,
        pkt: Packet,
        bssid: str,
        ssid: str | None,
        channel: int,
        listening_channel: int,
        own_fake: bool,
        same_ssid_peer_count: int,
        now: float,
    ) -> None:
        if bssid in recent_beacon_bssids(now=now) or own_fake:
            return
        raw = pkt.raw or b""
        seq = _seq(raw)
        previous = self._beacon_seq.get(bssid)
        gap = 0 if previous is None else _seq_gap(seq, previous)
        established = self._channel.get(bssid)
        switch, quiet = _announcements(raw)
        suspicious = previous is not None and gap > _SEQ_GAP and (switch is not None or quiet)
        if suspicious:
            moved = switch is not None and established is not None and switch != established
            if moved:
                name = ssid or bssid
                self._emit(ThreatEvent(
                    kind="channel_switch",
                    level="high",
                    bssid=bssid,
                    ssid=ssid or "",
                    channel=established,
                    title="Channel-switch announcement",
                    body=(
                        f"{name} ({bssid}) advertised a switch to channel {switch} "
                        f"with a sequence jump of {gap}"
                    ),
                ), now)
            elif quiet and switch is None:
                name = ssid or bssid
                self._emit(ThreatEvent(
                    kind="channel_switch",
                    level="medium",
                    bssid=bssid,
                    ssid=ssid or "",
                    channel=established or channel,
                    title="Quiet announcement",
                    body=f"{name} ({bssid}) advertised a quiet period with a sequence jump of {gap}",
                ), now)
        else:
            self._beacon_seq[bssid] = seq
            seen_channel = pkt.channel if isinstance(pkt, BeaconPacket) and pkt.channel else channel
            if seen_channel:
                self._channel[bssid] = seen_channel
        if pkt.type != "beacon":
            self._consider_rogue(pkt, bssid, ssid, same_ssid_peer_count, now)
            return
        self._consider_rogue(pkt, bssid, ssid, same_ssid_peer_count, now)
        seen_channel = self._channel.get(bssid) or channel
        self._consider_flood(bssid, ssid, seen_channel, listening_channel, now)

    def _consider_rogue(
        self,
        pkt: Packet,
        bssid: str,
        ssid: str | None,
        same_ssid_peer_count: int,
        now: float,
    ) -> None:
        name = (ssid or "").strip()
        if not name or name == "<hidden>":
            return
        if same_ssid_peer_count >= _MULTI_AP_SSID_PEERS:
            return
        key = name.casefold()
        known = self._ssid_bssids[key]
        first = bssid not in known
        vendor = vendor_for_mac(bssid)
        rssi = pkt.rssi
        others = {mac: item for mac, item in known.items() if mac != bssid}
        known[bssid] = (rssi, vendor)
        if not first or not others:
            return
        strongest = max(item[0] for item in others.values())
        vendors = {item[1] for item in others.values() if item[1]}
        louder = rssi - strongest >= _RSSI_DELTA
        different_vendor = bool(vendor and vendors and vendor not in vendors)
        if not (louder and different_vendor):
            return
        level = "high"
        self._emit(ThreatEvent(
            kind="rogue_ap",
            level=level,
            bssid=bssid,
            ssid=name,
            channel=pkt.channel or 0 if isinstance(pkt, BeaconPacket) else 0,
            title="Rogue access point",
            body=f"{name} is also advertised by {bssid} at {rssi} dBm",
        ), now)

    def _consider_flood(
        self,
        bssid: str,
        ssid: str | None,
        channel: int,
        listening_channel: int,
        now: float,
    ) -> None:
        name = (ssid or "").strip()
        if not name or name == "<hidden>" or not channel:
            return
        started = self._session_started if self._session_started is not None else now
        if now - started < _SESSION_WARMUP_S:
            return
        # A beacon can bleed into an adjacent tune while advertising another
        # channel. It must not start that channel's warmup or count toward its
        # flood window until a radio is actually listening there.
        if listening_channel and listening_channel != channel:
            return
        first_seen = self._channel_first_seen.setdefault(channel, now)
        if now - first_seen < _CHANNEL_WARMUP_S:
            return
        key = name.casefold()
        if any(item[1] == key for item in self._new_ssids):
            return
        self._new_ssids.append((now, key, channel))
        while self._new_ssids and now - self._new_ssids[0][0] > _FLOOD_WINDOW_S:
            self._new_ssids.popleft()
        count = sum(1 for item in self._new_ssids if item[2] == channel)
        if count < _FLOOD_MIN:
            return
        level = "high" if count >= _FLOOD_HIGH else "medium"
        self._emit(ThreatEvent(
            kind="beacon_flood",
            level=level,
            bssid=bssid,
            ssid="",
            channel=channel,
            title="Beacon flood",
            body=f"{count} new network names on channel {channel} in {_FLOOD_WINDOW_S:.0f}s",
        ), now)

    def _emit(self, event: ThreatEvent, now: float) -> None:
        key = (event.kind, event.bssid if event.kind != "beacon_flood" else "*")
        rank = _LEVEL_RANK[event.level]
        previous = self._announced.get(key)
        if previous is not None:
            old_rank, at = previous
            if rank <= old_rank and now - at < _COOLDOWN_S:
                return
        self._announced[key] = (rank, now)
        self._pending.append(event)


def _disconnect_level(rows: list[_Disconnect], *, pmf_required: bool) -> str | None:
    ap_rows = [item for item in rows if item.from_ap]
    if len(ap_rows) < _BURST_MIN:
        return None
    rows = ap_rows
    if pmf_required:
        return "high"
    broadcast = any(item.dest == _BROADCAST for item in rows)
    both = any(item.from_ap for item in rows) and any(not item.from_ap for item in rows)
    if broadcast or both:
        return "high"
    seq_odd = any(
        item.seq == 0 or (item.seq_gap is not None and item.seq_gap > 64)
        for item in rows
    )
    if seq_odd:
        return "medium"
    return None


def _seq(raw: bytes) -> int:
    if len(raw) < 24:
        return 0
    return (int.from_bytes(raw[22:24], "little") >> 4) & 0xFFF


def _seq_gap(left: int, right: int) -> int:
    gap = (left - right) & 0xFFF
    if gap > 0x800:
        gap = 0x1000 - gap
    return gap


def _announcements(raw: bytes) -> tuple[int | None, bool]:
    if len(raw) < 36:
        return None, False
    switch = None
    quiet = False
    for tag, body, _raw in iter_information_elements(raw, 36):
        if tag == _CSA and len(body) >= 3:
            switch = body[1]
        elif tag == _ECSA and len(body) >= 4:
            switch = body[2]
        elif tag == _QUIET and body:
            quiet = True
    return switch, quiet
