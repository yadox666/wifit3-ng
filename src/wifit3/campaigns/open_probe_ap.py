"""Automated probe honeypot for one directed probe SSID.

The campaign is deliberately management-only: it advertises one or two test
BSSIDs (an open ESS and/or a WPA2-PSK ESS), answers stations requesting that
ESS, and observes whether they authenticate, associate, complete a WPA2 M2 or
send DHCP. It never deauthenticates, serves DHCP, or routes traffic.

It can host both an OPEN and a WPA2 BSSID at once (``encryption="BOTH"``). When
two spoofable cards can reach the channel each BSSID gets its own radio (and its
own hardware ACK); otherwise both BSSIDs share one card, where only the armed
BSSID is hardware-ACKed and the other responds best-effort in software.
"""
from __future__ import annotations

import asyncio
import enum
import os
import struct
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

from wifit3.campaigns.campaign import Campaign
from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.ap import assoc_resp, auth_resp, eapol_m1, open_assoc_resp
from wifit3.dot11.dhcp import parse_client_message
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.mac import mac_to_str, str_to_mac
from wifit3.dot11.probe import (
    open_beacon,
    open_probe_resp,
    probe_resp,
    wpa2_beacon,
)
from wifit3.wlan.array import fake_mac_rank

OPEN_PROBE_TIMEOUT_S = 60.0
_BEACON_PERIOD_S = 100 * 1024 / 1_000_000
# Bound only passive probe/scan observers so a noisy channel cannot grow the
# table without limit. Clients that actually engage (auth/assoc/M2/DHCP) always
# get a row regardless of this cap: this is a honeypot, it must log every victim.
_MAX_OBSERVED_CLIENTS = 512


class OpenProbePhase(enum.IntEnum):
    WAITING = 0
    PROBED = 1
    AUTHENTICATED = 2
    ASSOCIATED = 3
    EAPOL_M2 = 4
    DHCP = 5


@dataclass(slots=True)
class ClientAttempt:
    phase: OpenProbePhase = OpenProbePhase.WAITING
    probes: int = 0
    directed_probes: int = 0
    wildcard_probes: int = 0
    auth: int = 0
    assoc: int = 0
    m2: int = 0
    dhcp: int = 0
    is_target: bool = False


@dataclass(slots=True)
class OpenProbeStats:
    phase: OpenProbePhase = OpenProbePhase.WAITING
    probes: int = 0
    auth: int = 0
    assoc: int = 0
    m2: int = 0
    dhcp_discover: int = 0
    dhcp_request: int = 0
    events: list[str] = field(default_factory=list)
    clients: dict[str, ClientAttempt] = field(default_factory=dict)


def random_bssid() -> bytes:
    """Return a random locally-administered unicast BSSID."""
    return b"\x02" + os.urandom(5)


class _ApEndpoint:
    """One synthetic BSSID the honeypot advertises: its frames and per-AP stats.

    ``iface`` is bound at run time; ``registered`` tracks the AP-list row so
    teardown removes exactly what it created.
    """

    __slots__ = (
        "encryption", "ssid", "channel", "bssid", "bssid_text", "rsn_ie",
        "rsn_source", "profile_ies", "stats", "beacon", "probe_response",
        "iface", "registered",
    )

    def __init__(
        self,
        *,
        encryption: str,
        ssid: str,
        channel: int,
        bssid: bytes,
        rsn_ie: bytes | None,
        rsn_source: str,
        profile_ies: bytes,
        events: list[str],
    ) -> None:
        self.encryption = encryption
        self.ssid = ssid
        self.channel = channel
        self.bssid = bssid
        self.bssid_text = mac_to_str(bssid)
        self.rsn_ie = rsn_ie or GENERIC_RSN_IE
        self.rsn_source = rsn_source
        self.profile_ies = profile_ies
        self.stats = OpenProbeStats()
        # All endpoints share one ordered event stream so the UI log stays coherent.
        self.stats.events = events
        self.iface = None
        self.registered = False
        if encryption == "WPA2":
            self.probe_response = probe_resp(
                bssid, ssid, channel, self.rsn_ie, profile_ies,
            )
            self.beacon = wpa2_beacon(
                bssid, ssid, channel, self.rsn_ie, profile_ies,
            )
        else:
            self.probe_response = open_probe_resp(bssid, ssid, channel)
            self.beacon = open_beacon(bssid, ssid, channel)


class OpenProbeApCampaign(Campaign):
    key = "open-probe-ap"
    idle_label = "Probe Honeypot"
    run_label = "Stop Honeypot"

    def __init__(
        self,
        array,
        client,
        ssid: str,
        channel: int,
        *,
        timeout: float = OPEN_PROBE_TIMEOUT_S,
        bssid: bytes | None = None,
        encryption: str = "OPEN",
        rsn_ie: bytes | None = None,
        rsn_source: str = "generic WPA2",
        profile_ies: bytes = b"",
    ) -> None:
        # Campaign's base selector expects a target carrying ``channel``.
        target = type("_OpenProbeTarget", (), {"channel": channel})()
        super().__init__(target, array)
        self.client = client
        self.client_mac = str_to_mac(client.mac)
        self.client_text = mac_to_str(self.client_mac)
        self.ssid = ssid
        self.channel = channel
        self.timeout = max(1.0, float(timeout))
        self.encryption = encryption.upper()
        self.rsn_ie = rsn_ie or GENERIC_RSN_IE
        self.rsn_source = rsn_source
        self.profile_ies = profile_ies
        self.result = "no-interface"
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._tx_tasks: set[asyncio.Task] = set()
        self._events: list[str] = []
        self._rx_bindings: list[tuple] = []
        self._own_macs: list[bytes] = []

        # Build the endpoint spec list: BOTH → an OPEN + a WPA2 BSSID.
        if self.encryption == "BOTH":
            specs = [
                ("OPEN", None, "OPEN", b""),
                ("WPA2", self.rsn_ie, rsn_source, profile_ies),
            ]
        elif self.encryption in {"OPEN", "WPA2"}:
            specs = [(self.encryption, self.rsn_ie, rsn_source, profile_ies)]
        else:
            raise ValueError(f"Unsupported test AP encryption: {encryption}")

        used: set[str] = set()
        self.endpoints: list[_ApEndpoint] = []
        for index, (enc, ep_rsn, ep_source, ep_profile) in enumerate(specs):
            ep_bssid = bssid if (index == 0 and bssid is not None) else None
            ep_bssid = ep_bssid or self._unused_random_bssid(used)
            used.add(mac_to_str(ep_bssid))
            self.endpoints.append(_ApEndpoint(
                encryption=enc,
                ssid=ssid,
                channel=channel,
                bssid=ep_bssid,
                rsn_ie=ep_rsn,
                rsn_source=ep_source,
                profile_ies=ep_profile,
                events=self._events,
            ))

        # Single-mode public surface (kept identical for callers and tests).
        primary = self.endpoints[0]
        self.stats = primary.stats
        self.bssid = primary.bssid
        self.bssid_text = primary.bssid_text
        self._beacon = primary.beacon
        self._probe_response = primary.probe_response

    @property
    def is_dual(self) -> bool:
        return len(self.endpoints) > 1

    def _spoofable_candidates(self) -> list:
        if self.array is None:
            return []
        return [
            member
            for member in self.array.members
            if self.channel in member.supported_channels
            and member.driver.FAKE_MAC is FakeMacSupport.SPOOFABLE
        ]

    @property
    def iface(self):
        if self._iface is None and self.array is not None:
            candidates = self._spoofable_candidates()
            preferred = self.array.preferred
            self._iface = (
                preferred
                if preferred in candidates
                else min(candidates, key=fake_mac_rank, default=None)
            )
        return self._iface

    def _assign_ifaces(self) -> None:
        """Bind each endpoint to a radio: one per BSSID when two spoofable cards
        can reach the channel (auto), else all BSSIDs share the primary card."""
        primary = self.iface
        candidates = self._spoofable_candidates()
        extras = [c for c in candidates if c is not primary]
        if self.is_dual and extras:
            ifaces = [primary, *extras]
            for endpoint, radio in zip(self.endpoints, ifaces):
                endpoint.iface = radio
        else:
            for endpoint in self.endpoints:
                endpoint.iface = primary

    def _endpoints_by_iface(self) -> dict:
        grouped: dict = {}
        for endpoint in self.endpoints:
            grouped.setdefault(endpoint.iface, []).append(endpoint)
        return grouped

    async def _loop(self) -> None:
        if self.iface is None:
            return
        self._assign_ifaces()
        grouped = self._endpoints_by_iface()
        self.result = "running"
        self.started_at = time.monotonic()
        for endpoint in self.endpoints:
            self._event(
                f"Honeypot started · {endpoint.ssid} · CH {endpoint.channel} · "
                f"{endpoint.iface.name} · {endpoint.encryption} · "
                f"origin {self.client_text} · timeout {int(self.timeout)}s"
            )
            if endpoint.encryption == "WPA2":
                self._event(f"RSN profile · {endpoint.rsn_source}")
            own_ap = self.array.register_own_fake_ap(
                endpoint.bssid_text, endpoint.ssid, endpoint.channel,
                endpoint.encryption,
            )
            own_ap.last_beacon_frame = endpoint.beacon
            endpoint.registered = True
            self.array.register_own_mac(endpoint.bssid)
            self._own_macs.append(endpoint.bssid)

        async with AsyncExitStack() as stack:
            for radio in grouped:
                await stack.enter_async_context(self.array.claim(radio))
            for radio, endpoints in grouped.items():
                # Arm the first BSSID on each radio for a hardware ACK; any other
                # BSSID sharing the radio still transmits, best-effort, in software.
                await stack.enter_async_context(self.array.lease(
                    channel=self.channel,
                    fake_mac=endpoints[0].bssid,
                    bssid=endpoints[0].bssid,
                    iface=radio,
                ))
                callback = self._rx_callback_for(endpoints)
                radio.register_rx_callback(callback)
                self._rx_bindings.append((radio, callback))
            try:
                deadline = self.started_at + self.timeout
                while not self.stopped and time.monotonic() < deadline:
                    for endpoint in self.endpoints:
                        beacon = self._restamp(endpoint.beacon)
                        if await endpoint.iface.send_no_wait(beacon):
                            self.array.record_own_fake_ap_beacon(endpoint.bssid_text)
                    await asyncio.sleep(_BEACON_PERIOD_S)
            finally:
                for radio, callback in self._rx_bindings:
                    radio.unregister_rx_callback(callback)
                self._rx_bindings.clear()
                await self._drain_tx_tasks()
        self.finished_at = time.monotonic()
        self.result = self._result_for_phase()

    async def teardown(self) -> None:
        # The lease and claim context managers perform all radio restoration.
        await self._drain_tx_tasks()
        for radio, callback in self._rx_bindings:
            radio.unregister_rx_callback(callback)
        self._rx_bindings.clear()
        for endpoint in self.endpoints:
            if endpoint.registered:
                self.array.finish_own_fake_ap(endpoint.bssid_text)
        for mac in self._own_macs:
            self.array.unregister_own_mac(mac)
        self._own_macs.clear()
        self.finished_at = self.finished_at or time.monotonic()
        if self.result == "running":
            self.result = self._result_for_phase()

    def _rx_callback_for(self, endpoints):
        def _callback(packet) -> None:
            for endpoint in endpoints:
                self._dispatch(endpoint, packet)
        return _callback

    def on_rx(self, packet) -> None:
        """Public dispatch to every endpoint (single-card path and direct tests)."""
        for endpoint in self.endpoints:
            self._dispatch(endpoint, packet)

    def _dispatch(self, ep: _ApEndpoint, packet) -> None:
        raw = getattr(packet, "raw", b"")
        if len(raw) < 24:
            return
        source = raw[10:16]
        source_text = mac_to_str(source)
        is_target = source == self.client_mac
        if getattr(packet, "type_id", -1) == 2:
            if raw[4:10] == ep.bssid:
                self._on_data(ep, packet, source, source_text, is_target)
            return
        if getattr(packet, "type_id", -1) != 0:
            return
        subtype = getattr(packet, "subtype_id", -1)
        if subtype == 0x04:
            self._on_probe(ep, packet, source, source_text, is_target)
            return
        if raw[4:10] != ep.bssid:
            return
        if subtype == 0x0B:
            advanced = self._record_attempt(
                ep, source_text, OpenProbePhase.AUTHENTICATED, "auth", is_target,
            )
            ep.stats.auth += 1
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    + (
                        "802.11 Open-System authentication requested "
                        "(WPA2 pending)"
                        if ep.encryption == "WPA2"
                        else "802.11 Open-System authentication requested"
                    )
                )
            self._tx(ep, auth_resp(ep.bssid, source))
        elif subtype in (0x00, 0x02):
            advanced = self._record_attempt(
                ep, source_text, OpenProbePhase.ASSOCIATED, "assoc", is_target,
            )
            ep.stats.assoc += 1
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    + (
                        "WPA2 association requested"
                        if ep.encryption == "WPA2"
                        else "associated to open test AP"
                    )
                )
            response = (
                assoc_resp(ep.bssid, source, channel=ep.channel)
                if ep.encryption == "WPA2"
                else open_assoc_resp(ep.bssid, source, channel=ep.channel)
            )
            self._tx(ep, response)
            if ep.encryption == "WPA2":
                m1 = eapol_m1(ep.bssid, source, os.urandom(32), replay=1)
                self.array.record_injected_eapol(m1)
                self._tx(ep, m1)

    def _on_probe(
        self, ep: _ApEndpoint, packet, source: bytes, source_text: str,
        is_target: bool,
    ) -> None:
        ssid = getattr(packet, "ssid", None)
        if ssid not in (None, "", "<hidden>", ep.ssid):
            return
        wildcard = ssid in (None, "", "<hidden>")
        previous = ep.stats.clients.get(source_text)
        first_of_kind = previous is None or (
            previous.wildcard_probes == 0
            if wildcard
            else previous.directed_probes == 0
        )
        self._record_attempt(
            ep, source_text, OpenProbePhase.PROBED, "probes", is_target,
        )
        attempt = ep.stats.clients.get(source_text)
        if attempt is not None:
            if wildcard:
                attempt.wildcard_probes += 1
            else:
                attempt.directed_probes += 1
        ep.stats.probes += 1
        if first_of_kind:
            self._event(
                f"{self._role(is_target)} {source_text} · "
                + (
                    "wildcard scan observed"
                    if wildcard
                    else f"directed probe received · {ep.ssid}"
                )
            )
        response = ep.probe_response[:4] + source + ep.probe_response[10:]
        self._tx(ep, response)

    def _on_data(
        self,
        ep: _ApEndpoint,
        packet,
        source: bytes,
        source_text: str,
        is_target: bool,
    ) -> None:
        attempt = ep.stats.clients.get(source_text)
        if attempt is None or attempt.phase < OpenProbePhase.ASSOCIATED:
            return
        if (
            ep.encryption == "WPA2"
            and getattr(packet, "type", "") == "eapol"
            and getattr(packet, "msg_num", 0) == 2
        ):
            ep.stats.m2 += 1
            advanced = self._record_attempt(
                ep, source_text, OpenProbePhase.EAPOL_M2, "m2", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "WPA2 EAPOL M2 captured"
                )
            return
        message = parse_client_message(packet.raw, source)
        if message == "discover":
            ep.stats.dhcp_discover += 1
            advanced = self._record_attempt(
                ep, source_text, OpenProbePhase.DHCP, "dhcp", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "DHCP Discover observed"
                )
        elif message == "request":
            ep.stats.dhcp_request += 1
            advanced = self._record_attempt(
                ep, source_text, OpenProbePhase.DHCP, "dhcp", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "DHCP Request observed"
                )

    def _event(self, message: str) -> None:
        self._events.append(message)

    def _record_attempt(
        self,
        ep: _ApEndpoint,
        client_mac: str,
        phase: OpenProbePhase,
        counter: str,
        is_target: bool,
    ) -> bool:
        attempt = ep.stats.clients.get(client_mac)
        if attempt is None:
            # Only cap passive probe/scan observers; a client that engaged
            # (auth/assoc/M2/DHCP) is always registered so no victim is dropped.
            if (
                phase <= OpenProbePhase.PROBED
                and len(ep.stats.clients) >= _MAX_OBSERVED_CLIENTS
            ):
                return False
            attempt = ClientAttempt(is_target=is_target)
            ep.stats.clients[client_mac] = attempt
        setattr(attempt, counter, getattr(attempt, counter) + 1)
        if phase <= attempt.phase:
            return False
        attempt.phase = phase
        ep.stats.phase = max(ep.stats.phase, phase)
        return True

    @staticmethod
    def _role(is_target: bool) -> str:
        return "ORIGIN" if is_target else "CLIENT"

    def _result_for_phase(self) -> str:
        phase = max(
            (endpoint.stats.phase for endpoint in self.endpoints),
            default=OpenProbePhase.WAITING,
        )
        if phase >= OpenProbePhase.DHCP:
            return "dhcp"
        if phase >= OpenProbePhase.EAPOL_M2:
            return "handshake"
        if self.stopped:
            return "stopped"
        if phase >= OpenProbePhase.ASSOCIATED:
            return "associated"
        if phase >= OpenProbePhase.AUTHENTICATED:
            return "authenticated"
        if phase >= OpenProbePhase.PROBED:
            return "probe"
        return "timeout"

    def _unused_random_bssid(self, used: set[str] | None = None) -> bytes:
        observed = getattr(self.array, "access_points", {})
        used = used or set()
        for _ in range(64):
            candidate = random_bssid()
            text = mac_to_str(candidate)
            if text not in observed and text not in used:
                return candidate
        raise RuntimeError("could not generate an unused local BSSID")

    def _tx(self, ep: _ApEndpoint, frame: bytes) -> None:
        # Keep a strong reference until completion: a bare create_task may be
        # garbage-collected mid-flight, and teardown drains this set so no
        # response is transmitted after the lease/claim restores the radio.
        radio = ep.iface or self.iface
        task = asyncio.create_task(radio.send_no_wait(frame))
        self._tx_tasks.add(task)
        task.add_done_callback(self._tx_tasks.discard)

    async def _drain_tx_tasks(self) -> None:
        pending = [task for task in self._tx_tasks if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tx_tasks.clear()

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]
