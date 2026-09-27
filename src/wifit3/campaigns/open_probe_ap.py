"""Open AP test for one directed probe SSID.

The campaign is deliberately management-only: it advertises an open ESS,
answers stations requesting that ESS, and observes whether they send DHCP. It
never deauthenticates, serves DHCP, or routes traffic.
"""
from __future__ import annotations

import asyncio
import enum
import os
import struct
import time
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
_MAX_OBSERVED_CLIENTS = 64


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
        if self.encryption not in {"OPEN", "WPA2"}:
            raise ValueError(f"Unsupported test AP encryption: {encryption}")
        self.bssid = bssid or self._unused_random_bssid()
        self.rsn_ie = rsn_ie or GENERIC_RSN_IE
        self.rsn_source = rsn_source
        self.profile_ies = profile_ies
        self.bssid_text = mac_to_str(self.bssid)
        self.stats = OpenProbeStats()
        self.result = "no-interface"
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._lease = None
        self._own_ap_registered = False
        if self.encryption == "WPA2":
            self._probe_response = probe_resp(
                self.bssid,
                self.ssid,
                self.channel,
                self.rsn_ie,
                self.profile_ies,
            )
            self._beacon = wpa2_beacon(
                self.bssid,
                self.ssid,
                self.channel,
                self.rsn_ie,
                self.profile_ies,
            )
        else:
            self._probe_response = open_probe_resp(
                self.bssid, self.ssid, self.channel,
            )
            self._beacon = open_beacon(self.bssid, self.ssid, self.channel)

    @property
    def iface(self):
        if self._iface is None and self.array is not None:
            candidates = [
                member
                for member in self.array.members
                if self.channel in member.supported_channels
                and member.driver.FAKE_MAC is FakeMacSupport.SPOOFABLE
            ]
            preferred = self.array.preferred
            self._iface = (
                preferred
                if preferred in candidates
                else min(candidates, key=fake_mac_rank, default=None)
            )
        return self._iface

    async def _loop(self) -> None:
        iface = self.iface
        if iface is None:
            return
        self.result = "running"
        self.started_at = time.monotonic()
        self._event(
            f"Honeypot started · {self.ssid} · CH {self.channel} · "
            f"{iface.name} · {self.encryption} · origin {self.client_text} · "
            f"timeout {int(self.timeout)}s"
        )
        if self.encryption == "WPA2":
            self._event(f"RSN profile · {self.rsn_source}")
        own_ap = self.array.register_own_fake_ap(
            self.bssid_text, self.ssid, self.channel, self.encryption,
        )
        own_ap.last_beacon_frame = self._beacon
        self._own_ap_registered = True
        self._lease = self.array.lease(
            channel=self.channel,
            fake_mac=self.bssid,
            bssid=self.bssid,
            iface=iface,
        )
        async with self.array.claim(iface):
            async with self._lease:
                iface.register_rx_callback(self.on_rx)
                try:
                    deadline = self.started_at + self.timeout
                    while (
                        not self.stopped
                        and time.monotonic() < deadline
                    ):
                        if await iface.send_no_wait(self._restamp(self._beacon)):
                            self.array.record_own_fake_ap_beacon(self.bssid_text)
                        await asyncio.sleep(_BEACON_PERIOD_S)
                finally:
                    iface.unregister_rx_callback(self.on_rx)
        self.finished_at = time.monotonic()
        self.result = self._result_for_phase()

    async def teardown(self) -> None:
        # The lease and claim context managers perform all radio restoration.
        if self._own_ap_registered:
            self.array.finish_own_fake_ap(self.bssid_text)
        self.finished_at = self.finished_at or time.monotonic()
        if self.result == "running":
            self.result = self._result_for_phase()

    def on_rx(self, packet) -> None:
        raw = getattr(packet, "raw", b"")
        if len(raw) < 24:
            return
        source = raw[10:16]
        source_text = mac_to_str(source)
        is_target = source == self.client_mac
        if getattr(packet, "type_id", -1) == 2:
            if raw[4:10] == self.bssid:
                self._on_data(packet, source, source_text, is_target)
            return
        if getattr(packet, "type_id", -1) != 0:
            return
        subtype = getattr(packet, "subtype_id", -1)
        if subtype == 0x04:
            self._on_probe(packet, source, source_text, is_target)
            return
        if raw[4:10] != self.bssid:
            return
        if subtype == 0x0B:
            advanced = self._record_attempt(
                source_text, OpenProbePhase.AUTHENTICATED, "auth", is_target,
            )
            self.stats.auth += 1
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    + (
                        "802.11 Open-System authentication requested "
                        "(WPA2 pending)"
                        if self.encryption == "WPA2"
                        else "802.11 Open-System authentication requested"
                    )
                )
            self._tx(auth_resp(self.bssid, source))
        elif subtype in (0x00, 0x02):
            advanced = self._record_attempt(
                source_text, OpenProbePhase.ASSOCIATED, "assoc", is_target,
            )
            self.stats.assoc += 1
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    + (
                        "WPA2 association requested"
                        if self.encryption == "WPA2"
                        else "associated to open test AP"
                    )
                )
            response = (
                assoc_resp(self.bssid, source, channel=self.channel)
                if self.encryption == "WPA2"
                else open_assoc_resp(self.bssid, source, channel=self.channel)
            )
            self._tx(response)
            if self.encryption == "WPA2":
                m1 = eapol_m1(self.bssid, source, os.urandom(32), replay=1)
                self.array.record_injected_eapol(m1)
                self._tx(m1)

    def _on_probe(
        self, packet, source: bytes, source_text: str, is_target: bool,
    ) -> None:
        ssid = getattr(packet, "ssid", None)
        if ssid not in (None, "", "<hidden>", self.ssid):
            return
        wildcard = ssid in (None, "", "<hidden>")
        previous = self.stats.clients.get(source_text)
        first_of_kind = previous is None or (
            previous.wildcard_probes == 0
            if wildcard
            else previous.directed_probes == 0
        )
        self._record_attempt(
            source_text, OpenProbePhase.PROBED, "probes", is_target,
        )
        attempt = self.stats.clients.get(source_text)
        if attempt is not None:
            if wildcard:
                attempt.wildcard_probes += 1
            else:
                attempt.directed_probes += 1
        self.stats.probes += 1
        if first_of_kind:
            self._event(
                f"{self._role(is_target)} {source_text} · "
                + (
                    "wildcard scan observed"
                    if wildcard
                    else f"directed probe received · {self.ssid}"
                )
            )
        response = self._probe_response[:4] + source + self._probe_response[10:]
        self._tx(response)

    def _on_data(
        self,
        packet,
        source: bytes,
        source_text: str,
        is_target: bool,
    ) -> None:
        attempt = self.stats.clients.get(source_text)
        if attempt is None or attempt.phase < OpenProbePhase.ASSOCIATED:
            return
        if (
            self.encryption == "WPA2"
            and getattr(packet, "type", "") == "eapol"
            and getattr(packet, "msg_num", 0) == 2
        ):
            self.stats.m2 += 1
            advanced = self._record_attempt(
                source_text, OpenProbePhase.EAPOL_M2, "m2", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "WPA2 EAPOL M2 captured"
                )
            return
        message = parse_client_message(packet.raw, source)
        if message == "discover":
            self.stats.dhcp_discover += 1
            advanced = self._record_attempt(
                source_text, OpenProbePhase.DHCP, "dhcp", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "DHCP Discover observed"
                )
        elif message == "request":
            self.stats.dhcp_request += 1
            advanced = self._record_attempt(
                source_text, OpenProbePhase.DHCP, "dhcp", is_target,
            )
            if advanced:
                self._event(
                    f"{self._role(is_target)} {source_text} · "
                    "DHCP Request observed"
                )

    def _event(self, message: str) -> None:
        self.stats.events.append(message)

    def _record_attempt(
        self,
        client_mac: str,
        phase: OpenProbePhase,
        counter: str,
        is_target: bool,
    ) -> bool:
        attempt = self.stats.clients.get(client_mac)
        if attempt is None:
            if len(self.stats.clients) >= _MAX_OBSERVED_CLIENTS:
                return False
            attempt = ClientAttempt(is_target=is_target)
            self.stats.clients[client_mac] = attempt
        setattr(attempt, counter, getattr(attempt, counter) + 1)
        if phase <= attempt.phase:
            return False
        attempt.phase = phase
        self.stats.phase = max(self.stats.phase, phase)
        return True

    @staticmethod
    def _role(is_target: bool) -> str:
        return "ORIGIN" if is_target else "CLIENT"

    def _result_for_phase(self) -> str:
        if self.stats.phase >= OpenProbePhase.DHCP:
            return "dhcp"
        if self.stats.phase >= OpenProbePhase.EAPOL_M2:
            return "handshake"
        if self.stopped:
            return "stopped"
        if self.stats.phase >= OpenProbePhase.ASSOCIATED:
            return "associated"
        if self.stats.phase >= OpenProbePhase.AUTHENTICATED:
            return "authenticated"
        if self.stats.phase >= OpenProbePhase.PROBED:
            return "probe"
        return "timeout"

    def _unused_random_bssid(self) -> bytes:
        observed = getattr(self.array, "access_points", {})
        for _ in range(32):
            candidate = random_bssid()
            if mac_to_str(candidate) not in observed:
                return candidate
        raise RuntimeError("could not generate an unused local BSSID")

    def _tx(self, frame: bytes) -> None:
        asyncio.create_task(self.iface.send_no_wait(frame))

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]
