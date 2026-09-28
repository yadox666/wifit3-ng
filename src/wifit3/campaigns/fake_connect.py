"""Temporary open-system association used to stimulate otherwise-idle open APs."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from wifit3.dot11 import mac_to_str, random_client_mac, str_to_mac
from wifit3.dot11.connectivity import (
    TCP_ACK,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    build_arp_request,
    build_dns_query,
    build_tcp_frame,
    parse_arp_reply,
    parse_dns_response,
    parse_http_response,
    parse_tcp_segment,
    random_ephemeral_port,
)
from wifit3.dot11.dhcp import (
    DhcpOffer,
    build_discover,
    build_release,
    build_request,
    parse_ack,
    parse_offer,
    random_xid,
)

from .auth_assoc import Association, build_client_leaving
from .campaign import Campaign

logger = logging.getLogger(__name__)

CONNECTIVITY_HOST = "connectivitycheck.gstatic.com"
CONNECTIVITY_PATH = "/generate_204"
CONNECTIVITY_URL = f"http://{CONNECTIVITY_HOST}{CONNECTIVITY_PATH}"
MAX_HTTP_HEADER_BYTES = 8192


@dataclass(slots=True)
class ConnectivityResult:
    status: str
    checked_at: float
    detail: str
    gateway: str | None = None
    gateway_reachable: bool = False
    dns_server: str | None = None
    dns_reachable: bool = False
    tcp_reachable: bool = False
    http_status: int | None = None
    portal_origin: str | None = None
    gateway_mac: bytes | None = field(default=None, repr=False)


class _PacketInbox:
    """Bounded thread-safe packet handoff for a short active probe."""

    def __init__(self, iface):
        self.iface = iface
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=256)

    def _rx(self, packet) -> None:
        raw = bytes(getattr(packet, "raw", b""))
        if raw:
            self.loop.call_soon_threadsafe(self._put, raw)

    def _put(self, raw: bytes) -> None:
        if not self.queue.full():
            self.queue.put_nowait(raw)

    def start(self) -> None:
        self.iface.register_rx_callback(self._rx)

    def stop(self) -> None:
        self.iface.unregister_rx_callback(self._rx)

    async def match(self, parser, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                raw = await asyncio.wait_for(self.queue.get(), remaining)
            except asyncio.TimeoutError:
                return None
            result = parser(raw)
            if result is not None:
                return result


class _DhcpProbe:
    """Thread-safe handoff from driver RX callbacks to one DHCP probe."""

    def __init__(self, iface, bssid: str, client_mac: bytes, xid: int):
        self.iface = iface
        self.bssid = bssid.casefold()
        self.client_mac = client_mac
        self.xid = xid
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[DhcpOffer] = asyncio.Queue(maxsize=1)
        self._seen = False

    def _rx(self, packet) -> None:
        if (getattr(packet, "bssid", "") or "").casefold() != self.bssid:
            return
        offer = parse_offer(getattr(packet, "raw", b""), self.xid, self.client_mac)
        if offer is not None and not self._seen:
            self._seen = True
            self.loop.call_soon_threadsafe(self.queue.put_nowait, offer)

    def start(self) -> None:
        self.iface.register_rx_callback(self._rx)

    def stop(self) -> None:
        self.iface.unregister_rx_callback(self._rx)

    async def wait(self, timeout: float) -> DhcpOffer | None:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout)
        except asyncio.TimeoutError:
            return None


class FakeConnectCampaign(Campaign):
    """Associate a temporary client with an OPEN or WEP AP until disconnected."""

    button_id = "btn-fake-connect"
    key = "fake_connect"
    hotkey = None
    stoppable = True
    idle_label = "Fake-Connect"
    run_label = "Disconnect"
    idle_variant = "primary"
    run_variant = "error"

    def __init__(self, array, target, source_mac: bytes | None = None, log=None):
        super().__init__(ap=target, array=array)
        self.target = target
        cache = getattr(array, "_fake_connect_macs", None)
        if cache is None:
            cache = {}
            array._fake_connect_macs = cache
        if source_mac is None:
            source_mac = cache.setdefault(target.bssid.casefold(), random_client_mac())
        self.source_mac = source_mac
        self.log = log or (lambda _message: None)
        self.association_only = (
            (getattr(target, "encryption", "") or "").casefold() == "wep"
        )
        self.association_ssid, self.ssid_is_guess = self._association_ssid(array, target)
        self.associated = False
        self.fail_reason: Optional[str] = None
        self.dhcp_offer: DhcpOffer | None = None
        self.dhcp_lease: DhcpOffer | None = None
        self.connectivity_result: ConnectivityResult | None = None
        self.dhcp_probing = False
        self.metadata_recorded = False
        self.lease_recorded = False
        self.connectivity_recorded = False
        self._dhcp_xid: int | None = None
        self._fake_client_registered = False

    @property
    def client_mac(self) -> str:
        return mac_to_str(self.source_mac)

    @classmethod
    def visible(cls, ap) -> bool:
        encryption = (getattr(ap, "encryption", "") or "").casefold()
        return encryption == "wep" or (
            encryption == "open" and not getattr(ap, "akm_suites", ())
        )

    @classmethod
    def ineligible_reason(cls, ap) -> Optional[str]:
        if ap.is_hidden and not getattr(ap, "siblings", ()):
            return "hidden SSID: no confirmed or sibling-derived name"
        return None

    @staticmethod
    def _association_ssid(array, target) -> tuple[str, bool]:
        if target.ssid:
            return target.ssid, False
        strongest = None
        strongest_beacons = -1
        for bssid in getattr(target, "siblings", ()):
            sibling = array.access_points.get(bssid)
            if sibling and sibling.ssid and sibling.beacons > strongest_beacons:
                strongest = sibling.ssid
                strongest_beacons = sibling.beacons
        return (strongest or "", bool(strongest))

    def status_under_card(self) -> str:
        return "● Fake-Connect"

    def status_headlines(self, vault) -> list[str]:
        if self.associated:
            if self.association_only:
                network = "WEP association only · data requires the key"
            elif self.connectivity_result is not None:
                network = self.connectivity_result.detail
            elif self.dhcp_lease is not None:
                network = "testing Internet connectivity"
            elif self.dhcp_offer is not None:
                network = "requesting temporary DHCP lease"
            else:
                network = (
                    "requesting DHCP Offer"
                    if self.dhcp_probing else "no DHCP Offer observed"
                )
            return [
                "[bold green]● Fake client associated[/bold green]",
                f"[dim]{self.client_mac} · SSID {self.association_ssid}"
                f"{' [sibling guess]' if self.ssid_is_guess else ''} "
                f"· {network}[/dim]",
            ]
        if self.fail_reason:
            return [
                "[bold red]● Fake-Connect failed[/bold red]",
                f"[dim]{self.fail_reason}[/dim]",
            ]
        return [
            "[bold cyan]● Fake-Connect[/bold cyan]",
            f"[dim]authenticating as {self.client_mac}[/dim]",
        ]

    async def _loop(self) -> None:
        self.fail_reason = None
        if not self.association_ssid:
            self.fail_reason = "no usable SSID is known"
            return
        bssid = str_to_mac(self.target.bssid)
        async with self.array.lease(channel=self.target.channel, iface=self.iface) as iface:
            arm = self.array.lease(fake_mac=self.source_mac, bssid=bssid, iface=iface)
            async with arm:
                if arm.mac:
                    self.source_mac = str_to_mac(arm.mac)
                    self.array._fake_connect_macs[
                        self.target.bssid.casefold()
                    ] = self.source_mac
                assoc = Association(
                    iface,
                    self.target.bssid,
                    self.association_ssid,
                    self.target.channel,
                    our_mac=self.source_mac,
                    privacy=self.association_only,
                    should_stop=lambda: self.stopped,
                )
                assoc.start()
                try:
                    self.log(
                        f"Open auth → association to [cyan]{self.association_ssid}[/cyan] "
                        f"{'[black bold on yellow] SIBLING GUESS [/black bold on yellow] ' if self.ssid_is_guess else ''}"
                        f"[dim](client MAC: {self.client_mac})[/dim]"
                    )
                    if not await assoc.associate(attempts=3):
                        self.fail_reason = assoc.fail_reason or "association timed out"
                        return
                    self.associated = True
                    register = getattr(self.array, "register_fake_client", None)
                    if register is not None:
                        register(self.source_mac, self.target.bssid)
                        self._fake_client_registered = True
                    if self.association_only:
                        self.log(
                            "[bold green]Associated[/bold green] · "
                            "[yellow]WEP association only[/yellow] "
                            "[dim](network data requires the WEP key)[/dim]"
                        )
                    else:
                        self.log(
                            "[bold green]Associated[/bold green] · passively observing "
                            "traffic generated by the AP"
                        )
                        self.dhcp_offer = await self._discover_dhcp(iface, bssid)
                        if self.dhcp_offer is not None:
                            self.log(
                                "[bold green]DHCP Offer[/bold green] · "
                                f"{self.dhcp_offer.summary()} "
                                "[dim](requesting temporary lease)[/dim]"
                            )
                            self.connectivity_result = await self._probe_connectivity(
                                iface, bssid, self.dhcp_offer,
                            )
                        else:
                            self.log(
                                "[yellow]No DHCP Offer observed[/yellow] "
                                "[dim](association remains active)[/dim]"
                            )
                    while not self.stopped and assoc.associated:
                        await asyncio.sleep(0.1)
                    if not self.stopped:
                        self.fail_reason = assoc.fail_reason or "AP disconnected the client"
                finally:
                    if self.associated and assoc.associated:
                        try:
                            await iface.send_no_wait(
                                build_client_leaving(bssid, self.source_mac),
                            )
                        except Exception:
                            logger.debug("Fake-Connect leave frame failed", exc_info=True)
                    if self._fake_client_registered:
                        unregister = getattr(self.array, "unregister_fake_client", None)
                        if unregister is not None:
                            unregister(self.source_mac)
                        self._fake_client_registered = False
                    assoc.stop()
                    self.associated = False

    async def _discover_dhcp(self, iface, bssid: bytes) -> DhcpOffer | None:
        xid = random_xid()
        self._dhcp_xid = xid
        discover = build_discover(bssid, self.source_mac, xid)
        probe = _DhcpProbe(iface, self.target.bssid, self.source_mac, xid)
        self.dhcp_probing = True
        probe.start()
        try:
            for attempt in range(1, 4):
                if self.stopped:
                    return None
                self.log(
                    f"DHCP Discover [dim](attempt {attempt}/3; no lease claimed)[/dim]"
                )
                await iface.send_no_wait(discover)
                offer = await probe.wait(1.5)
                if offer is not None:
                    return offer
            return None
        finally:
            probe.stop()
            self.dhcp_probing = False

    async def _probe_connectivity(
        self,
        iface,
        bssid: bytes,
        offer: DhcpOffer,
    ) -> ConnectivityResult:
        result = ConnectivityResult(
            "inconclusive", time.time(), "DHCP lease was not acquired",
        )
        if self._dhcp_xid is None or not offer.server:
            self.log(
                "[yellow]Connectivity probe inconclusive[/yellow] "
                "[dim](Offer omitted DHCP server identifier)[/dim]"
            )
            return result

        inbox = _PacketInbox(iface)
        inbox.start()
        gateway_mac = None
        try:
            lease, nak = await self._request_dhcp_lease(
                iface, inbox, bssid, offer,
            )
            if nak:
                result.detail = "DHCP server rejected the temporary lease"
                self.log("[yellow]DHCP NAK[/yellow] · connectivity not tested")
                return result
            if lease is None:
                result.detail = "No DHCP ACK observed"
                self.log(
                    "[yellow]No DHCP ACK observed[/yellow] "
                    "[dim](connectivity inconclusive)[/dim]"
                )
                return result
            self.dhcp_lease = lease
            result = await self._test_lease_connectivity(
                iface, inbox, bssid, lease,
            )
            gateway_mac = result.gateway_mac
            return result
        finally:
            lease = self.dhcp_lease
            if lease is not None and lease.server:
                try:
                    await iface.send_no_wait(
                        build_release(
                            bssid,
                            self.source_mac,
                            gateway_mac or b"\xff" * 6,
                            random_xid(),
                            lease.offered_ip,
                            lease.server,
                        )
                    )
                    self.log("[dim]DHCP Release sent · temporary lease relinquished[/dim]")
                except Exception:
                    logger.debug("DHCP Release failed", exc_info=True)
            inbox.stop()

    async def _request_dhcp_lease(
        self,
        iface,
        inbox: _PacketInbox,
        bssid: bytes,
        offer: DhcpOffer,
    ) -> tuple[DhcpOffer | None, bool]:
        request = build_request(
            bssid,
            self.source_mac,
            self._dhcp_xid,
            offer.offered_ip,
            offer.server,
        )
        for attempt in range(1, 4):
            if self.stopped:
                return None, False
            self.log(f"DHCP Request [dim](attempt {attempt}/3; temporary lease)[/dim]")
            await iface.send_no_wait(request)
            reply = await inbox.match(
                lambda raw: _matching_ack(
                    raw, self._dhcp_xid, self.source_mac,
                ),
                1.5,
            )
            if reply is None:
                continue
            lease, nak = reply
            if lease is not None:
                lease = _merge_lease(lease, offer)
                self.log(
                    f"[bold green]DHCP ACK[/bold green] · {lease.offered_ip} "
                    "[dim](temporary lease)[/dim]"
                )
            return lease, nak
        return None, False

    async def _test_lease_connectivity(
        self,
        iface,
        inbox: _PacketInbox,
        bssid: bytes,
        lease: DhcpOffer,
    ) -> ConnectivityResult:
        result = ConnectivityResult(
            "limited", time.time(), "Temporary lease acquired",
        )
        gateway = lease.routers[0] if lease.routers else None
        result.gateway = gateway
        if not gateway:
            result.detail = "Lease omitted a default gateway"
            self.log("[yellow]Connectivity limited[/yellow] · no default gateway")
            return result

        gateway_mac = await self._resolve_arp(
            iface, inbox, bssid, lease.offered_ip, gateway,
        )
        if gateway_mac is None:
            result.detail = "Default gateway did not answer ARP"
            self.log("[yellow]Gateway unreachable[/yellow] · no ARP reply")
            return result
        result.gateway_reachable = True
        result.gateway_mac = gateway_mac
        self.log(f"[bold green]Gateway reachable[/bold green] · {gateway}")

        dns_server = lease.dns_servers[0] if lease.dns_servers else None
        result.dns_server = dns_server
        if not dns_server:
            result.detail = "Lease omitted DNS servers"
            self.log("[yellow]Connectivity limited[/yellow] · no DNS server")
            return result

        dns_hop = gateway_mac
        if _same_network(lease.offered_ip, dns_server, lease.subnet_mask):
            if dns_server != gateway:
                dns_hop = await self._resolve_arp(
                    iface, inbox, bssid, lease.offered_ip, dns_server,
                )
                if dns_hop is None:
                    result.detail = "DNS server did not answer ARP"
                    return result
        addresses = await self._resolve_dns(
            iface, inbox, bssid, lease.offered_ip, dns_server, dns_hop,
        )
        if addresses is None:
            result.detail = "DNS query received no response"
            self.log("[yellow]DNS unreachable[/yellow]")
            return result
        result.dns_reachable = True
        if not addresses:
            result.detail = "Connectivity endpoint had no IPv4 answer"
            self.log("[yellow]DNS reachable[/yellow] · endpoint had no IPv4 answer")
            return result
        self.log("[bold green]DNS reachable[/bold green] · connectivity endpoint resolved")

        response, tcp_reachable = await self._http_probe(
            iface, inbox, bssid, lease.offered_ip, addresses[0], gateway_mac,
        )
        result.tcp_reachable = tcp_reachable
        if response is None:
            result.detail = (
                "TCP connected but no HTTP response"
                if tcp_reachable else "Connectivity endpoint TCP connection failed"
            )
            self.log(f"[yellow]{result.detail}[/yellow]")
            return result
        result.http_status = response.status
        result.portal_origin = response.location_origin
        if response.status == 204:
            result.status = "internet_confirmed"
            result.detail = "Expected HTTP 204 received"
            self.log("[bold green]Internet confirmed[/bold green] · expected HTTP 204")
        elif 300 <= response.status < 400 and response.location_origin:
            result.status = "portal_observed"
            result.detail = f"HTTP redirect to {response.location_origin}"
            self.log(
                "[bold yellow]Captive portal observed[/bold yellow] · redirect to "
                f"{response.location_origin}"
            )
        else:
            result.status = "portal_suspected"
            result.detail = (
                f"Connectivity endpoint returned unexpected HTTP {response.status}"
            )
            self.log(
                "[yellow]Captive portal suspected[/yellow] · "
                f"unexpected HTTP {response.status}"
            )
        return result

    async def _resolve_arp(
        self,
        iface,
        inbox: _PacketInbox,
        bssid: bytes,
        client_ip: str,
        target_ip: str,
    ) -> bytes | None:
        frame = build_arp_request(bssid, self.source_mac, client_ip, target_ip)
        for _ in range(3):
            if self.stopped:
                return None
            await iface.send_no_wait(frame)
            reply = await inbox.match(
                lambda raw: parse_arp_reply(
                    raw, self.source_mac, client_ip, target_ip,
                ),
                1.0,
            )
            if reply is not None:
                return reply.mac
        return None

    async def _resolve_dns(
        self,
        iface,
        inbox: _PacketInbox,
        bssid: bytes,
        client_ip: str,
        dns_ip: str,
        next_hop_mac: bytes,
    ) -> tuple[str, ...] | None:
        source_port = random_ephemeral_port()
        transaction_id = secrets.randbits(16)
        frame = build_dns_query(
            bssid, self.source_mac, next_hop_mac,
            client_ip, dns_ip, CONNECTIVITY_HOST,
            source_port=source_port, transaction_id=transaction_id,
        )
        for _ in range(2):
            if self.stopped:
                return None
            await iface.send_no_wait(frame)
            response = await inbox.match(
                lambda raw: parse_dns_response(
                    raw, client_ip, dns_ip, source_port, transaction_id,
                ),
                1.5,
            )
            if response is not None:
                return response
        return None

    async def _http_probe(
        self,
        iface,
        inbox: _PacketInbox,
        bssid: bytes,
        client_ip: str,
        remote_ip: str,
        next_hop_mac: bytes,
    ):
        source_port = random_ephemeral_port()
        initial_sequence = secrets.randbits(32)
        syn = build_tcp_frame(
            bssid, self.source_mac, next_hop_mac,
            client_ip, remote_ip, source_port, 80,
            initial_sequence, 0, TCP_SYN,
            ident=secrets.randbits(16),
        )
        syn_ack = None
        for _ in range(3):
            if self.stopped:
                return None, False
            await iface.send_no_wait(syn)
            candidate = await inbox.match(
                lambda raw: parse_tcp_segment(
                    raw, client_ip, remote_ip, source_port, 80,
                ),
                1.5,
            )
            if (
                candidate is not None
                and candidate.flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK)
                and candidate.acknowledgement == (initial_sequence + 1) & 0xFFFFFFFF
            ):
                syn_ack = candidate
                break
        if syn_ack is None:
            return None, False

        client_sequence = (initial_sequence + 1) & 0xFFFFFFFF
        remote_sequence = (syn_ack.sequence + 1) & 0xFFFFFFFF
        request = (
            f"GET {CONNECTIVITY_PATH} HTTP/1.1\r\n"
            f"Host: {CONNECTIVITY_HOST}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        await iface.send_no_wait(
            build_tcp_frame(
                bssid, self.source_mac, next_hop_mac,
                client_ip, remote_ip, source_port, 80,
                client_sequence, remote_sequence, TCP_ACK,
                ident=secrets.randbits(16),
            )
        )
        await iface.send_no_wait(
            build_tcp_frame(
                bssid, self.source_mac, next_hop_mac,
                client_ip, remote_ip, source_port, 80,
                client_sequence, remote_sequence, TCP_ACK | TCP_PSH, request,
                ident=secrets.randbits(16),
            )
        )
        client_sequence = (client_sequence + len(request)) & 0xFFFFFFFF
        received = bytearray()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and len(received) < MAX_HTTP_HEADER_BYTES:
            if self.stopped:
                break
            segment = await inbox.match(
                lambda raw: parse_tcp_segment(
                    raw, client_ip, remote_ip, source_port, 80,
                ),
                max(0.05, deadline - time.monotonic()),
            )
            if segment is None or segment.flags & TCP_RST:
                break
            if segment.payload and segment.sequence == remote_sequence:
                room = MAX_HTTP_HEADER_BYTES - len(received)
                received.extend(segment.payload[:room])
                remote_sequence = (
                    remote_sequence + len(segment.payload)
                ) & 0xFFFFFFFF
                await iface.send_no_wait(
                    build_tcp_frame(
                        bssid, self.source_mac, next_hop_mac,
                        client_ip, remote_ip, source_port, 80,
                        client_sequence, remote_sequence, TCP_ACK,
                        ident=secrets.randbits(16),
                    )
                )
                parsed = parse_http_response(bytes(received))
                if parsed is not None:
                    await iface.send_no_wait(
                        build_tcp_frame(
                            bssid, self.source_mac, next_hop_mac,
                            client_ip, remote_ip, source_port, 80,
                            client_sequence, remote_sequence, TCP_RST | TCP_ACK,
                            ident=secrets.randbits(16),
                        )
                    )
                    return parsed, True
        return None, True


def _matching_ack(
    raw: bytes,
    xid: int,
    client_mac: bytes,
) -> tuple[DhcpOffer | None, bool] | None:
    lease, nak = parse_ack(raw, xid, client_mac)
    return (lease, nak) if lease is not None or nak else None


def _merge_lease(ack: DhcpOffer, offer: DhcpOffer) -> DhcpOffer:
    """Keep useful Offer options omitted by a minimal DHCP ACK."""
    return DhcpOffer(
        offered_ip=ack.offered_ip,
        server=ack.server or offer.server,
        subnet_mask=ack.subnet_mask or offer.subnet_mask,
        routers=ack.routers or offer.routers,
        dns_servers=ack.dns_servers or offer.dns_servers,
        domain=ack.domain or offer.domain,
        portal=ack.portal or offer.portal,
        lease_seconds=(
            ack.lease_seconds
            if ack.lease_seconds is not None
            else offer.lease_seconds
        ),
    )


def _same_network(address: str, other: str, mask: str | None) -> bool:
    if not mask:
        return False
    try:
        network = ipaddress.IPv4Network((address, mask), strict=False)
        return ipaddress.IPv4Address(other) in network
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False
