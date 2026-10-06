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
    build_mdns_service_query,
    build_nbns_node_status_query,
    build_ssdp_discovery_query,
    build_tcp_frame,
    build_wsd_probe,
    classify_announced_services,
    parse_arp_reply,
    parse_arp_reply_any,
    parse_dns_response,
    parse_http_response,
    parse_mdns_services,
    parse_nbns_node_status,
    parse_ssdp_services,
    parse_tcp_segment,
    parse_wsd_services,
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
from wifit3.dot11.ie import GENERIC_RSN_IE, force_psk_akm
from wifit3.dot11.station_crypto import CcmpStationCodec, WepStationCodec
from wifit3.id.common import vendor_for_mac
from wifit3.models.access_point import CaptureType

from .auth_assoc import Association, build_client_leaving
from .campaign import Campaign
from .wpa_station import WpaHandshakeError, WpaPskSupplicant

logger = logging.getLogger(__name__)

CONNECTIVITY_HOST = "connectivitycheck.gstatic.com"
CONNECTIVITY_PATH = "/generate_204"
CONNECTIVITY_URL = f"http://{CONNECTIVITY_HOST}{CONNECTIVITY_PATH}"
MAX_HTTP_HEADER_BYTES = 8192
DHCP_PROBE_ATTEMPTS = 6
DHCP_PROBE_WAIT_SECONDS = 3.0
DATAPATH_VERIFY_SECONDS = 4.0
ARP_SWEEP_MAX_HOSTS = 256           # cap the sweep (a /24 is 254 usable hosts)
ARP_SWEEP_PACING_SECONDS = 0.005    # gap between broadcast ARP requests
ARP_SWEEP_SETTLE_SECONDS = 1.5      # listen window after the last request
ARP_SWEEP_LOG_LIMIT = 20            # neighbors listed inline before "+N more"
BONJOUR_DISCOVERY_SECONDS = 2.0
BONJOUR_SERVICE_LIMIT = 64
LOCAL_DISCOVERY_SECONDS = 2.0
NBNS_DISCOVERY_MAX_HOSTS = 64
NBNS_DISCOVERY_PACING_SECONDS = 0.01


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

    def __init__(self, iface, decode=None):
        self.iface = iface
        self.decode = decode or (lambda raw: raw)
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=256)

    def _rx(self, packet) -> None:
        raw = bytes(getattr(packet, "raw", b""))
        if raw:
            decoded = self.decode(raw)
            if decoded is not None:
                self.loop.call_soon_threadsafe(self._put, decoded)

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

    def __init__(self, iface, bssid: str, client_mac: bytes, xid: int, decode=None):
        self.iface = iface
        self.bssid = bssid.casefold()
        self.client_mac = client_mac
        self.xid = xid
        self.decode = decode or (lambda raw: raw)
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[DhcpOffer] = asyncio.Queue(maxsize=1)
        self._seen = False

    def _rx(self, packet) -> None:
        raw = bytes(getattr(packet, "raw", b""))
        if len(raw) < 24:
            return
        bssid = str_to_mac(self.bssid)
        if raw[10:16] != bssid:
            return
        dest = raw[4:10]
        if dest != self.client_mac and dest != b"\xff" * 6:
            return
        raw = self.decode(raw)
        offer = (
            parse_offer(raw, self.xid, self.client_mac)
            if raw is not None else None
        )
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
    """Associate a temporary client with an open, WEP, or captured-key WPA2 AP."""

    button_id = "btn-fake-connect"
    key = "fake_connect"
    hotkey = None
    stoppable = True
    idle_label = "Fake-Connect"
    run_label = "Disconnect"
    idle_variant = "primary"
    run_variant = "error"

    def __init__(
        self,
        array,
        target,
        source_mac: bytes | None = None,
        log=None,
        credential: str | bytes | None = None,
    ):
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
        self.credential = credential
        self.security = (getattr(target, "encryption", "") or "").casefold()
        self.association_only = self.security == "wep" and credential is None
        self._codec: WepStationCodec | CcmpStationCodec | None = None
        self.association_ssid, self.ssid_is_guess = self._association_ssid(array, target)
        self.associated = False
        self.fail_reason: Optional[str] = None
        self.dhcp_offer: DhcpOffer | None = None
        self.dhcp_lease: DhcpOffer | None = None
        self.connectivity_result: ConnectivityResult | None = None
        self.dhcp_probing = False
        self.datapath_verified = False
        self.arp_neighbors: list[tuple[str, str]] = []   # (ip, mac) discovered on-subnet
        self.arp_neighbors_recorded = False
        self.bonjour_services: list[tuple[str, str | None, str]] = []
        self.bonjour_services_recorded = False
        self.ssdp_services: list[tuple[str, str | None, str]] = []
        self.wsd_services: list[tuple[str, str | None, str]] = []
        self.nbns_roles: list[tuple[str, str | None, str]] = []
        self.discovered_services: list[tuple[str, str | None, str, str]] = []
        self.device_roles: list[tuple[str, str | None, str]] = []
        self.local_services_recorded = False
        self.metadata_recorded = False
        self.lease_recorded = False
        self.connectivity_recorded = False
        self._dhcp_xid: int | None = None
        self._fake_client_registered = False

    @property
    def client_mac(self) -> str:
        return mac_to_str(self.source_mac)

    @staticmethod
    def _usable_passphrase(psk: str | None) -> bool:
        if not psk or not psk.strip():
            return False
        return psk.strip().casefold() != "placeholder"

    @classmethod
    def _wpa2_psk_ccmp(cls, ap) -> bool:
        encryption = (getattr(ap, "encryption", "") or "").casefold()
        return (
            encryption.startswith("wpa2")
            and 2 in getattr(ap, "akm_suites", ())
            and (getattr(ap, "pairwise_cipher", None) or "CCMP") == "CCMP"
        )

    @classmethod
    def _session_psk(cls, ap) -> str | None:
        psk = getattr(ap, "wps_pbc_psk", None) or getattr(ap, "wps_pin_psk", None)
        return psk if cls._usable_passphrase(psk) else None

    @classmethod
    def resolve_credential(cls, ap, vault) -> str | bytes | None:
        encryption = (getattr(ap, "encryption", "") or "").casefold()
        if encryption == "wep":
            wep_key = getattr(ap, "wep_key", None)
            if wep_key:
                return wep_key
            for cap in vault.persisted(ap.bssid):
                if cap.type == CaptureType.WEP and cap.value:
                    try:
                        return bytes.fromhex(cap.value.strip())
                    except ValueError:
                        pass
            return None
        if cls._wpa2_psk_ccmp(ap):
            psk = cls._session_psk(ap) or vault.known_psk(ap)
            return psk if cls._usable_passphrase(psk) else None
        return None

    @classmethod
    def visible(cls, ap, vault=None) -> bool:
        encryption = (getattr(ap, "encryption", "") or "").casefold()
        if encryption == "wep":
            return True
        if encryption == "open" and not getattr(ap, "akm_suites", ()):
            return True
        if cls._wpa2_psk_ccmp(ap):
            if cls._session_psk(ap):
                return True
            if vault is not None and cls._usable_passphrase(vault.known_psk(ap)):
                return True
        return False

    @classmethod
    def ineligible_reason(cls, ap, vault=None) -> Optional[str]:
        if ap.is_hidden and not getattr(ap, "siblings", ()):
            return "hidden SSID: no confirmed or sibling-derived name"
        encryption = (getattr(ap, "encryption", "") or "").casefold()
        if encryption.startswith("wpa") and not cls._wpa2_psk_ccmp(ap):
            return "captured-key connection supports WPA2-PSK with CCMP only"
        if cls._wpa2_psk_ccmp(ap) and vault is not None:
            if not cls._session_psk(ap) and not cls._usable_passphrase(
                vault.known_psk(ap),
            ):
                return "no captured WPA2-PSK in Vault"
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
                    assoc_trailer_ies=self._association_ies(),
                    privacy=self.security != "open",
                    should_stop=lambda: self.stopped,
                )
                assoc.start()
                try:
                    if self.security == "open":
                        auth_label = "Open auth"
                    elif self.security == "wep":
                        auth_label = "Shared-key auth"
                    elif self.security.startswith("wpa2"):
                        auth_label = "WPA2-PSK auth"
                    else:
                        auth_label = "Auth"
                    self.log(
                        f"{auth_label} → association to [cyan]{self.association_ssid}[/cyan] "
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
                        if not await self._establish_data_security(iface, bssid):
                            return
                        await self._verify_encrypted_datapath(iface, bssid)
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
        discover = build_discover(
            bssid, self.source_mac, xid, broadcast=self._codec is None,
        )
        probe = _DhcpProbe(
            iface, self.target.bssid, self.source_mac, xid,
            decode=self._decode_data,
        )
        self.dhcp_probing = True
        probe.start()
        try:
            for attempt in range(1, DHCP_PROBE_ATTEMPTS + 1):
                if self.stopped:
                    return None
                self.log(
                    f"DHCP Discover [dim](attempt {attempt}/{DHCP_PROBE_ATTEMPTS}; "
                    "no lease claimed)[/dim]"
                )
                await self._send_data(iface, discover)
                offer = await probe.wait(DHCP_PROBE_WAIT_SECONDS)
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

        inbox = _PacketInbox(iface, decode=self._decode_data)
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
            # Release the shared inbox before the sweep so it is the sole codec
            # reader: a second _codec.open() on the same frame trips CCMP replay.
            inbox.stop()
            await self._sweep_arp_neighbors(iface, bssid, lease)
            await self._discover_bonjour(iface, bssid, lease)
            await self._discover_ssdp(iface, bssid, lease)
            await self._discover_wsd(iface, bssid, lease)
            await self._discover_nbns(iface, bssid, lease)
            self._classify_discovered_hosts()
            return result
        finally:
            lease = self.dhcp_lease
            if lease is not None and lease.server:
                try:
                    await self._send_data(
                        iface,
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
            broadcast=self._codec is None,
        )
        for attempt in range(1, DHCP_PROBE_ATTEMPTS + 1):
            if self.stopped:
                return None, False
            self.log(
                f"DHCP Request [dim](attempt {attempt}/{DHCP_PROBE_ATTEMPTS}; "
                "temporary lease)[/dim]"
            )
            await self._send_data(iface, request)
            reply = await inbox.match(
                lambda raw: _matching_ack(
                    raw, self._dhcp_xid, self.source_mac,
                ),
                DHCP_PROBE_WAIT_SECONDS,
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

    async def _sweep_arp_neighbors(self, iface, bssid: bytes, lease: DhcpOffer) -> None:
        """Broadcast an ARP request to every host in our /24-scoped subnet and
        collect the responders (IP + MAC). Bounded and best-effort; enumerates
        LAN neighbours while the temporary lease is held. Never aborts."""
        hosts = _sweep_targets(lease.offered_ip, lease.subnet_mask)
        if not hosts:
            return
        found: dict[str, bytes] = {}

        def _rx(packet) -> None:
            raw = self._decode_data(bytes(getattr(packet, "raw", b"")))
            if raw is None:
                return
            reply = parse_arp_reply_any(raw, self.source_mac, lease.offered_ip)
            if reply is not None and reply.address not in found:
                found[reply.address] = reply.mac

        self.log(
            f"[cyan]ARP sweep[/cyan] · probing {len(hosts)} host"
            f"{'s' if len(hosts) != 1 else ''} on {lease.offered_ip}/"
            f"{_mask_to_prefix(lease.subnet_mask)}"
        )
        iface.register_rx_callback(_rx)
        try:
            for host_ip in hosts:
                if self.stopped:
                    break
                await self._send_data(
                    iface,
                    build_arp_request(bssid, self.source_mac, lease.offered_ip, host_ip),
                )
                await asyncio.sleep(ARP_SWEEP_PACING_SECONDS)
            await asyncio.sleep(ARP_SWEEP_SETTLE_SECONDS)
        finally:
            iface.unregister_rx_callback(_rx)

        self.arp_neighbors = sorted(
            ((ip, mac_to_str(mac)) for ip, mac in found.items()),
            key=lambda item: tuple(int(octet) for octet in item[0].split(".")),
        )
        if not self.arp_neighbors:
            self.log("[dim]ARP sweep · no neighbours responded[/dim]")
            return
        self.log(
            f"[bold green]ARP sweep[/bold green] · {len(self.arp_neighbors)} "
            f"neighbour{'s' if len(self.arp_neighbors) != 1 else ''} discovered"
        )
        for ip, mac in self.arp_neighbors[:ARP_SWEEP_LOG_LIMIT]:
            vendor = vendor_for_mac(mac)
            marker = " [dim](gateway)[/dim]" if ip in (lease.routers or ()) else ""
            self.log(
                f"[dim]  {ip:<15} {mac}{f'  {vendor}' if vendor else ''}{marker}[/dim]"
            )
        remaining = len(self.arp_neighbors) - ARP_SWEEP_LOG_LIMIT
        if remaining > 0:
            self.log(f"[dim]  … +{remaining} more[/dim]")

    async def _discover_bonjour(
        self,
        iface,
        bssid: bytes,
        lease: DhcpOffer,
    ) -> None:
        """Enumerate local DNS-SD service types after the bounded ARP sweep."""
        found: set[tuple[str, str]] = set()

        def _rx(packet) -> None:
            raw = self._decode_data(bytes(getattr(packet, "raw", b"")))
            if raw is None:
                return
            response = parse_mdns_services(raw)
            if response is None:
                return
            for service_type in response.service_types:
                if len(found) >= BONJOUR_SERVICE_LIMIT:
                    break
                found.add((response.source_ip, service_type))

        self.log("[cyan]Bonjour discovery[/cyan] · enumerating local DNS-SD services")
        iface.register_rx_callback(_rx)
        try:
            await self._send_data(
                iface,
                build_mdns_service_query(bssid, self.source_mac, lease.offered_ip),
            )
            await asyncio.sleep(BONJOUR_DISCOVERY_SECONDS)
        finally:
            iface.unregister_rx_callback(_rx)

        mac_by_ip = {ip: mac for ip, mac in self.arp_neighbors}
        self.bonjour_services = sorted(
            (
                (ip, mac_by_ip.get(ip), service_type)
                for ip, service_type in found
            ),
            key=lambda item: (
                tuple(int(octet) for octet in item[0].split(".")),
                item[2],
            ),
        )
        if not self.bonjour_services:
            self.log("[dim]Bonjour discovery · no services advertised[/dim]")
            return
        self.log(
            f"[bold green]Bonjour discovery[/bold green] · "
            f"{len(self.bonjour_services)} service"
            f"{'s' if len(self.bonjour_services) != 1 else ''} discovered"
        )
        for ip, _mac, service_type in self.bonjour_services[:ARP_SWEEP_LOG_LIMIT]:
            self.log(f"[dim]  {ip:<15} {service_type}[/dim]")
        remaining = len(self.bonjour_services) - ARP_SWEEP_LOG_LIMIT
        if remaining > 0:
            self.log(f"[dim]  … +{remaining} more[/dim]")

    async def _discover_ssdp(
        self,
        iface,
        bssid: bytes,
        lease: DhcpOffer,
    ) -> None:
        source_port = random_ephemeral_port()
        found: set[tuple[str, str]] = set()

        def _rx(packet) -> None:
            raw = self._decode_data(bytes(getattr(packet, "raw", b"")))
            response = (
                parse_ssdp_services(raw, source_port)
                if raw is not None else None
            )
            if response is not None:
                found.update(
                    (response.source_ip, service)
                    for service in response.service_types
                )

        self.log("[cyan]SSDP discovery[/cyan] · querying UPnP devices")
        iface.register_rx_callback(_rx)
        try:
            await self._send_data(
                iface,
                build_ssdp_discovery_query(
                    bssid,
                    self.source_mac,
                    lease.offered_ip,
                    source_port=source_port,
                ),
            )
            await asyncio.sleep(LOCAL_DISCOVERY_SECONDS)
        finally:
            iface.unregister_rx_callback(_rx)
        self.ssdp_services = self._correlate_local_services(found)
        self._log_local_services("SSDP discovery", self.ssdp_services)

    async def _discover_wsd(
        self,
        iface,
        bssid: bytes,
        lease: DhcpOffer,
    ) -> None:
        source_port = random_ephemeral_port()
        found: set[tuple[str, str]] = set()

        def _rx(packet) -> None:
            raw = self._decode_data(bytes(getattr(packet, "raw", b"")))
            response = (
                parse_wsd_services(raw, source_port)
                if raw is not None else None
            )
            if response is not None:
                found.update(
                    (response.source_ip, service)
                    for service in response.service_types
                )

        self.log("[cyan]WS-Discovery[/cyan] · querying local devices")
        iface.register_rx_callback(_rx)
        try:
            await self._send_data(
                iface,
                build_wsd_probe(
                    bssid,
                    self.source_mac,
                    lease.offered_ip,
                    source_port=source_port,
                ),
            )
            await asyncio.sleep(LOCAL_DISCOVERY_SECONDS)
        finally:
            iface.unregister_rx_callback(_rx)
        self.wsd_services = self._correlate_local_services(found)
        self._log_local_services("WS-Discovery", self.wsd_services)

    async def _discover_nbns(
        self,
        iface,
        bssid: bytes,
        lease: DhcpOffer,
    ) -> None:
        source_port = random_ephemeral_port()
        pending: dict[int, str] = {}
        found: set[tuple[str, str]] = set()

        def _rx(packet) -> None:
            raw = self._decode_data(bytes(getattr(packet, "raw", b"")))
            response = (
                parse_nbns_node_status(raw, source_port)
                if raw is not None else None
            )
            if (
                response is None
                or pending.get(response.transaction_id) != response.source_ip
            ):
                return
            found.update(
                (response.source_ip, role)
                for role in response.roles
            )

        targets = self.arp_neighbors[:NBNS_DISCOVERY_MAX_HOSTS]
        if not targets:
            return
        self.log(
            f"[cyan]NBNS discovery[/cyan] · querying {len(targets)} ARP neighbour"
            f"{'s' if len(targets) != 1 else ''}"
        )
        iface.register_rx_callback(_rx)
        try:
            for target_ip, target_mac in targets:
                if self.stopped:
                    break
                transaction_id = secrets.randbits(16)
                while transaction_id in pending:
                    transaction_id = secrets.randbits(16)
                pending[transaction_id] = target_ip
                await self._send_data(
                    iface,
                    build_nbns_node_status_query(
                        bssid,
                        self.source_mac,
                        str_to_mac(target_mac),
                        lease.offered_ip,
                        target_ip,
                        source_port=source_port,
                        transaction_id=transaction_id,
                    ),
                )
                await asyncio.sleep(NBNS_DISCOVERY_PACING_SECONDS)
            await asyncio.sleep(LOCAL_DISCOVERY_SECONDS)
        finally:
            iface.unregister_rx_callback(_rx)
        self.nbns_roles = self._correlate_local_services(found)
        self._log_local_services("NBNS discovery", self.nbns_roles)

    def _correlate_local_services(
        self,
        found: set[tuple[str, str]],
    ) -> list[tuple[str, str | None, str]]:
        mac_by_ip = {ip: mac for ip, mac in self.arp_neighbors}
        return sorted(
            (
                (ip, mac_by_ip.get(ip), service)
                for ip, service in found
            ),
            key=lambda item: (
                tuple(int(octet) for octet in item[0].split(".")),
                item[2],
            ),
        )

    def _log_local_services(
        self,
        label: str,
        services: list[tuple[str, str | None, str]],
    ) -> None:
        if not services:
            self.log(f"[dim]{label} · no services advertised[/dim]")
            return
        self.log(
            f"[bold green]{label}[/bold green] · {len(services)} "
            f"service{'s' if len(services) != 1 else ''} discovered"
        )
        for ip, _mac, service in services[:ARP_SWEEP_LOG_LIMIT]:
            self.log(f"[dim]  {ip:<15} {service}[/dim]")

    def _classify_discovered_hosts(self) -> None:
        observations: list[tuple[str, str | None, str, str]] = []
        for source, services in (
            ("mdns", self.bonjour_services),
            ("ssdp", self.ssdp_services),
            ("wsd", self.wsd_services),
            ("nbns", self.nbns_roles),
        ):
            observations.extend(
                (ip, mac, service, source)
                for ip, mac, service in services
            )
        self.discovered_services = observations
        grouped: dict[tuple[str, str | None], set[str]] = {}
        for ip, mac, service, source in observations:
            roles = (
                (service,)
                if source == "nbns"
                else classify_announced_services((service,))
            )
            grouped.setdefault((ip, mac), set()).update(roles)
        self.device_roles = sorted(
            (
                (ip, mac, role)
                for (ip, mac), roles in grouped.items()
                for role in roles
            ),
            key=lambda item: (
                tuple(int(octet) for octet in item[0].split(".")),
                item[2],
            ),
        )
        if self.device_roles:
            self.log(
                f"[bold green]Host roles[/bold green] · "
                f"{len(self.device_roles)} classified"
            )
            for ip, _mac, role in self.device_roles[:ARP_SWEEP_LOG_LIMIT]:
                self.log(f"[dim]  {ip:<15} {role}[/dim]")

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
            await self._send_data(iface, frame)
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
            await self._send_data(iface, frame)
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
            await self._send_data(iface, syn)
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
        await self._send_data(
            iface,
            build_tcp_frame(
                bssid, self.source_mac, next_hop_mac,
                client_ip, remote_ip, source_port, 80,
                client_sequence, remote_sequence, TCP_ACK,
                ident=secrets.randbits(16),
            )
        )
        await self._send_data(
            iface,
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
                await self._send_data(
                    iface,
                    build_tcp_frame(
                        bssid, self.source_mac, next_hop_mac,
                        client_ip, remote_ip, source_port, 80,
                        client_sequence, remote_sequence, TCP_ACK,
                        ident=secrets.randbits(16),
                    )
                )
                parsed = parse_http_response(bytes(received))
                if parsed is not None:
                    await self._send_data(
                        iface,
                        build_tcp_frame(
                            bssid, self.source_mac, next_hop_mac,
                            client_ip, remote_ip, source_port, 80,
                            client_sequence, remote_sequence, TCP_RST | TCP_ACK,
                            ident=secrets.randbits(16),
                        )
                    )
                    return parsed, True
        return None, True

    def _association_ies(self) -> bytes:
        if not self.security.startswith("wpa"):
            return b""
        source = getattr(self.target, "rsn_ie", None) or GENERIC_RSN_IE
        return force_psk_akm(
            source,
            pmf_capable=bool(getattr(self.target, "pmf_capable", False)),
        ) or GENERIC_RSN_IE

    async def _establish_data_security(self, iface, bssid: bytes) -> bool:
        if self.security == "open":
            return True
        if self.security == "wep":
            if not isinstance(self.credential, bytes):
                self.fail_reason = "no captured WEP key is available"
                return False
            try:
                self._codec = WepStationCodec(self.credential)
            except ValueError as exc:
                self.fail_reason = str(exc)
                return False
            self.log("[bold green]WEP key loaded[/bold green] · encrypted data enabled")
            return True
        if not isinstance(self.credential, str):
            self.fail_reason = "no captured WPA2 passphrase is available"
            return False
        self.log("[cyan]WPA2 4-way handshake[/cyan] · validating captured passphrase")
        try:
            keys = await WpaPskSupplicant(
                iface,
                bssid=bssid,
                client_mac=self.source_mac,
                ssid=self.association_ssid,
                passphrase=self.credential,
                rsn_ie=self._association_ies(),
                should_stop=lambda: self.stopped,
            ).run()
        except WpaHandshakeError as exc:
            self.fail_reason = str(exc)
            return False
        self._codec = CcmpStationCodec(keys.temporal_key)
        for key_id, group_key in keys.group_keys.items():
            self._codec.install_group_key(key_id, group_key)
        detail = "CCMP data enabled"
        if keys.group_keys:
            detail += " · group key for broadcast DHCP"
        self.log(f"[bold green]WPA2 key confirmed[/bold green] · {detail}")
        return True

    async def _verify_encrypted_datapath(self, iface, bssid: bytes) -> bool:
        """Confirm the negotiated key really works on the air: transmit an
        encrypted frame the AP link-ACKs (write) and wait for one MIC-valid
        frame the AP sent us (read). Informational; never aborts the campaign."""
        if self._codec is None:
            return True
        loop = asyncio.get_running_loop()
        decrypted: asyncio.Future = loop.create_future()

        def _rx(packet) -> None:
            if decrypted.done():
                return
            raw = bytes(getattr(packet, "raw", b""))
            # Only Protected data frames the AP transmitted (Addr2 == BSSID).
            if len(raw) < 24 or raw[10:16] != bssid:
                return
            if raw[0] & 0x0C != 0x08 or not raw[1] & 0x40:
                return
            if self._codec.open(raw) is not None:      # None => MIC/ICV failure
                loop.call_soon_threadsafe(decrypted.set_result, True)

        iface.register_rx_callback(_rx)
        try:
            tx_ok = await self._send_encrypted_probe(iface, bssid)
            try:
                await asyncio.wait_for(decrypted, DATAPATH_VERIFY_SECONDS)
                rx_ok = True
            except asyncio.TimeoutError:
                rx_ok = False
        finally:
            iface.unregister_rx_callback(_rx)

        self.datapath_verified = rx_ok
        if rx_ok:
            self.log(
                "[bold green]Encrypted data path verified[/bold green] · "
                f"{'TX link-ACKed · ' if tx_ok else ''}"
                "decrypted a live frame from the AP (MIC valid)"
            )
        elif tx_ok:
            self.log(
                "[yellow]Encrypted TX link-ACKed[/yellow] · no decryptable "
                "downlink yet [dim](AP may not be forwarding traffic)[/dim]"
            )
        else:
            self.log(
                "[yellow]Encrypted data path unconfirmed[/yellow] "
                "[dim](no AP ACK or decryptable frame observed)[/dim]"
            )
        return rx_ok

    async def _send_encrypted_probe(self, iface, bssid: bytes) -> bool:
        """Send one encrypted, AP-addressed (RA == BSSID) DHCP Discover and, when
        the card supports it, use its link-ACK as write confirmation."""
        frame = build_discover(
            bssid, self.source_mac, random_xid(), broadcast=self._codec is None,
        )
        if self._codec is not None:
            frame = self._codec.protect(frame)
        enable = getattr(iface, "enable_rx_acks", None)
        send_until_ack = getattr(iface, "send_until_ack", None)
        if enable is not None and send_until_ack is not None:
            try:
                await enable()
                return await send_until_ack(frame, max_retries=3)
            finally:
                disable = getattr(iface, "disable_rx_acks", None)
                if disable is not None:
                    await disable()
        return await iface.send_no_wait(frame)

    async def _send_data(self, iface, frame: bytes) -> bool:
        if self._codec is not None:
            frame = self._codec.protect(frame)
        return await iface.send_no_wait(frame)

    def _decode_data(self, frame: bytes) -> bytes | None:
        return self._codec.open(frame) if self._codec is not None else frame


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


def _mask_to_prefix(mask: str | None) -> int:
    """Prefix length for a dotted mask, defaulting to /24 when unknown."""
    if not mask:
        return 24
    try:
        return ipaddress.IPv4Network(("0.0.0.0", mask)).prefixlen
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return 24


def _sweep_targets(client_ip: str, mask: str | None) -> list[str]:
    """Host IPs to ARP-probe: every host in the subnet except our own address,
    scoped to the /24 around us when the subnet is larger, and capped."""
    try:
        network = ipaddress.IPv4Network((client_ip, mask or "255.255.255.0"),
                                        strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return []
    if network.num_addresses > 256:
        network = ipaddress.IPv4Network((client_ip, "255.255.255.0"), strict=False)
    us = ipaddress.IPv4Address(client_ip)
    hosts = [str(host) for host in network.hosts() if host != us]
    return hosts[:ARP_SWEEP_MAX_HOSTS]
