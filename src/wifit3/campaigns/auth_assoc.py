"""802.11 open-auth + association against one AP, plus a live-interface transport.

``WlanTransport`` adapts a ``WlanInterface`` to a ``send``/``recv``/``drain``
contract: TX via ``send_until_ack``/``send_no_wait``; RX via an ``asyncio.Queue`` fed by a registered
callback that keeps only AP→us frames (Addr1==our MAC, Addr2==BSSID), so a caller
never trips over its own echoed TX or unrelated traffic.

``Association`` does Open-System auth + an Association Request. The assoc-req carries
whatever trailing IE the caller supplies (``assoc_trailer_ies``): a WPS vendor IE, a
forged RSN IE for PMKID, or nothing, so this module knows no protocol above the
802.11 skeleton.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

from wifit3.dot11 import build_deauth, random_client_mac, str_to_mac
from wifit3.dot11.auth_assoc import auth_req, assoc_req, status_description
from wifit3.dot11.deauth import reason_description
from wifit3.dot11.packet import AuthPacket, AssocRespPacket, DeauthPacket
from wifit3.dot11.probe import probe_req

logger = logging.getLogger(__name__)


def build_client_leaving(bssid: bytes, our_mac: bytes, deauth: bool = True) -> bytes:
    """A client→AP deauth (default) / disassoc announcing we're leaving the BSS."""
    return build_deauth(bssid, our_mac, bssid, 3 if deauth else 8, disassoc=not deauth)


class WlanTransport:
    """Send/recv/drain over a live WlanInterface."""

    def __init__(self, iface, bssid: bytes, our_mac: bytes, tx_observer=None):
        self.iface = iface
        self.bssid = bssid
        self.our_mac = our_mac
        self.tx_observer = tx_observer
        self._q: asyncio.Queue = asyncio.Queue()
        self._loop = asyncio.get_running_loop()
        self._active = False

    def _rx_cb(self, pkt) -> None:
        # Keep only AP→us frames: Addr1 (dest) == our MAC, Addr2 (src) == BSSID.
        frame = pkt.raw
        if len(frame) < 24:
            return
        if frame[4:10] != self.our_mac or frame[10:16] != self.bssid:
            return
        # Thread-safe handoff (driver RX may fire from a background reader).
        self._loop.call_soon_threadsafe(self._q.put_nowait, bytes(frame))

    def start(self) -> None:
        if self._active:
            return
        self._active = True
        # Forged-MAC registration is the campaign's job (via the array); the transport is radio-only.
        self.iface.register_rx_callback(self._rx_cb)

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        self.iface.unregister_rx_callback(self._rx_cb)

    async def send_until_ack(self, frame: bytes, max_retries: int = 0) -> bool:
        if self.tx_observer is not None:
            self.tx_observer(frame)
        return await self.iface.send_until_ack(frame, max_retries=max_retries)

    async def send_no_wait(self, frame: bytes) -> bool:
        if self.tx_observer is not None:
            self.tx_observer(frame)
        return await self.iface.send_no_wait(frame)

    async def recv(self, timeout: float) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._q.get(), timeout)
        except asyncio.TimeoutError:
            return None

    def drain(self) -> None:
        """Drop any queued frames."""
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except asyncio.QueueEmpty:
                break


class Association:
    """Open-System auth + Association Request against one AP."""

    def __init__(self, iface, bssid: str, ssid: str, channel: int,
                 our_mac: Optional[bytes] = None, assoc_timeout: float = 1.5,
                 auth_timeout: float = 1.0,
                 assoc_trailer_ies: bytes = b"",
                 privacy: Optional[bool] = None,
                 require_auth: bool = False,
                 capability_flags: Optional[set] = None,
                 ht_capable: bool = True,
                 wmm: bool = False,
                 should_stop: Optional[Callable[[], bool]] = None):
        self.iface = iface
        self.bssid = bssid.lower()
        self.bssid_bytes = str_to_mac(self.bssid)
        self.ssid = ssid or ""
        self.channel = channel
        self.our_mac = our_mac or random_client_mac()
        self.assoc_timeout = assoc_timeout
        self.auth_timeout = auth_timeout
        self.assoc_trailer_ies = assoc_trailer_ies
        self.privacy = privacy
        self.require_auth = require_auth
        self.capability_flags = capability_flags
        self.ht_capable = ht_capable
        self.wmm = wmm
        self.should_stop = should_stop or (lambda: False)
        self.associated = False
        self.fail_reason: Optional[str] = None
        self._auth_ok = False
        self._assoc_ok = False
        self._kicked = False
        self._active = False

    # ---- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._active:
            return
        self._active = True
        self.iface.register_rx_callback(self._rx_cb)

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        self.iface.unregister_rx_callback(self._rx_cb)

    async def associate(self, attempts: int = 5) -> bool:
        """Open-auth + assoc. Returns True once the AP accepts us (status 0)."""
        if self.iface.current_channel != self.channel:
            if not await self.iface.set_channel(self.channel):
                self.fail_reason = f"could not tune to channel {self.channel}"
                return False
        last_fail: Optional[str] = None
        used_ht = self.ht_capable
        for _ in range(attempts):
            if self.should_stop():
                return False
            self._auth_ok = False
            self._assoc_ok = False
            self._kicked = False
            self.fail_reason = None
            if self.require_auth:
                # Strict APs (AirOS WPA2-EAP) ignore Auth from a STA they have
                # not seen probe, then deauth Assoc with reason 9.
                logger.info("-> Probe Req to %s", self.bssid)
                await self.iface.send_no_wait(
                    probe_req(self.bssid_bytes, self.our_mac, self.ssid)
                )
                await asyncio.sleep(0.08)
            logger.info("-> Auth Req to %s", self.bssid)
            await self._send_until(auth_req(self.bssid_bytes, self.our_mac),
                                   lambda: self._auth_ok, self.auth_timeout)
            if not self._auth_ok:
                last_fail = self.fail_reason or "no Auth resp"
                if self.require_auth:
                    # AirOS and other strict APs deauth (reason 9) if Assoc
                    # arrives before Open-System Auth completes.
                    continue
            if self._kicked:
                last_fail = self.fail_reason or last_fail
                continue
            logger.info("-> Assoc Req to %s (ht=%s wmm=%s)", self.bssid, used_ht, self.wmm)
            await self._send_until(assoc_req(self.bssid_bytes, self.our_mac, self.ssid,
                                             self.assoc_trailer_ies,
                                             channel=self.channel,
                                             privacy=self.privacy,
                                             ht_capable=used_ht,
                                             capability_flags=self.capability_flags,
                                             wmm=self.wmm),
                                   lambda: self._assoc_ok, self.assoc_timeout)
            if self._assoc_ok:
                self.associated = True
                return True
            last_fail = self.fail_reason or (
                "no Assoc resp after Auth resp"
                if self._auth_ok else "no Auth/Assoc resp"
            )
            if last_fail.startswith("Assoc rejected"):
                if used_ht and "caps-unsupported" in last_fail:
                    used_ht = False
                    logger.info("Assoc caps-unsupported; retrying without HT")
                    continue
                break
        self.associated = False
        self.fail_reason = last_fail or self.fail_reason or "no Auth/Assoc resp"
        return False

    async def _send_until(self, frame: bytes, done, timeout: float,
                          resend_after: float = 0.4) -> None:
        """Send ``frame`` immediately, then poll ``done()`` up to ``timeout``, resending
        every ``resend_after`` while still silent (covers a lost TX or a lost AP reply)."""
        deadline = time.time() + timeout
        last_send = 0.0
        while (
            time.time() < deadline
            and not done()
            and not self._kicked
            and not self.should_stop()
        ):
            if time.time() - last_send >= resend_after:
                await self.iface.send_no_wait(frame)
                last_send = time.time()
            await asyncio.sleep(0.02)

    def _rx_cb(self, pkt) -> None:
        if not self._active or pkt.raw[4:10] != self.our_mac:   # addressed to us
            return
        if isinstance(pkt, AssocRespPacket):
            desc = status_description(pkt.status)
            if pkt.status == 0:
                self._assoc_ok = True
                logger.info("<- Assoc Resp (status 0: %s) from %s", desc, self.bssid)
            elif pkt.status is not None:
                self.fail_reason = f"Assoc rejected (status {pkt.status}: {desc})"
                logger.info("<- Assoc Resp rejected (status %s: %s) from %s", pkt.status, desc, self.bssid)
                self._kicked = True
        elif isinstance(pkt, AuthPacket):
            desc = status_description(pkt.status)
            if pkt.status == 0:
                self._auth_ok = True
                logger.info("<- Auth Resp (status 0: %s) from %s", desc, self.bssid)
            elif pkt.status is not None:
                self.fail_reason = f"Auth rejected (status {pkt.status}: {desc})"
                logger.info("<- Auth Resp rejected (status %s: %s) from %s", pkt.status, desc, self.bssid)
        elif isinstance(pkt, DeauthPacket):
            kind = "disassoc" if getattr(pkt, "type", "") == "mgmt_10" else "deauth"
            desc = reason_description(pkt.reason)
            specific = self.fail_reason and self.fail_reason.startswith(
                ("Assoc rejected", "Auth rejected")
            )
            if not specific:
                self.fail_reason = f"{kind} (reason {pkt.reason}: {desc})"
            logger.info("<- %s (reason %s: %s) from %s", kind.upper(), pkt.reason, desc, self.bssid)
            self.associated = False
            self._assoc_ok = False
            self._auth_ok = False
            self._kicked = True
