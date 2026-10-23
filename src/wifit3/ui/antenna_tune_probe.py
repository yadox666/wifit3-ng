"""Active link probe for AntennaTune: measure Ack success on gentle unicast probes."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Literal, Optional

from wifit3.campaigns.campaign import Campaign
from wifit3.dot11.link_probe import ap_link_probe_req, client_link_null
from wifit3.dot11.mac import mac_to_str, random_client_mac, str_to_mac
from wifit3.wlan.lease import Lease

logger = logging.getLogger(__name__)

_PROBE_INTERVAL_S = 0.5


@dataclass
class AntennaTuneProbeStats:
    """Cumulative link-probe TX / Ack counts for the open AntennaTune session."""

    mode: str = "idle"
    mac: str = ""
    sent: int = 0
    acked: int = 0
    running: bool = False
    status: str = ""

    @property
    def ack_ratio(self) -> float:
        if self.sent < 1:
            return 0.0
        return self.acked / self.sent


@dataclass
class AntennaTuneSession:
    """Shared state between the modal and the sample provider."""

    probe: Optional["AntennaTuneLinkProbe"] = None
    iface: object | None = None
    stats: AntennaTuneProbeStats = field(default_factory=AntennaTuneProbeStats)


def open_session(app, *, mode: Literal["ap", "client"], channel: int | None) -> AntennaTuneSession:
    """Session with the elected card pre-selected for ``channel``."""
    session = AntennaTuneSession()
    array = getattr(app, "array", None)
    if array is not None and channel is not None:
        session.iface = array.select_iface(channel)
    session.probe = AntennaTuneLinkProbe(app, mode=mode, session=session)
    return session


class AntennaTuneLinkProbe:
    """Send low-rate unicast probes with RX Ack tally armed."""

    def __init__(self, app, *, mode: Literal["ap", "client"], session: AntennaTuneSession) -> None:
        self._app = app
        self._mode = mode
        self._session = session
        self._stats = AntennaTuneProbeStats(mode=mode, mac="", running=False)
        self._tx_mac = random_client_mac()
        self._stats.mac = mac_to_str(self._tx_mac)
        self._stopped = False
        self._task: Optional[asyncio.Task] = None
        self._lease: Optional[Lease] = None

    @property
    def stats(self) -> AntennaTuneProbeStats:
        return self._stats

    def reset_counts(self) -> None:
        self._stats.sent = 0
        self._stats.acked = 0

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopped = False
        self._task = asyncio.create_task(self._run())

    async def restart(self) -> None:
        """Stop the current lease and probe again on the session's selected card."""
        await self.stop()
        self.reset_counts()
        self.start()

    async def stop(self) -> None:
        self._stopped = True
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._stats.running = False

    async def _run(self) -> None:
        array = getattr(self._app, "array", None)
        if array is None:
            self._stats.status = "No radio"
            return
        if Campaign.active is not None:
            self._stats.status = f"Radio busy ({Campaign.active.key})"
            return

        ap, client, channel = self._resolve_target()
        if channel is None:
            self._stats.status = "No channel"
            return
        if self._mode == "client":
            if ap is None:
                self._stats.status = "Client not on an AP"
                return
            self._tx_mac = str_to_mac(ap.bssid)
            self._stats.mac = ap.bssid.lower()
        iface = self._session.iface
        supported = getattr(iface, "supported_channels", None)
        if iface is None or (supported is not None and channel not in supported):
            iface = array.select_iface(channel)
        if iface is None:
            self._stats.status = "No card on channel"
            return

        self._stats.running = True
        self._stats.status = "Probing…"
        self._lease = array.lease(
            channel=channel,
            fake_mac=self._tx_mac,
            ack_tally=True,
            iface=iface,
        )
        try:
            async with self._lease as tx:
                while not self._stopped:
                    if Campaign.active is not None:
                        self._stats.status = f"Paused ({Campaign.active.key})"
                        await asyncio.sleep(_PROBE_INTERVAL_S)
                        continue
                    self._stats.status = "Probing…"
                    frame = self._build_frame(ap, client)
                    if frame is None:
                        self._stats.status = "No probe target"
                        break
                    base = tx.acks_seen(self._tx_mac)
                    await tx.send_until_ack(frame, max_retries=0)
                    self._stats.sent += 1
                    if tx.acks_seen(self._tx_mac) > base:
                        self._stats.acked += 1
                    await asyncio.sleep(_PROBE_INTERVAL_S)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("AntennaTune link probe stopped: %s", exc)
            self._stats.status = str(exc)[:48]
        finally:
            self._stats.running = False
            if not self._stopped and self._stats.status == "Probing…":
                self._stats.status = "Stopped"

    def _resolve_target(self):
        if self._mode == "ap":
            ap = getattr(self._app, "target_ap", None)
            if ap is None:
                return None, None, None
            return ap, None, ap.channel
        client = getattr(self._app, "target_client", None)
        if client is None:
            return None, None, None
        ap = None
        if client.bssid:
            ap = self._app.array.access_points.get(client.bssid.lower())
        channel = ap.channel if ap is not None else None
        return ap, client, channel

    def _build_frame(self, ap, client) -> Optional[bytes]:
        if self._mode == "ap":
            if ap is None:
                return None
            ssid = ap.ssid if ap.ssid and ap.ssid != "<hidden>" else ""
            return ap_link_probe_req(
                str_to_mac(ap.bssid), self._tx_mac, ssid, channel=ap.channel)
        if client is None or ap is None:
            return None
        return client_link_null(str_to_mac(ap.bssid), str_to_mac(client.mac))
