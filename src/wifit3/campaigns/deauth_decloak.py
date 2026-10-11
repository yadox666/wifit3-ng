"""Deauth-driven hidden-SSID discovery: kick associated clients and wait for
passive decloak (assoc / reassoc / probe response) to reveal the network name."""
from __future__ import annotations

from typing import Optional

from wifit3.persist.config import Config
from wifit3.safety import deauth_limits

from . import treelog
from .campaign import Campaign
from .deauth_targets import associated_client_macs

# Match Focus live-client window (see focus_v2.screen._CLIENT_LIVE_SECONDS).
_LIVE_CLIENT_SEC = 10.0
_WAIT_AFTER_DEAUTH_SEC = 8.0
_MAX_CLIENT_CYCLES = 24


class DeauthDecloakCampaign(Campaign):
    """Round-robin deauths on a hidden AP until the sink learns its SSID."""

    key = "deauth_decloak"
    button_id = "btn-deauth-decloak"
    stoppable = True
    idle_label = "Detect AP name"
    run_label = "Stop detecting"
    idle_variant = "warning"
    run_variant = "error"

    @classmethod
    def visible(cls, ap) -> bool:
        """Top-bar button: hidden SSID targets without mandatory PMF."""
        if getattr(ap, "pmf_required", False):
            return False
        return getattr(ap, "is_hidden", False)

    @classmethod
    def allowed(cls, ap, *, live_client_count: int) -> bool:
        """True when the control can start (visible and at least one live client)."""
        return cls.visible(ap) and live_client_count > 0 and cls.ineligible_reason(
            ap, live_client_count=live_client_count,
        ) is None

    @classmethod
    def ineligible_reason(cls, ap, *, live_client_count: int) -> Optional[str]:
        if Config.is_silenced(ap.bssid):
            return "AP silenced"
        active = Campaign.active
        if active is not None and active.key != cls.key:
            return f"Blocked ({active.key} is active)"
        if getattr(ap, "pmf_required", False):
            return "PMF required (deauth blocked)"
        if not getattr(ap, "is_hidden", False):
            return "SSID already known"
        if live_client_count < 1:
            return "No live associated clients"
        return None

    def __init__(self, array, target, log=None):
        super().__init__(ap=target, array=array)
        self.target = target
        self.log = log or (lambda _m: None)
        self.revealed_ssid: Optional[str] = None
        self.deauths_sent = 0

    def status_under_card(self) -> str:
        return "● Detect SSID"

    def status_headlines(self, vault) -> list[str]:
        hint = f' [dim]"{self.revealed_ssid}"[/dim]' if self.revealed_ssid else ""
        return [
            f"[bold yellow]● Detect AP name[/bold yellow]{hint}",
            f"[dim]deauth bursts:{self.deauths_sent}[/dim]",
        ]

    def _current_ssid(self) -> Optional[str]:
        ap = self.array.access_points.get(self.target.bssid.lower())
        if ap is None:
            ssid = getattr(self.target, "ssid", None)
        else:
            ssid = ap.ssid
        if ssid and ssid != "<hidden>":
            return ssid
        return None

    def _live_targets(self) -> list[str]:
        return associated_client_macs(
            self.array,
            self.target.bssid,
            exclude_fake=True,
            live_within_sec=_LIVE_CLIENT_SEC,
        )

    async def _loop(self) -> None:
        burst_rounds, _broadcast_count = deauth_limits()
        cycles = 0
        index = 0
        async with self.array.lease(channel=self.target.channel, iface=self.iface) as iface:
            while not self.stopped and cycles < _MAX_CLIENT_CYCLES:
                revealed = self._current_ssid()
                if revealed:
                    self.revealed_ssid = revealed
                    self.log(treelog.leaf(
                        f"[bold green]SSID revealed:[/bold green] [cyan]{revealed}[/cyan]"))
                    return
                clients = self._live_targets()
                if not clients:
                    self.log(treelog.leaf_fail("No live clients left to deauthenticate"))
                    return
                mac = clients[index % len(clients)]
                index += 1
                cycles += 1
                self.log(f"Deauthing [cyan]{mac}[/cyan] to provoke SSID reveal…")
                res = await iface.deauth_client(self.target.bssid, mac, rounds=burst_rounds)
                self.deauths_sent += res.total_sent
                revealed = await self.array.wait_until(
                    lambda: self.stopped or self._current_ssid() is not None,
                    _WAIT_AFTER_DEAUTH_SEC,
                )
                if self.stopped:
                    return
                if revealed:
                    self.revealed_ssid = self._current_ssid()
                    if self.revealed_ssid:
                        self.log(treelog.leaf(
                            f"[bold green]SSID revealed:[/bold green] "
                            f"[cyan]{self.revealed_ssid}[/cyan]"))
                    return
        if not self.stopped and not self.revealed_ssid:
            self.log(treelog.leaf_fail("Timed out without learning the SSID"))
