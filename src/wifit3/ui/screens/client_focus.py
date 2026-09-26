from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from wifit3.id import vendor_for_mac
from wifit3.dot11.enterprise import EAP_TYPE_NAMES
from wifit3.persist.common import bssid_to_dashed, safe_ssid
from wifit3.persist.config import Config
from wifit3.persist.pcap import PcapWriter
from wifit3.ui.recording_indicator import recording_indicator
from wifit3.ui.signal_bar import dbm_style
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.wlan.enterprise_risk import enterprise_findings

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


class ClientFocusView(Screen):
    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("x", "toggle_capture", "Capture PCAP"),
    ]

    CSS = """
    ClientFocusView { layout: vertical; background: $surface; }
    #client-focus-top { height: 3; }
    #client-focus-status { width: 1fr; content-align: center middle; text-align: center; }
    #client-pcap-recording {
        width: 20; content-align: center middle; text-align: center;
    }
    #client-focus-body { height: 1fr; }
    #client-summary, #client-network {
        width: 1fr; height: 100%; border: round $primary; padding: 1 2;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._writer: PcapWriter | None = None
        self._array = None
        self._client_mac: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="client-focus-top"):
            yield Static("", id="client-focus-status")
            yield Static("", id="client-pcap-recording")
        with Horizontal(id="client-focus-body"):
            summary = Static("", id="client-summary")
            summary.border_title = "CLIENT TARGET"
            yield summary
            network = Static("", id="client-network")
            network.border_title = "ASSOCIATION & CAPTURE"
            yield network
        yield GlobalJobTracker()
        yield Footer()

    async def on_mount(self) -> None:
        self.set_interval(0.5, self._refresh)
        client = self.app.target_client
        array = self.app.array
        if client is None or array is None or not client.bssid:
            self.app.pop_screen()
            return
        ap = array.access_points.get(client.bssid)
        if ap is None:
            self.app.pop_screen()
            return
        await array.stop_hopping()
        await array.set_channel(ap.channel, scan=False)
        self._start_capture(client, ap)
        self._refresh()

    def _refresh(self) -> None:
        client = self.app.target_client
        array = self.app.array
        if client is None:
            return
        target = self.app.locked_target
        if (
            target is not None
            and time.time() - client.last_seen > Config.target_reacquire_timeout
        ):
            self.stop_capture()
            self.app.locked_target_id = None
            self.notify(
                f"Target {target.alias} was not reacquired",
                title="Target lock released",
                severity="warning",
            )
            target = None
        alias = target.alias if target is not None else client.mac
        manufacturer = vendor_for_mac(client.mac) or "Unknown"
        ap = array.access_points.get(client.bssid or "") if array is not None else None
        eap_methods = client.enterprise.server_eap_types | client.enterprise.client_eap_types
        enterprise = (
            "\n[dim]Enterprise EAP[/dim]  "
            + ", ".join(
                EAP_TYPE_NAMES.get(method, f"type {method}")
                for method in sorted(eap_methods)
            )
            if eap_methods else ""
        )
        lock_status = (
            f"[bold cyan]● TARGET LOCKED[/bold cyan]  {escape(alias)}"
            if target is not None
            else f"[yellow]● TARGET LOST[/yellow]  {escape(alias)}"
        )
        self.query_one("#client-focus-status", Static).update(
            lock_status
        )
        self.query_one("#client-pcap-recording", Static).update(
            recording_indicator("PCAP RECORDING", self._writer is not None),
        )
        self.query_one("#client-summary", Static).update(
            f"[bold]{escape(client.mac)}[/bold]\n\n"
            f"[dim]Manufacturer[/dim]  {escape(manufacturer)}\n"
            f"[dim]Signal[/dim]  [{dbm_style(client.signal)}]{client.signal} dBm[/]\n"
            f"[dim]Packets[/dim]  {client.packets}\n"
            f"[dim]First seen[/dim]  {time.strftime('%H:%M:%S', time.localtime(client.first_seen))}\n"
            f"[dim]Last seen[/dim]  {max(0, int(time.time() - client.last_seen))}s ago\n\n"
            f"[dim]Probe requests[/dim]\n"
            f"{escape(', '.join(sorted(client.probed_ssids)) or 'None observed')}"
            f"{enterprise}"
        )
        findings = enterprise_findings(ap) if ap is not None else []
        risk = (
            f"\n\n[bold red]SECURITY RISK[/bold red]\n"
            f"{escape(findings[0].label)}"
            if findings and findings[0].severity >= 3 else ""
        )
        writer = self._writer
        capture = (
            f"[bold green]RECORDING[/bold green]  {writer.count} packets\n"
            f"[dim]{escape(writer.path.name)}[/dim]"
            if writer is not None
            else "[yellow]Capture stopped[/yellow]"
        )
        self.query_one("#client-network", Static).update(
            f"[dim]SSID[/dim]  {escape(ap.ssid or '<hidden>') if ap else 'Waiting'}\n"
            f"[dim]BSSID[/dim]  {escape(client.bssid or 'Unassociated')}\n"
            f"[dim]Channel[/dim]  {ap.channel if ap else '-'}\n"
            f"[dim]Security[/dim]  {escape(ap.encryption or 'Unknown') if ap else '-'}\n\n"
            f"{capture}{risk}"
        )

    def _start_capture(self, client, ap) -> None:
        if self._writer is not None or self.app.array is None:
            return
        directory = Path(Config.captures_dir)
        epoch = int(time.time())
        while True:
            path = directory / (
                f"{safe_ssid(ap.ssid)}_{bssid_to_dashed(ap.bssid)}_"
                f"{epoch}_packet_capture.pcap"
            )
            if not path.exists():
                break
            epoch += 1
        try:
            self._writer = PcapWriter(
                path,
                max_bytes=Config.target_capture_max_mb * 1024 * 1024,
                max_parts=Config.target_capture_max_parts,
            )
        except OSError as exc:
            self.notify(str(exc), title="Capture failed", severity="error")
            return
        self._array = self.app.array
        self._client_mac = client.mac
        self._array.register_packet_callback(self._capture_packet)

    def _capture_packet(self, packet) -> None:
        writer = self._writer
        if (
            writer is None
            or self._client_mac is None
            or not packet.client_mac
            or packet.client_mac.casefold() != self._client_mac.casefold()
        ):
            return
        writer.write(packet.raw, time.time())

    def stop_capture(self, *, notify: bool = True) -> None:
        writer, self._writer = self._writer, None
        if writer is None:
            return
        if self._array is not None:
            self._array.unregister_packet_callback(self._capture_packet)
        self._array = None
        self._client_mac = None
        writer.close()
        self.app.vault.refresh()
        if notify:
            self.notify(
                f"{writer.count} packets\n{writer.path.name}",
                title="Client PCAP saved",
                timeout=6,
            )

    def action_toggle_capture(self) -> None:
        if self._writer is not None:
            self.stop_capture()
            return
        client = self.app.target_client
        array = self.app.array
        ap = array.access_points.get(client.bssid or "") if array and client else None
        if client is not None and ap is not None:
            self._start_capture(client, ap)

    async def action_go_back(self) -> None:
        self.stop_capture()
        self.app.pop_screen()
