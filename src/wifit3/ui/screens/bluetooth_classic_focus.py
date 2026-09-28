from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from wifit3.bluetooth.assigned_numbers import manufacturer_label, service_label
from wifit3.bluetooth.classification import device_classification

if TYPE_CHECKING:
    from wifit3.models import BluetoothDevice
    from wifit3.ui.app import WifiteApp


class BluetoothClassicFocusView(Screen):
    """Read-only identity, SDP, and controller details for a Classic device."""

    app: "WifiteApp"

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "browse_services", "Browse SDP"),
    ]

    CSS = """
    BluetoothClassicFocusView { layout: vertical; background: $surface; }
    #classic-top { height: 3; }
    #classic-top Button { height: 3; width: auto; min-width: 0; margin-right: 1; }
    #classic-status { width: 1fr; height: 3; content-align: center middle; }
    #classic-body { height: 1fr; }
    .classic-panel { width: 1fr; height: 100%; border: round $primary; padding: 1 2; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="classic-top"):
            yield Button("‹ Bluetooth", id="classic-back")
            yield Button("Browse SDP", id="classic-sdp", variant="primary")
            yield Static("", id="classic-status")
        with Horizontal(id="classic-body"):
            identity = Static("", id="classic-identity", classes="classic-panel")
            identity.border_title = "CLASSIC IDENTITY"
            yield identity
            services = Static("", id="classic-services", classes="classic-panel")
            services.border_title = "READ-ONLY SDP"
            yield services
            health = Static("", id="classic-health", classes="classic-panel")
            health.border_title = "HCI HEALTH"
            yield health
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.5, self._refresh)
        self._refresh()

    def _refresh(self) -> None:
        if self.app.screen is not self:
            return
        device = self.app.bluetooth_manager.classic_focus_device
        if device is None:
            self.query_one("#classic-status", Static).update("[red]Device unavailable[/red]")
            return
        self.query_one("#classic-status", Static).update(
            f"[bold cyan]● CLASSIC OBSERVATION[/]  {escape(device.name)}"
        )
        self.query_one("#classic-identity", Static).update(self._identity(device))
        self.query_one("#classic-services", Static).update(self._services(device))
        self.query_one("#classic-health", Static).update(self._health())

    @staticmethod
    def _identity(device: "BluetoothDevice") -> str:
        classification = device_classification(device)
        manufacturer = manufacturer_label(
            device.manufacturer_ids, device.identifier,
        ) or "Unknown"
        related = (
            "\n".join(f"  {escape(value)}" for value in device.related_identifiers)
            or "  none"
        )
        return (
            f"[bold]{escape(device.name)}[/bold]\n"
            f"[dim]{escape(device.identifier)}[/dim]\n\n"
            f"[dim]Signal[/dim] {device.rssi} dBm\n"
            f"[dim]Class of device[/dim] "
            f"{f'0x{device.class_of_device:06x}' if device.class_of_device is not None else 'unknown'}\n"
            f"[dim]Category[/dim] {escape(classification.category)}"
            f" · {escape(classification.detail)}\n"
            f"[dim]OUI / manufacturer[/dim] {escape(manufacturer)}\n"
            f"[dim]Page scan repetition[/dim] {device.page_scan_repetition_mode}\n"
            f"[dim]Clock offset[/dim] {device.clock_offset}\n"
            f"[dim]Observations[/dim] {device.advertisement_count}\n\n"
            f"[bold]Probable BT/BLE relation[/bold]\n"
            f"[dim]Confidence[/dim] {escape(device.correlation_confidence or 'none')}\n"
            f"{related}\n"
            f"[dim]{escape(', '.join(device.correlation_evidence) or 'No correlation evidence')}[/dim]"
        )

    @staticmethod
    def _services(device: "BluetoothDevice") -> str:
        if not device.service_uuids:
            return (
                "[dim]No SDP service browse completed yet.[/dim]\n\n"
                "Press [bold]R[/bold] to request the public service records.\n"
                "This view does not pair, authenticate, or write profile data."
            )
        return "\n".join(
            f"[cyan]•[/] {escape(service_label(uuid))}\n  [dim]{escape(uuid)}[/dim]"
            for uuid in device.service_uuids
        )

    def _health(self) -> str:
        health = self.app.bluetooth_manager.hci_health
        if health is None:
            return "[dim]USB HCI controller unavailable[/dim]"
        last_event = (
            f"{health.last_event_at:.3f}" if health.last_event_at is not None else "none"
        )
        return (
            f"[dim]Event packets[/dim] {health.event_packets}\n"
            f"[dim]Malformed[/dim] {health.malformed_events}\n"
            f"[dim]Classic observations[/dim] {health.classic_observations}\n"
            f"[dim]BLE observations[/dim] {health.ble_observations}\n"
            f"[dim]Inquiry completions[/dim] {health.inquiry_completions}\n"
            f"[dim]Remote-name requests[/dim] {health.remote_name_requests}\n"
            f"[dim]Name successes[/dim] {health.remote_name_successes}\n"
            f"[dim]Name failures[/dim] {health.remote_name_failures}\n"
            f"[dim]Read errors[/dim] {health.read_errors}\n"
            f"[dim]Last event epoch[/dim] {last_event}"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "classic-back":
            self.action_go_back()
        elif event.button.id == "classic-sdp":
            self.action_browse_services()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_browse_services(self) -> None:
        self.browse_services()

    @work(exclusive=True, group="classic-sdp")
    async def browse_services(self) -> None:
        device = self.app.bluetooth_manager.classic_focus_device
        if device is None:
            return
        self.query_one("#classic-status", Static).update(
            f"[yellow]Browsing public SDP records…[/]  {escape(device.name)}"
        )
        try:
            services = await self.app.bluetooth_manager.browse_classic_sdp(
                device.identifier,
            )
        except Exception as exc:
            self.notify(str(exc), title="Classic SDP failed", severity="error")
        else:
            self.notify(
                f"Found {len(services)} public service classes",
                title="Classic SDP complete",
            )
        finally:
            self._refresh()
