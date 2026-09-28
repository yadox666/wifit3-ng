from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, Select

from wifit3.campaigns.eap_lab_config import EapLabLaunchConfig


class EapLabModal(ModalScreen[EapLabLaunchConfig | None]):
    """Configure the Enterprise EAP lab honeypot."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    EapLabModal { align: center middle; }
    EapLabModal #dialog {
        width: 72; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    EapLabModal #title {
        width: 1fr; text-align: center; text-style: bold; margin-bottom: 1;
    }
    EapLabModal #description { height: auto; color: $text-muted; margin-bottom: 1; }
    EapLabModal .field-label { margin-top: 1; }
    EapLabModal #buttons { height: auto; align: center middle; margin-top: 1; }
    EapLabModal #buttons Button { margin: 0 1; }
    """

    def __init__(self, ssid: str, channel: int, *, default_methods: tuple[int, ...]) -> None:
        super().__init__()
        self.ssid = ssid
        self.channel = channel
        self.default_methods = default_methods

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Enterprise EAP Lab Honeypot", id="title")
            yield Label(
                f"Twin {self.ssid} on CH {self.channel}: cloned beacon, untrusted TLS, "
                "client misconfiguration tests (downgrade, inner PAP, lab DHCP), and "
                "MS-CHAPv2 capture to Vault (Hashcat 5500/5600).",
                id="description",
            )
            yield Checkbox(
                "Evict clients from the real AP (deauth + CSA + BTM when allowed)",
                value=True,
                id="lab-eviction",
            )
            yield Checkbox(
                "Client security assessment (untrusted cert, downgrade probes)",
                value=True,
                id="lab-assessment",
            )
            yield Checkbox(
                "Offer weaker outer EAP methods first (TTLS before PEAP, etc.)",
                value=True,
                id="lab-weak-outer",
            )
            yield Checkbox(
                "Probe inner PAP before MS-CHAPv2",
                value=True,
                id="lab-inner-pap",
            )
            yield Checkbox(
                "Flag empty MS-CHAPv2 responses",
                value=True,
                id="lab-empty-mschap",
            )
            yield Checkbox(
                "Answer DHCP on the lab BSSID (isolated 10.99.0.0/24)",
                value=True,
                id="lab-dhcp",
            )
            yield Checkbox(
                "Request client certificates during EAP-TLS",
                value=True,
                id="lab-client-cert",
            )
            yield Label("Duration", classes="field-label")
            yield Select(
                [(f"{minutes} minute{'s' if minutes > 1 else ''}", minutes * 60)
                 for minutes in (5, 10, 15, 30, 60)],
                value=300,
                allow_blank=False,
                id="lab-duration",
            )
            with Horizontal(id="buttons"):
                yield Button("Start EAP Lab", variant="warning", id="start")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            duration = self.query_one("#lab-duration", Select).value
            if not isinstance(duration, int):
                self.dismiss(None)
                return
            assessment = self.query_one("#lab-assessment", Checkbox).value
            self.dismiss(
                EapLabLaunchConfig(
                    timeout=duration,
                    eviction=self.query_one("#lab-eviction", Checkbox).value,
                    request_client_cert=self.query_one("#lab-client-cert", Checkbox).value,
                    eap_methods=self.default_methods,
                    security_assessment=assessment,
                    weak_outer_first=(
                        assessment
                        and self.query_one("#lab-weak-outer", Checkbox).value
                    ),
                    probe_inner_pap=(
                        assessment
                        and self.query_one("#lab-inner-pap", Checkbox).value
                    ),
                    probe_empty_mschap=(
                        assessment
                        and self.query_one("#lab-empty-mschap", Checkbox).value
                    ),
                    lab_dhcp=assessment and self.query_one("#lab-dhcp", Checkbox).value,
                ),
            )
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)
