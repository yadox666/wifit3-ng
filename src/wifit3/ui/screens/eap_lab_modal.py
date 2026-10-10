from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select

from wifit3.campaigns.eap_lab_config import (
    EapLabLaunchConfig,
    EnterpriseProbeConfig,
    distinct_lab_ssid,
    lab_identities_field_value,
    resolve_lab_identities,
)


def _option(label: str, tip: str, *, value: bool, id: str) -> Checkbox:
    """One-line option. The full sentence stays on the tooltip."""
    return Checkbox(label, value=value, id=id, tooltip=tip, compact=True)


class EapLabModal(ModalScreen[EapLabLaunchConfig | None]):
    """Configure the Enterprise EAP lab honeypot."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    EapLabModal { align: center middle; }
    EapLabModal #dialog {
        width: 52; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    EapLabModal #title {
        width: 100%; text-align: center; text-style: bold;
    }
    EapLabModal #description {
        width: 100%; height: 1; text-align: center;
        color: $text-muted; margin-bottom: 1;
    }
    EapLabModal Checkbox {
        width: 100%; height: 1; margin: 0; background: transparent;
    }
    EapLabModal .field-label { width: 100%; height: 1; margin-top: 1; }
    EapLabModal #lab-duration { width: 100%; }
    EapLabModal #buttons { height: 3; align: center middle; margin-top: 1; }
    EapLabModal #buttons Button { margin: 0 1; }
    """

    def __init__(
        self,
        ssid: str,
        channel: int,
        *,
        default_methods: tuple[int, ...],
        members: list | None = None,
        preferred_name: str = "",
        iface_name: str = "",
        lab_channel: int | None = None,
        record_pcap: bool = True,
    ) -> None:
        super().__init__()
        self.ssid = ssid
        self.channel = channel
        self.default_methods = default_methods
        self._iface_name = iface_name
        self._lab_channel = lab_channel if lab_channel is not None else channel
        self._record_pcap = record_pcap
        del members, preferred_name

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            lab_ssid = distinct_lab_ssid(self.ssid)
            yield Label("Enterprise EAP Lab Honeypot", id="title")
            description = Label(f"Twin {self.ssid} · untrusted TLS", id="description")
            description.tooltip = (
                f"Twin {self.ssid}: cloned beacon, untrusted TLS. "
                "Card, channel, and PCAP come from the Enterprise assessment. "
                "Inner PAP is a client vulnerability test; NAK or silence falls back "
                "to MS-CHAPv2. Any username the phone sends is accepted. "
                "PAP credentials and complete MS-CHAPv2 go to the Vault."
            )
            yield description
            yield _option(
                f"Distinct SSID ({lab_ssid})",
                f"Distinct lab SSID ({lab_ssid}) so phones list it separately from the real AP.",
                value=True,
                id="lab-distinct-ssid",
            )
            yield _option(
                "Evict real-AP clients",
                "Evict clients from the real AP (deauth + CSA + BTM). "
                "Off by default - pauses automatically while a phone joins the lab.",
                value=False,
                id="lab-eviction",
            )
            yield _option(
                "Client security assessment",
                "Client security assessment (untrusted certificate and downgrade probes).",
                value=True,
                id="lab-assessment",
            )
            yield _option(
                "Weaker outer EAP first",
                "Offer weaker outer EAP methods first (TTLS before PEAP, and so on).",
                value=True,
                id="lab-weak-outer",
            )
            yield _option(
                "Inner PAP, then MS-CHAPv2",
                "Offer inner PAP first (client vulnerability test). "
                "NAK or timeout falls back to MS-CHAPv2. PAP credentials are saved to the Vault.",
                value=True,
                id="lab-inner-pap",
            )
            yield _option(
                "Flag empty MS-CHAPv2",
                "Flag empty MS-CHAPv2 responses.",
                value=True,
                id="lab-empty-mschap",
            )
            yield _option(
                "Lab DHCP 10.99.0.0/24",
                "Answer DHCP on the lab BSSID (isolated 10.99.0.0/24).",
                value=True,
                id="lab-dhcp",
            )
            yield _option(
                "Request client certificate",
                "Request a client certificate (EAP-TLS only). Leave off for "
                "PEAP/MS-CHAPv2 - phones treat CertificateRequest as a "
                "user-certificate picker and leave.",
                value=False,
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
                    distinct_ssid=self.query_one("#lab-distinct-ssid", Checkbox).value,
                    lab_ssid=(
                        distinct_lab_ssid(self.ssid)
                        if self.query_one("#lab-distinct-ssid", Checkbox).value
                        else (self.ssid or "")
                    ),
                    record_pcap=self._record_pcap,
                    iface_name=self._iface_name,
                    lab_channel=self._lab_channel,
                ),
            )
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)


class EnterpriseProbeModal(ModalScreen[EnterpriseProbeConfig | None]):
    """Configure identities for the Enterprise deep lab probe."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    EnterpriseProbeModal { align: center middle; }
    EnterpriseProbeModal #dialog {
        width: 72; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    EnterpriseProbeModal #title {
        width: 1fr; text-align: center; text-style: bold; margin-bottom: 1;
    }
    EnterpriseProbeModal #description { height: auto; color: $text-muted; margin-bottom: 1; }
    EnterpriseProbeModal .field-label { margin-top: 1; }
    EnterpriseProbeModal #buttons { height: auto; align: center middle; margin-top: 1; }
    EnterpriseProbeModal #buttons Button { margin: 0 1; }
    """

    def __init__(self, ssid: str) -> None:
        super().__init__()
        self.ssid = ssid

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Enterprise deep lab probe", id="title")
            yield Label(
                f"Against {self.ssid}: PEAP/TTLS/TLS mapping and MS-CHAPv2 server challenge. "
                "No password is sent. Nothing is written to Vault - only the "
                "honeypot saves a complete MS-CHAPv2 capture. "
                "Default identity is LAB_USER from eap-lab/lab.env. Add more with commas.",
                id="description",
            )
            yield Label("Lab identities (comma-separated, no passwords)", classes="field-label")
            yield Input(
                value=lab_identities_field_value(),
                placeholder="labuser, lab-probe@eap-lab.local",
                id="lab-identities",
            )
            with Horizontal(id="buttons"):
                yield Button("Start probe", variant="warning", id="start")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self.dismiss(
                EnterpriseProbeConfig(
                    lab_identities=resolve_lab_identities(
                        self.query_one("#lab-identities", Input).value
                    ),
                ),
            )
            return
        self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)
