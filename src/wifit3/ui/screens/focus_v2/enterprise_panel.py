from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, Select, Static

from wifit3.campaigns.eap_lab_config import (
    channels_for_lab_iface,
    default_lab_channel,
    lab_host_ifaces,
)
from wifit3.chips.products import ALFA
from wifit3.dot11.enterprise import EAP_TYPE_NAMES, TLS_EAP_TYPES
from wifit3.models import AccessPoint
from wifit3.wlan.enterprise_risk import enterprise_findings, tls_cipher_name

_MARKUP_RE = re.compile(r"\[/?[^\]]+\]")


@dataclass(frozen=True, slots=True)
class EnterpriseLabChoice:
    """Shared radio options for the outer probe and the PEAP honeypot."""

    action: str
    iface_name: str = ""
    lab_channel: int | None = None
    record_pcap: bool = True


def assessment_markdown(systems: tuple[AccessPoint, ...]) -> str:
    """Plain Markdown of the on-screen assessment. Markup only; no secrets added."""
    body = "\n\n".join(
        [_strip_markup(_infrastructure_summary(systems))]
        + [_strip_markup(_system_summary(ap)) for ap in systems]
    )
    when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"# Enterprise assessment\n\nSaved {when}\n\n{body}\n"


def _strip_markup(text: str) -> str:
    return _MARKUP_RE.sub("", text)


def _card_label(iface) -> str:
    return (
        getattr(getattr(iface, "driver", None), "product_name", None)
        or getattr(iface, "product_name", None)
        or getattr(iface, "chipset", None)
        or "card"
    )


def _is_awus1900(iface) -> bool:
    """RTL8814AU retail AWUS1900. Dual-band; not the 2.4 GHz AR9271 AWUS036NHA."""
    chipset = str(getattr(iface, "chipset", "") or "")
    return _card_label(iface) == ALFA.AWUS1900 or "8814" in chipset


def _initial_host_name(hosts, preferred_name: str) -> str:
    """Pinned card wins. Otherwise the AWUS1900, the dual-band adapter on this bench."""
    names = {member.name for member in hosts}
    if preferred_name in names:
        return preferred_name
    for member in hosts:
        if _is_awus1900(member):
            return member.name
    return hosts[0].name if hosts else ""


def _method_names(methods: Iterable[int]) -> str:
    return ", ".join(
        EAP_TYPE_NAMES.get(method, f"EAP type {method}")
        for method in sorted(methods)
    ) or "not observed"


def _coverage(ap: AccessPoint) -> list[tuple[str, bool, str]]:
    profile = ap.enterprise
    methods = profile.server_eap_types | profile.client_eap_types
    tls_expected = bool(methods & TLS_EAP_TYPES)
    return [
        ("Enterprise advertisement", True, "AKM observed in AP security information"),
        (
            "EAP exchange",
            profile.eap_packets > 0,
            f"{profile.eap_packets} packet(s)" if profile.eap_packets else "waiting for a client exchange",
        ),
        (
            "Method negotiation",
            bool(methods),
            _method_names(methods),
        ),
        (
            "Outer TLS",
            not tls_expected or bool(profile.tls_versions or profile.tls_cipher_suites),
            (
                ", ".join(sorted(profile.tls_versions)) or "parameters not observed"
                if tls_expected else "not required by observed outer method"
            ),
        ),
        (
            "TLS ClientHello",
            not tls_expected or bool(
                profile.tls_client_versions or profile.tls_client_cipher_suites
            ),
            (
                ", ".join(sorted(profile.tls_client_versions)) or "offers not observed"
                if tls_expected else "not required by observed outer method"
            ),
        ),
        (
            "RADIUS certificate",
            not tls_expected or bool(profile.certificates),
            (
                f"{len(profile.certificates)} certificate(s)"
                if profile.certificates else
                ("not visible yet" if tls_expected else "not required by observed outer method")
            ),
        ),
        (
            "EAP outcome",
            bool(profile.eap_successes or profile.eap_failures),
            f"{profile.eap_successes} success / {profile.eap_failures} failure",
        ),
        (
            "Active Enterprise probe",
            profile.probe_attempts > 0,
            (
                f"{profile.probe_last_status}: {profile.probe_last_detail}"
                if profile.probe_last_status else "not run"
            ),
        ),
    ]


def _infrastructure_summary(systems: tuple[AccessPoint, ...]) -> str:
    channels = sorted({ap.channel for ap in systems})
    methods_by_ap = {
        ap.bssid: ap.enterprise.server_eap_types | ap.enterprise.client_eap_types
        for ap in systems
    }
    leaf_certificates = {
        ap.bssid: next(iter(ap.enterprise.certificates), None)
        for ap in systems
    }
    observed_leafs = {value for value in leaf_certificates.values() if value}
    shared_leafs = {
        fingerprint
        for fingerprint in observed_leafs
        if sum(value == fingerprint for value in leaf_certificates.values()) > 1
    }
    lines = [
        "[bold]Infrastructure correlation[/bold]",
        f"  Systems: {len(systems)} · channels: {', '.join(map(str, channels))}",
    ]
    method_sets = [methods for methods in methods_by_ap.values() if methods]
    if method_sets:
        union = set().union(*method_sets)
        intersection = set.intersection(*method_sets) if len(method_sets) > 1 else union
        lines.append(f"  Methods observed anywhere: {_method_names(union)}")
        if union != intersection:
            lines.append(
                "  [yellow]Configuration variance:[/yellow] "
                f"methods common to every observed system: {_method_names(intersection)}"
            )
    pmf_states = {(ap.pmf_capable, ap.pmf_required) for ap in systems}
    if len(pmf_states) > 1:
        lines.append("  [yellow]Configuration variance:[/yellow] PMF posture differs by BSSID")
    if len(observed_leafs) > 1:
        lines.append(
            f"  [cyan]RADIUS pool:[/cyan] {len(observed_leafs)} different leaf certificates observed"
        )
    if shared_leafs:
        short = ", ".join(sorted(fingerprint[:12] for fingerprint in shared_leafs))
        lines.append(f"  Shared RADIUS leaf certificate(s): {short}")
    if not observed_leafs:
        lines.append("  [dim]No leaf certificate is available for RADIUS correlation yet.[/dim]")
    return "\n".join(lines)


def _system_summary(ap: AccessPoint) -> str:
    profile = ap.enterprise
    methods = profile.server_eap_types | profile.client_eap_types
    lines = [
        f"[bold cyan]{escape(ap.ssid or '<hidden>')}[/bold cyan]",
        f"[dim]{escape(ap.bssid)} · channel {ap.channel} · {escape(ap.encryption or 'Unknown')}[/dim]",
        "",
        "[bold]Observed authentication[/bold]",
        f"  Server requests: {_method_names(profile.server_eap_types)}",
        f"  Client responses: {_method_names(profile.client_eap_types)}",
        f"  Client NAK alternatives: {_method_names(profile.nak_eap_types)}",
        (
            f"  EAP traffic: {profile.eap_requests} request / {profile.eap_responses} response"
            f" · {profile.eap_successes} success / {profile.eap_failures} failure"
        ),
    ]
    if profile.first_seen is not None:
        first = datetime.fromtimestamp(profile.first_seen).strftime("%H:%M:%S")
        last = datetime.fromtimestamp(profile.last_seen or profile.first_seen).strftime("%H:%M:%S")
        lines.append(f"  Window: {first}–{last}")

    lines.extend(["", "[bold]TLS and certificates[/bold]"])
    lines.append(
        f"  Client versions: {', '.join(sorted(profile.tls_client_versions)) or 'not observed'}"
    )
    lines.append(f"  Observed versions: {', '.join(sorted(profile.tls_versions)) or 'not observed'}")
    lines.append(
        "  Client cipher offers: "
        + (
            ", ".join(
                tls_cipher_name(cipher)
                for cipher in sorted(profile.tls_client_cipher_suites)
            )
            or "not observed"
        )
    )
    lines.append(
        "  Selected ciphers: "
        + (
            ", ".join(tls_cipher_name(cipher) for cipher in sorted(profile.tls_cipher_suites))
            or "not observed"
        )
    )
    if profile.tls_server_names:
        lines.append(f"  Client SNI: {escape(', '.join(sorted(profile.tls_server_names)))}")
    if profile.tls_supported_groups:
        groups = ", ".join(f"0x{group:04X}" for group in sorted(profile.tls_supported_groups))
        lines.append(f"  Supported groups: {groups}")
    if profile.tls_signature_algorithms:
        algorithms = ", ".join(
            f"0x{algorithm:04X}" for algorithm in sorted(profile.tls_signature_algorithms)
        )
        lines.append(f"  Signature algorithms: {algorithms}")
    if profile.certificates:
        for certificate in profile.certificates.values():
            expiry = (
                datetime.fromtimestamp(certificate.not_after).strftime("%Y-%m-%d")
                if certificate.not_after is not None else "unknown expiry"
            )
            key = " ".join(
                str(value) for value in (
                    certificate.public_key_algorithm,
                    certificate.public_key_bits,
                ) if value is not None
            ) or "unknown key"
            lines.append(
                f"  {certificate.fingerprint[:12]} · {escape(key)}"
                f" · {escape(certificate.signature_algorithm or 'unknown signature')} · expires {expiry}"
            )
            if certificate.subject:
                lines.append(f"    Subject: {escape(certificate.subject)}")
            if certificate.issuer:
                lines.append(f"    Issuer: {escape(certificate.issuer)}")
            if certificate.san_dns:
                lines.append(f"    SAN: {escape(', '.join(certificate.san_dns))}")
            if certificate.extended_key_usage:
                lines.append(
                    f"    EKU: {escape(', '.join(certificate.extended_key_usage))}"
                )
            if certificate.is_ca is not None:
                lines.append(f"    CA certificate: {'yes' if certificate.is_ca else 'no'}")
    else:
        lines.append("  Certificate: not observed")

    lines.extend(["", "[bold]Test coverage and gaps[/bold]"])
    for label, complete, detail in _coverage(ap):
        marker = "[green]✓[/green]" if complete else "[yellow]○[/yellow]"
        lines.append(f"  {marker} {label}: [dim]{escape(detail)}[/dim]")

    findings = enterprise_findings(ap)
    lines.extend(["", "[bold]Assessment[/bold]"])
    if findings:
        colors = {0: "cyan", 1: "yellow", 2: "orange1", 3: "red", 4: "bold red"}
        for finding in findings:
            lines.append(
                f"  [{colors[finding.severity]}]●[/] {escape(finding.label)}"
                f" [dim]· {escape(finding.evidence)} · {finding.confidence} confidence[/dim]"
            )
    else:
        lines.append("  [green]●[/green] No passive weakness observed")

    lines.extend(["", "[bold]Active probe[/bold]"])
    if profile.probe_attempts:
        when = (
            datetime.fromtimestamp(profile.probe_last_seen).strftime("%Y-%m-%d %H:%M:%S")
            if profile.probe_last_seen is not None else "unknown time"
        )
        lines.append(
            f"  Attempts: {profile.probe_attempts} · "
            f"{escape(profile.probe_last_status or 'unknown')} · {when}"
        )
        if profile.probe_last_detail:
            lines.append(f"  {escape(profile.probe_last_detail)}")
        for note in profile.probe_last_compatibility_notes[:6]:
            lines.append(f"  [dim]• {escape(note)}[/dim]")
        if profile.probe_last_mschap_challenge_path:
            lines.append(
                f"  MS-CHAPv2 challenge: [dim]{escape(profile.probe_last_mschap_challenge_path)}[/dim]"
            )
        if profile.probe_last_report_path:
            lines.append(
                f"  Report: [dim]{escape(profile.probe_last_report_path)}[/dim]"
            )
    else:
        lines.append(
            "  [dim]Not run. Probe surveys outer EAP/TLS and captures inner MS-CHAPv2 "
            "challenges without sending a password.[/dim]"
        )

    if profile.probe_history:
        lines.append("  [bold]Probe history[/bold]")
        for run in reversed(profile.probe_history[-5:]):
            when = datetime.fromtimestamp(run.started_at).strftime("%Y-%m-%d %H:%M:%S")
            duration = max(0.0, run.ended_at - run.started_at)
            method = (
                EAP_TYPE_NAMES.get(run.eap_method, f"EAP type {run.eap_method}")
                if run.eap_method is not None else "method unknown"
            )
            lines.append(
                f"    {when} · {escape(run.status)} · {escape(method)} · {duration:.1f}s"
            )
        latest = profile.probe_history[-1]
        if latest.events:
            lines.append("  [bold]Latest probe timeline[/bold]")
            for event in latest.events[-20:]:
                stamp = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S.%f")[:-3]
                arrow = {"tx": "→", "rx": "←", "local": "·"}.get(event.direction, "·")
                suffix = (
                    f" · id {event.eap_identifier}"
                    if event.eap_identifier is not None else ""
                )
                lines.append(
                    f"    [dim]{stamp}[/dim] {arrow} {escape(event.phase)}: "
                    f"{escape(event.detail)}{suffix}"
                )

    lines.extend(["", f"[bold]Persisted EAP sessions ({len(profile.sessions)})[/bold]"])
    if profile.sessions:
        for session in sorted(profile.sessions, key=lambda item: item.last_seen, reverse=True)[:20]:
            observed = session.server_eap_types | session.client_eap_types
            when = datetime.fromtimestamp(session.last_seen).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(
                f"  {escape(session.client_id)} · {escape(session.source)}"
                f" · {escape(session.outcome)}"
                f" · {_method_names(observed)} · {session.eap_packets} packet(s) · {when}"
            )
    else:
        lines.append("  [dim]No complete or partial EAP session has been reconstructed yet.[/dim]")

    if methods & {21, 25, 43, 55}:
        lines.append(
            "  [dim]The tunneled inner method and client certificate validation remain unknown.[/dim]"
        )
    lines.append("  [dim]Absence of observed evidence is not proof of a secure configuration.[/dim]")
    return "\n".join(lines)


class EnterprisePanel(ModalScreen[EnterpriseLabChoice | None]):
    BINDINGS = [Binding("escape", "dismiss", "Close", show=False)]

    DEFAULT_CSS = """
    EnterprisePanel { align: center middle; background: $background 70%; }
    EnterprisePanel > #enterprise-box {
        width: 78; max-width: 92; height: auto;
        border: round $primary; background: $panel; padding: 1 2;
    }
    #enterprise-title { height: 1; text-style: bold; color: $accent; }
    #enterprise-hint { height: 1; color: $text-muted; margin-bottom: 1; }
    .lab-row { height: 3; }
    .lab-row .row-label {
        width: 14; height: 3; content-align: left middle; color: $text-muted;
    }
    .lab-row Select { width: 1fr; }
    #enterprise-channel { width: 28; max-width: 36; }
    #enterprise-pcap { width: 22; height: 3; margin-left: 1; }
    #enterprise-actions, #enterprise-actions-2 { height: 3; margin-top: 1; }
    #enterprise-actions Button, #enterprise-actions-2 Button { width: 1fr; margin: 0 1; }
    #enterprise-rule { height: 1; margin: 1 0 0 0; border-bottom: solid $primary; }
    #enterprise-systems {
        height: 12; margin-top: 1; border: round $boost;
        background: $surface; padding: 0 1;
    }
    .enterprise-system { width: 100%; height: auto; margin-bottom: 1; }
    """

    def __init__(
        self,
        systems: Iterable[AccessPoint],
        *,
        probing: bool = False,
        members: list | None = None,
        preferred_name: str = "",
        target_channel: int | None = None,
    ) -> None:
        super().__init__()
        self._systems = tuple(systems)
        self._probing = probing
        self._hosts = list(lab_host_ifaces(members or []))
        self._by_name = {member.name: member for member in self._hosts}
        self._preferred_name = _initial_host_name(self._hosts, preferred_name)
        first = self._systems[0] if self._systems else None
        self._target_channel = int(
            target_channel if target_channel is not None else (first.channel if first else 1)
        )

    def compose(self) -> ComposeResult:
        summaries = [
            Static(_system_summary(ap), classes="enterprise-system")
            for ap in self._systems
        ]
        host = self._by_name.get(self._preferred_name)
        with Vertical(id="enterprise-box"):
            yield Static(
                f"ENTERPRISE ASSESSMENT · {len(self._systems)} observed system(s)",
                id="enterprise-title",
            )
            yield Static(
                "Card, channel and PCAP apply to both labs",
                id="enterprise-hint",
            )
            with Horizontal(classes="lab-row"):
                yield Label("Wi-Fi card", classes="row-label")
                yield Select(
                    self._iface_options(),
                    value=host.name if host else Select.NULL,
                    allow_blank=not bool(self._hosts),
                    id="enterprise-iface",
                )
            with Horizontal(classes="lab-row"):
                yield Label("Channel", classes="row-label")
                yield Select(
                    self._channel_options(host),
                    value=default_lab_channel(host, self._target_channel),
                    allow_blank=False,
                    id="enterprise-channel",
                )
                yield Checkbox("Record PCAP", value=True, id="enterprise-pcap")
            with Horizontal(id="enterprise-actions"):
                probe = Button(
                    "Cancel AP test" if self._probing else "EAP AP test",
                    id="enterprise-probe",
                    variant="error" if self._probing else "warning",
                )
                probe.tooltip = (
                    "Cancel the running EAP AP test"
                    if self._probing else
                    "Outer/inner EAP against the real AP. Identities are asked next."
                )
                yield probe
                honeypot = Button(
                    "EAP clients test",
                    id="enterprise-eap-lab",
                    variant="warning",
                )
                honeypot.tooltip = (
                    "PEAP honeypot for client phones on the card and channel above. "
                    "Any username is accepted. PAP and complete MS-CHAPv2 go to the Vault."
                )
                yield honeypot
            with Horizontal(id="enterprise-actions-2"):
                yield Button("Save Report", id="enterprise-save-report", variant="primary")
                yield Button("Close", id="enterprise-close")
            yield Static("", id="enterprise-rule")
            yield VerticalScroll(
                Static(_infrastructure_summary(self._systems), classes="enterprise-system"),
                *summaries,
                id="enterprise-systems",
            )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "enterprise-iface":
            return
        host = self._by_name.get(event.value if isinstance(event.value, str) else "")
        channel = self.query_one("#enterprise-channel", Select)
        channel.set_options(self._channel_options(host))
        channel.value = default_lab_channel(host, self._target_channel)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "enterprise-probe":
            self.dismiss(self._choice("cancel_probe" if self._probing else "probe"))
        elif event.button.id == "enterprise-eap-lab":
            self.dismiss(self._choice("eap_lab"))
        elif event.button.id == "enterprise-save-report":
            self.dismiss(self._choice("save_report"))
        elif event.button.id == "enterprise-close":
            self.dismiss(None)

    def _choice(self, action: str) -> EnterpriseLabChoice:
        iface_value = self.query_one("#enterprise-iface", Select).value
        iface_name = iface_value if isinstance(iface_value, str) else ""
        host = self._by_name.get(iface_name)
        channel_value = self.query_one("#enterprise-channel", Select).value
        channel = channel_value if isinstance(channel_value, int) else self._target_channel
        allowed = set(channels_for_lab_iface(host, self._target_channel))
        if allowed and channel not in allowed:
            channel = default_lab_channel(host, self._target_channel)
        return EnterpriseLabChoice(
            action=action,
            iface_name=iface_name,
            lab_channel=channel,
            record_pcap=bool(self.query_one("#enterprise-pcap", Checkbox).value),
        )

    def _iface_options(self) -> list[tuple[str, str]]:
        return [
            (f"{_card_label(member)} · {member.name}", member.name)
            for member in self._hosts
        ] or [("No spoofable Wi-Fi card", "")]

    def _channel_options(self, host) -> list[tuple[str, int]]:
        channels = channels_for_lab_iface(host, self._target_channel)
        if not channels:
            channels = (self._target_channel,)
        return [
            (self._channel_label(channel), channel)
            for channel in channels
        ]

    def _channel_label(self, channel: int) -> str:
        band = "2.4 GHz" if channel <= 14 else "5 GHz"
        target = " (target)" if channel == self._target_channel else ""
        return f"{channel} · {band}{target}"
