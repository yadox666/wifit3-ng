from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from wifit3.dot11.enterprise import EAP_TYPE_NAMES, TLS_EAP_TYPES
from wifit3.models import AccessPoint
from wifit3.wlan.enterprise_risk import enterprise_findings, tls_cipher_name


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
    else:
        lines.append("  [dim]Not run. The probe stops before inner authentication.[/dim]")

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


class EnterprisePanel(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "dismiss", "Close", show=False)]

    DEFAULT_CSS = """
    EnterprisePanel { align: center middle; background: $background 70%; }
    EnterprisePanel > #enterprise-box {
        width: 90%; max-width: 120; height: 90%;
        border: round $primary; background: $panel; padding: 1 2;
    }
    #enterprise-title { height: 2; text-style: bold; }
    #enterprise-systems { height: 1fr; }
    .enterprise-system { width: 100%; height: auto; margin-bottom: 1; }
    #enterprise-actions { height: 3; }
    #enterprise-probe, #enterprise-eap-lab, #enterprise-save-report, #enterprise-close { width: 1fr; }
    """

    def __init__(self, systems: Iterable[AccessPoint], *, probing: bool = False) -> None:
        super().__init__()
        self._systems = tuple(systems)
        self._probing = probing

    def compose(self) -> ComposeResult:
        summaries = [
            Static(_system_summary(ap), classes="enterprise-system")
            for ap in self._systems
        ]
        with Vertical(id="enterprise-box"):
            yield Static(
                f"ENTERPRISE ASSESSMENT · {len(self._systems)} observed system(s)",
                id="enterprise-title",
            )
            yield VerticalScroll(
                Static(_infrastructure_summary(self._systems), classes="enterprise-system"),
                *summaries,
                id="enterprise-systems",
            )
            with Horizontal(id="enterprise-actions"):
                probe = Button(
                    "Cancel active probe" if self._probing else "Run active outer-EAP probe",
                    id="enterprise-probe",
                    variant="error" if self._probing else "warning",
                )
                probe.tooltip = (
                    "Cancel the running Enterprise probe"
                    if self._probing else
                    "Associates with an anonymous identity and stops before inner authentication"
                )
                yield probe
                yield Button(
                    "Start PEAP EAP lab honeypot",
                    id="enterprise-eap-lab",
                    variant="warning",
                )
                yield Button("Save report to Vault", id="enterprise-save-report")
                yield Button("Close", id="enterprise-close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "enterprise-probe":
            self.dismiss("cancel_probe" if self._probing else "probe")
        elif event.button.id == "enterprise-eap-lab":
            self.dismiss("eap_lab")
        elif event.button.id == "enterprise-save-report":
            self.dismiss("save_report")
        elif event.button.id == "enterprise-close":
            self.dismiss(None)
