"""Compact, expandable presentation of passive network metadata."""
from __future__ import annotations

import time
from typing import Iterable

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, Static

from wifit3.wlan.network_metadata import NetworkFact, NetworkMetadata


_LABELS = {
    "ipv4_addresses": "IPv4",
    "ipv6_addresses": "IPv6",
    "ipv4_networks": "IPv4 ranges",
    "ipv6_prefixes": "IPv6 prefixes",
    "gateways": "Gateways",
    "dhcp_servers": "DHCP servers",
    "dns_servers": "DNS servers",
    "domains": "Domains",
    "websites": "Websites",
    "gateway_reachability": "Gateway reached",
    "dns_reachability": "DNS reached",
    "connectivity": "Connectivity",
    "portal_status": "Portal assessment",
    "captive_portals": "Captive portal",
}
_ORDER = tuple(_LABELS)
_VALUE_LABELS = {
    "internet_confirmed": "Internet confirmed",
    "portal_observed": "Captive portal observed",
    "portal_suspected": "Captive portal suspected",
    "limited": "Limited or blocked",
    "inconclusive": "Inconclusive",
    "not_detected": "Not detected by HTTP probe",
    "intercepted": "Connectivity check intercepted",
}

_CLIENT_POPUP_ORDER = (
    "ipv4_addresses",
    "ipv6_addresses",
    "ipv4_networks",
    "ipv6_prefixes",
    "gateways",
    "dhcp_servers",
    "dns_servers",
    "domains",
    "websites",
    "connectivity",
    "portal_status",
    "captive_portals",
)


def client_network_details(
    metadata: NetworkMetadata | None,
    client_mac: str,
) -> str:
    """Compact client-specific network evidence for the client detail popup."""
    rows = ["[bold cyan]NETWORK[/bold cyan]"]
    if metadata is None:
        return "\n".join(rows + ["[dim]No network observations for this client.[/dim]"])
    with metadata.lock:
        client = metadata.clients.get(client_mac.casefold())
        client_facts = client.facts if client is not None else {}
        if not client_facts.get("ipv4_addresses") and not client_facts.get("ipv6_addresses"):
            rows.append("[dim]Client IP:[/dim] not observed")
        for kind in _CLIENT_POPUP_ORDER:
            values = client_facts.get(kind, [])
            if not values:
                continue
            if kind == "websites":
                rows.append(f"[dim]Websites ({len(values)}):[/dim]")
                rows.extend(
                    f"  {escape(fact.value)}"
                    for fact in _recent(values, limit=None)
                )
                continue
            rendered = ", ".join(
                escape(_VALUE_LABELS.get(fact.value, fact.value))
                for fact in _recent(values, limit=3)
            )
            rows.append(f"[dim]{escape(_LABELS[kind])}:[/dim] {rendered}")
        for kind in (
            "ipv4_networks",
            "ipv6_prefixes",
            "gateways",
            "dhcp_servers",
            "dns_servers",
            "domains",
            "connectivity",
            "portal_status",
            "captive_portals",
        ):
            if client_facts.get(kind):
                continue
            values = metadata.facts.get(kind, [])
            if not values:
                continue
            rendered = ", ".join(
                escape(_VALUE_LABELS.get(fact.value, fact.value))
                for fact in _recent(values, limit=3)
            )
            rows.append(f"[dim]{escape(_LABELS[kind])} (AP):[/dim] {rendered}")
        if len(rows) == 2 and rows[-1].endswith("not observed"):
            rows.append("[dim]No network observations for this client.[/dim]")
        evidence_time = client.last_seen if client is not None else metadata.last_seen
        rows.append(
            f"[dim]Last network evidence:[/dim] "
            f"{escape(_age(evidence_time, time.time()))}"
        )
    return "\n".join(rows)


class NetworkMetadataPanel(Vertical):
    """One-line summary that opens into evidence-aware AP/client details."""

    DEFAULT_CSS = """
    NetworkMetadataPanel {
        width: 100%; height: auto; max-height: 14;
        border: round $accent-darken-1; background: $surface-lighten-1;
    }
    NetworkMetadataPanel .network-toggle {
        width: 100%; min-width: 0; height: 1; min-height: 1;
        border: none; margin: 0; padding: 0 1;
        background: $surface-lighten-1; color: $text;
        content-align: left middle;
    }
    NetworkMetadataPanel .network-toggle:hover,
    NetworkMetadataPanel .network-toggle:focus {
        background: $accent-darken-2; text-style: bold;
    }
    NetworkMetadataPanel .network-details {
        width: 100%; height: 11;
        padding: 0 2 1 2; color: $text;
        overflow-y: auto; scrollbar-size-vertical: 1;
    }
    NetworkMetadataPanel .network-details-content {
        width: 100%; height: auto;
    }
    """

    def __init__(self, *, client_mac: str | None = None, id: str | None = None) -> None:
        super().__init__(id=id)
        self.client_mac = client_mac.casefold() if client_mac else None
        self.metadata: NetworkMetadata | None = None
        self.live = False
        self.expanded = False
        self._last_signature: tuple | None = None

    def compose(self) -> ComposeResult:
        yield Button("", classes="network-toggle")
        details = VerticalScroll(
            Static("", classes="network-details-content"),
            classes="network-details",
        )
        details.display = False
        yield details

    def on_mount(self) -> None:
        self._paint()

    def set_metadata(
        self,
        metadata: NetworkMetadata | None,
        *,
        live: bool,
        client_mac: str | None = None,
    ) -> None:
        self.metadata = metadata
        self.live = live
        if client_mac is not None:
            self.client_mac = client_mac.casefold()
        signature = self._content_signature()
        if self.is_mounted and signature != self._last_signature:
            self._paint()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if not event.button.has_class("network-toggle"):
            return
        self.expanded = not self.expanded
        self._last_signature = None
        self._paint()
        event.stop()

    def _paint(self) -> None:
        button = self.query_one(".network-toggle", Button)
        details = self.query_one(".network-details", VerticalScroll)
        content = details.query_one(".network-details-content", Static)
        metadata = self.metadata
        if metadata is None:
            button.label = self._summary()
            content.update(self._details())
        else:
            with metadata.lock:
                button.label = self._summary()
                content.update(self._details())
        details.display = self.expanded
        self._last_signature = self._content_signature()

    def _content_signature(self) -> tuple:
        """Skip destructive Textual repaints when only packet timestamps changed."""
        metadata = self.metadata
        if metadata is None:
            return (None, self.live, self.client_mac, self.expanded)
        with metadata.lock:
            selected = self._facts()
            visible = tuple(
                (
                    kind,
                    tuple(
                        (
                            fact.value,
                            fact.source,
                            fact.confidence,
                            bool(fact.expires_at and fact.expires_at < time.time()),
                        )
                        for fact in values
                    ),
                )
                for kind, values in sorted(selected.items())
            )
            global_values = ()
            if self.client_mac:
                global_values = tuple(
                    (
                        kind,
                        tuple(fact.value for fact in metadata.facts.get(kind, ())),
                    )
                    for kind in ("ipv4_networks", "ipv6_prefixes", "gateways", "dns_servers")
                )
            # Expanded evidence ages need only minute-level repainting.
            age_bucket = int(time.time() // 60) if self.expanded else 0
            return (
                id(metadata), self.live, self.client_mac, self.expanded,
                visible, global_values, age_bucket,
            )

    def _facts(self) -> dict[str, list[NetworkFact]]:
        metadata = self.metadata
        if metadata is None:
            return {}
        if self.client_mac:
            client = metadata.clients.get(self.client_mac)
            return client.facts if client is not None else {}
        return metadata.facts

    def _summary(self) -> str:
        arrow = "▾" if self.expanded else "▸"
        state = "[bold green]● LIVE[/]" if self.live else "[dim]HISTORY[/]"
        facts = self._facts()
        if not facts:
            suffix = "waiting for DHCP / RA" if self.live else "no observations"
            return f"{arrow}  [bold cyan]NETWORK[/]  {state}  [dim]{suffix}[/]"
        network = _latest_value(facts, "ipv4_networks") or _latest_value(
            facts, "ipv6_prefixes",
        )
        gateway = _latest_value(facts, "gateways")
        dns = _latest_value(facts, "dns_servers")
        portal_facts = facts.get("captive_portals", [])
        portal_status = facts.get("portal_status", [])
        portal = _portal_state(portal_facts, portal_status)
        portal_probability = _portal_probability(portal_facts, portal_status)
        connectivity = _latest_value(facts, "connectivity")
        chips = []
        if network:
            chips.append(f"[cyan]{escape(network)}[/]")
        if gateway:
            chips.append(f"[dim]GW[/] {escape(gateway)}")
        if dns:
            chips.append(f"[dim]DNS[/] {escape(dns)}")
        websites = facts.get("websites", [])
        if websites:
            chips.append(f"[dim]Websites[/] {len(websites)}")
        if connectivity:
            chips.append(_connectivity_chip(connectivity))
        chips.append(_portal_chip(portal, portal_probability))
        return f"{arrow}  [bold cyan]NETWORK[/]  {state}  " + "  •  ".join(chips)

    def _details(self) -> str:
        metadata = self.metadata
        facts = self._facts()
        if metadata is None or not facts:
            return (
                "[dim]Infrastructure metadata appears here when DHCP, IPv6 router "
                "advertisements, ARP, or a portal redirect is observed.[/dim]"
            )
        lines = []
        if self.client_mac:
            lines.append(f"[bold]CLIENT[/]  {escape(self.client_mac)}")
        else:
            lines.append(
                f"[bold]ACCESS POINT[/]  {escape(metadata.bssid)}"
                + (f"  [dim]{escape(metadata.ssid)}[/]" if metadata.ssid else "")
            )
        now = time.time()
        for kind in _ORDER:
            values = facts.get(kind, [])
            if not values:
                continue
            if kind in {"captive_portals", "portal_status"}:
                probability = _portal_probability(
                    facts.get("captive_portals", []),
                    facts.get("portal_status", []),
                )
                likelihood = (
                    f"{probability}% likelihood"
                    if probability is not None
                    else "likelihood unknown"
                )
                label = (
                    f"{_LABELS[kind]} · "
                    f"{_portal_state(facts.get('captive_portals', []), facts.get('portal_status', []))} · "
                    f"{likelihood}"
                )
            else:
                label = _LABELS[kind]
            if kind == "websites":
                lines.append(f"[dim]{escape(label)} ({len(values)})[/]")
                lines.extend(
                    f"  {_render_fact(fact, now, kind)}"
                    for fact in _recent(values, limit=None)
                )
                continue
            rendered = ", ".join(
                _render_fact(fact, now, kind)
                for fact in _recent(values, limit=4)
            )
            lines.append(f"[dim]{escape(label)}[/]  {rendered}")
        if self.client_mac:
            global_facts = metadata.facts
            missing = [
                kind for kind in ("ipv4_networks", "ipv6_prefixes", "gateways", "dns_servers")
                if kind not in facts and global_facts.get(kind)
            ]
            if missing:
                lines.append(
                    "[dim italic]AP-wide: [/dim italic]"
                    + "  •  ".join(
                        f"{_LABELS[kind]} {escape(_latest_value(global_facts, kind) or '')}"
                        for kind in missing
                    )
                )
        lines.append(
            f"[dim]Last evidence {escape(_age(metadata.last_seen, now))} · "
            "advertised values are not independently verified[/dim]"
        )
        return "\n".join(lines)


def _recent(
    values: Iterable[NetworkFact],
    limit: int | None = 4,
) -> list[NetworkFact]:
    recent = sorted(values, key=lambda fact: fact.last_seen, reverse=True)
    return recent if limit is None else recent[:limit]


def _latest_value(facts: dict[str, list[NetworkFact]], kind: str) -> str | None:
    values = facts.get(kind)
    return max(values, key=lambda fact: fact.last_seen).value if values else None


def _render_fact(fact: NetworkFact, now: float, kind: str | None = None) -> str:
    stale = (
        fact.expires_at is not None and fact.expires_at < now
    ) or now - fact.last_seen > 86400
    badge = {
        "observed": "[green]observed[/]",
        "advertised": "[cyan]advertised[/]",
        "inferred": "[yellow]inferred[/]",
    }[fact.confidence]
    historical = " [dim italic]historical[/]" if stale else ""
    return (
        f"[bold]{escape(_VALUE_LABELS.get(fact.value, fact.value))}[/] ({badge}, "
        f"[dim]{escape(fact.source)} · {_age(fact.last_seen, now)}[/]){historical}"
    )


def _portal_state(
    values: list[NetworkFact],
    assessments: list[NetworkFact] | None = None,
) -> str:
    if any(fact.confidence == "observed" for fact in values):
        return "Observed"
    if any(fact.confidence == "advertised" for fact in values):
        return "Declared"
    if values:
        return "Suspected"
    latest = max(assessments or [], key=lambda fact: fact.last_seen, default=None)
    if latest is not None and latest.value == "intercepted":
        return "Suspected"
    if latest is not None and latest.value == "not_detected":
        return "Unlikely"
    return "Not observed"


def _portal_probability(
    values: list[NetworkFact],
    assessments: list[NetworkFact] | None = None,
) -> int | None:
    """Return a conservative evidence score, not a population-based prior."""
    if not values:
        latest = max(assessments or [], key=lambda fact: fact.last_seen, default=None)
        if latest is None:
            return None
        return 90 if latest.value == "intercepted" else 5
    scores = []
    for fact in values:
        if fact.source in {"http_redirect", "http_connectivity_redirect"}:
            scores.append(99)
        elif fact.source in {"dhcp_option_114", "ipv6_option_37"}:
            scores.append(95)
        elif fact.confidence == "observed":
            scores.append(98)
        elif fact.confidence == "advertised":
            scores.append(90)
        else:
            scores.append(60)
    independent_sources = len({fact.source for fact in values})
    return min(99, max(scores) + max(0, independent_sources - 1) * 2)


def _portal_chip(state: str, probability: int | None) -> str:
    likelihood = f" · {probability}%" if probability is not None else ""
    if state == "Observed":
        return f"[black on yellow] PORTAL OBSERVED{likelihood} [/]"
    if state == "Declared":
        return f"[black on cyan] PORTAL DECLARED{likelihood} [/]"
    if state == "Suspected":
        return f"[yellow]PORTAL SUSPECTED{likelihood}[/]"
    if state == "Unlikely":
        return "[green]NO CAPTIVE PORTAL DETECTED[/]"
    return "[dim]portal likelihood unknown[/]"


def _connectivity_chip(value: str) -> str:
    if value == "internet_confirmed":
        return "[black on green] INTERNET [/]"
    if value in {"portal_observed", "portal_suspected"}:
        return "[black on yellow] PORTAL [/]"
    if value == "limited":
        return "[yellow]LIMITED[/]"
    return "[dim]connectivity unknown[/]"


def _age(timestamp: float, now: float) -> str:
    seconds = max(0, int(now - timestamp))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"
