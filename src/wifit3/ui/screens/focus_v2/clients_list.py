"""Clients list: List of related client MAC addresses underneath the AP."""
from __future__ import annotations

from typing import TYPE_CHECKING

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static, Tooltip
from rich.text import Text

from wifit3.id import Fingerprint, vendor_for_mac
from wifit3.ui.mac_format import mac_address_text
from wifit3.ui.search_input import SearchInput, sync_search_input_has_text
from ...signal_bar import dbm_style
from ... import focus_model as fm

if TYPE_CHECKING:
    from wifit3.wlan.network_metadata import NetworkFact, NetworkMetadata


def _widget_id(mac: str) -> str:
    return "cl-" + mac.replace(":", "")


class ClientWidget(Horizontal):
    """A Client of the currently-focused target."""

    class DeauthRequested(Message):
        def __init__(self, mac: str) -> None:
            super().__init__()
            self.mac = mac

    class FingerprintClicked(Message):
        def __init__(
            self, mac: str, fingerprint: Fingerprint | None, details: str,
            offset: tuple[int, int],
        ) -> None:
            super().__init__()
            self.mac = mac
            self.fingerprint = fingerprint
            self.details = details
            self.offset = offset

    def __init__(self, client, **kwargs) -> None:
        is_fake = bool(getattr(client, "is_fake", False))
        is_historical = bool(getattr(client, "historical", False))
        classes = ["client-row"]
        if is_fake:
            classes.append("fake-client")
        if is_historical:
            classes.append("historical-client")
        super().__init__(id=_widget_id(client.mac), classes=" ".join(classes), **kwargs)
        self._client = client
        self._mac = client.mac
        self._is_fake = is_fake
        self._is_historical = is_historical
        self._history_reasons = set(getattr(client, "history_reasons", set()))
        self._fp = None if self._is_fake else client.fingerprint
        self._manufacturer = (
            "Fake-Connect" if self._is_fake else vendor_for_mac(client.mac) or ""
        )
        self._power = client.signal
        self._packets = client.packets
        self._ipv4_hint = ""

    def compose(self) -> ComposeResult:
        badge = (
            "[yellow]◈[/yellow]"
            if self._is_fake
            else "[dim]◌[/dim]"
            if self._is_historical
            else self._fp.emoji if self._fp else ""
        )
        self._fp_label = Label(badge, classes="cl-fp")
        self._mac_label = Label(mac_address_text(self._mac), classes="cl-bssid")
        self._mfr_label = Label(self._manufacturer, classes="cl-mfr")
        power = "--" if self._is_fake or self._is_historical else str(self._power)
        self._pwr_label = Label(
            Text(power, style="yellow" if self._is_fake else dbm_style(self._power)),
            classes="cl-pwr",
        )
        self._pkts_label = Label(
            "--" if self._is_historical else str(self._packets),
            classes="cl-pkts",
        )
        if self._is_fake:
            self._fp_label.tooltip = "Temporary fake client created by Fake-Connect"
            self._mac_label.tooltip = self._fp_label.tooltip
        elif self._is_historical:
            reasons = " and ".join(sorted(self._history_reasons)) or "observation"
            tooltip = f"Historical client · {reasons}"
            self._fp_label.tooltip = tooltip
            self._mac_label.tooltip = tooltip
            self._mfr_label.tooltip = tooltip
        elif self._fp is not None:
            self._fp_label.tooltip = self._fp.label
            self._fp_label.add_class("fp-known")
            self._mac_label.add_class("fp-known")
        self._deauth = Button("✕", classes="cl-deauth", tooltip="Deauthenticate Client")
        if self._is_fake or self._is_historical:
            self._deauth.disabled = True
            self._deauth.tooltip = (
                "Historical client; no active station to deauthenticate"
                if self._is_historical
                else "Use Disconnect to remove this fake client"
            )
        yield self._fp_label
        yield self._mac_label
        yield self._mfr_label
        yield self._pwr_label
        yield self._pkts_label
        yield self._deauth

    def update_stats(self, power: int, packets: int) -> None:
        """Repaint power/packets in place, only on a real change (a blind ``Label.update`` at 10 Hz
        wipes text selection and burns CPU)."""
        if power != self._power and not self._is_fake and not self._is_historical:
            self._power = power
            self._pwr_label.update(Text(str(power), style=dbm_style(power)))
        if packets != self._packets and not self._is_historical:
            self._packets = packets
            self._pkts_label.update(str(packets))
        manufacturer = (
            "Fake-Connect" if self._is_fake else vendor_for_mac(self._mac) or ""
        )
        if manufacturer != self._manufacturer:
            self._manufacturer = manufacturer
            self._repaint_mfr_label()

    def _repaint_mfr_label(self) -> None:
        ipv4 = self._ipv4_hint
        if ipv4 and self._manufacturer:
            self._mfr_label.update(f"{self._manufacturer}  {ipv4}")
        elif ipv4:
            self._mfr_label.update(ipv4)
        else:
            self._mfr_label.update(self._manufacturer)

    def set_ipv4_hint(self, ipv4: str) -> None:
        """Show a swept/observed IPv4 beside the vendor when known."""
        if self._is_fake:
            return
        ipv4 = ipv4.strip()
        if ipv4 == self._ipv4_hint:
            return
        self._ipv4_hint = ipv4
        self._repaint_mfr_label()
        if ipv4:
            base_tip = self._mac_label.tooltip or self._mac
            if ipv4 not in base_tip:
                self._mac_label.tooltip = f"{base_tip} · IPv4 {ipv4}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if self._is_fake:
            return
        self.post_message(self.DeauthRequested(self._mac))

    def set_deauth_enabled(self, enabled: bool) -> None:
        self._deauth.disabled = self._is_fake or self._is_historical or not enabled

    def on_click(self, event: events.Click) -> None:
        targets = (self._mac_label, self._mfr_label)
        if event.widget in targets or (self._fp is not None and event.widget is self._fp_label):
            self.post_message(
                self.FingerprintClicked(
                    self._mac, self._fp, fm.client_advertised_details(self._client),
                    (event.screen_x, event.screen_y),
                ))

    # Keyboard a11y: the mac label is not focusable, so focusing the row's ✕ surfaces the
    # fingerprint as a tooltip at the button (Textual otherwise shows tooltips on hover only).
    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
        if self._fp is None:
            return
        try:
            tooltip = self.screen.query_one(Tooltip)
        except Exception:
            return
        tooltip.update(self._fp.label)
        tooltip.absolute_offset = self._deauth.region.offset
        tooltip.display = True

    def on_descendant_blur(self, _event: events.DescendantBlur) -> None:
        try:
            self.screen.query_one(Tooltip).display = False
        except Exception:
            pass


class FingerprintModal(ModalScreen[None]):
    """A small popup showing a Client's vendor information."""

    BINDINGS = [Binding("escape", "dismiss", "Close", show=False)]

    DEFAULT_CSS = """
    FingerprintModal { background: $background 0%; }
    FingerprintModal > #fp-box {
        width: auto; max-width: 90%; height: auto; max-height: 90%;
        overflow-y: auto;
        border: round $primary; background: $panel; padding: 0 1;
    }
    """

    def __init__(
        self, mac: str, fp: Fingerprint | None, *, details: str = "",
        offset: tuple[int, int],
    ) -> None:
        super().__init__()
        self._mac = mac
        self._fp = fp
        self._details = details
        self._offset = offset

    def compose(self) -> ComposeResult:
        heading = f"{self._fp.emoji} {self._fp.label}" if self._fp else self._mac
        rows = [Label(heading)]
        rows.extend(Label(line) for line in self._details.splitlines()[1:] if line)
        oui = Text("OUI: ", style="dim")
        oui.append_text(mac_address_text(self._mac[:8], style="dim"))
        box = Vertical(
            *rows,
            Label(oui),
            id="fp-box",
        )
        box.styles.offset = self._offset
        yield box

    def on_mount(self) -> None:
        # The box's real size isn't known until after layout, so a click near the screen edge
        # would place it partly off-screen; clamp once the size is known.
        self.call_after_refresh(self._keep_on_screen)

    def _keep_on_screen(self) -> None:
        box = self.query_one("#fp-box")
        max_x = max(0, self.size.width - box.outer_size.width)
        max_y = max(0, self.size.height - box.outer_size.height)
        x, y = self._offset
        box.styles.offset = (max(0, min(x, max_x)), max(0, min(y, max_y)))

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:            # the transparent backdrop, not the box or its labels
            self.dismiss()


class ClientsList(Vertical):
    DEFAULT_CSS = """
    ClientsList #client-web-search-box {
        width: 100%; height: 3; min-height: 3;
        border: solid $primary;
        background: $surface;
        padding: 0; margin: 0;
    }
    ClientsList #client-web-search {
        width: 1fr; height: 1; min-height: 1;
        border: none; padding: 0 1; margin: 0;
        background: transparent;
    }
    ClientsList #client-web-search.-has-text {
        background: $surface-darken-2;
    }
    ClientsList #clear-client-web-search {
        width: 3; min-width: 3; max-width: 3;
        height: 1; min-height: 1;
        border: none; padding: 0; margin: 0;
        background: transparent;
        color: $text-muted;
        content-align: center middle;
    }
    ClientsList #clear-client-web-search:hover,
    ClientsList #clear-client-web-search:focus {
        background: $primary;
        color: $text;
    }
    ClientsList #client-pane {
        width: 100%; height: 1fr;
    }
    ClientsList #website-pane {
        width: 100%; height: 1fr;
        border-top: solid $primary;
    }
    ClientsList #website-title {
        width: 100%; height: 1;
        color: $text-muted; text-style: bold;
    }
    ClientsList #website-rows {
        width: 100%; height: 1fr;
        scrollbar-size-vertical: 1;
    }
    ClientsList #website-content {
        width: 100%; height: auto;
    }
    ClientsList #client-rows-live,
    ClientsList #client-rows-history {
        height: auto;
        width: 100%;
    }
    ClientsList #clients-history-separator {
        width: 100%;
        height: 1;
        text-align: center;
        content-align: center middle;
        color: $text-muted;
        text-style: bold;
        border-top: solid $primary-darken-1;
        margin: 1 0 0 0;
        padding-top: 0;
    }
    """

    def __init__(self, clients, **kwargs) -> None:
        super().__init__(**kwargs)
        self._clients = clients
        self._rows: dict[str, ClientWidget] = {}
        self._open_network_mode = False
        self._network_metadata: NetworkMetadata | None = None
        self._website_facts: list[NetworkFact] = []
        self._network_revision = -1
        self._search_text = ""
        self._associated_ap = None

    def compose(self) -> ComposeResult:
        search_box = Horizontal(
            SearchInput(
                placeholder="Search clients and website URLs…",
                compact=True,
                id="client-web-search",
            ),
            Button(
                "×",
                id="clear-client-web-search",
                tooltip="Clear search",
                compact=True,
            ),
            id="client-web-search-box",
        )
        search_box.display = False
        yield search_box
        with Vertical(id="client-pane"):
            ap_banner = Static("", id="associated-ap-banner", classes="associated-ap-banner")
            ap_banner.display = False
            yield ap_banner
            yield Button("Deauth all", id="deauth-all", classes="bcast-btn",
                         tooltip="Deauthenticate all clients (Broadcast)")
            with Horizontal(classes="client-columns"):
                yield Label("", classes="cl-fp")
                yield Label("CLIENT", classes="cl-bssid")
                yield Label("VENDOR", classes="cl-mfr")
                yield Label("PWR", classes="cl-pwr")
                yield Label("PKT", classes="cl-pkts")
                yield Label("", classes="cl-action")
            live_rows = []
            history_rows = []
            for c in self._clients:
                widget = ClientWidget(c)
                self._rows[c.mac] = widget
                if getattr(c, "historical", False):
                    history_rows.append(widget)
                else:
                    live_rows.append(widget)
            with VerticalScroll(id="client-rows"):
                yield Vertical(*live_rows, id="client-rows-live")
                yield Static(
                    "CLIENTS HISTORY",
                    id="clients-history-separator",
                )
                yield Vertical(*history_rows, id="client-rows-history")
        websites = Vertical(
            Label("WEBSITES (0)", id="website-title"),
            VerticalScroll(
                Static("[dim]Waiting for website traffic…[/dim]", id="website-content"),
                id="website-rows",
            ),
            id="website-pane",
        )
        websites.display = False
        yield websites

    def on_mount(self) -> None:
        self._update_title()
        self._update_history_separator()

    def _client_row_host(self, client) -> Vertical:
        historical = bool(getattr(client, "historical", False))
        selector = "#client-rows-history" if historical else "#client-rows-live"
        return self.query_one(selector, Vertical)

    def _update_history_separator(self) -> None:
        if not self.is_mounted:
            return
        separator = self.query_one("#clients-history-separator", Static)
        has_history = any(
            row._is_historical and row.display for row in self._rows.values()
        )
        separator.display = has_history

    def sync(self, clients) -> None:
        """Reconcile client row information to match ``clients``."""
        current = {c.mac for c in clients}
        for mac in list(self._rows):
            if mac not in current:
                self._remove_row(mac)
        for c in clients:
            row = self._rows.get(c.mac)
            historical = bool(getattr(c, "historical", False))
            if row is not None and row._is_historical != historical:
                self._remove_row(c.mac)
                row = None
            if row is None:
                if self.query(f"#{_widget_id(c.mac)}"):
                    continue
                widget = ClientWidget(c)
                self._rows[c.mac] = widget
                self._client_row_host(c).mount(widget)
            else:
                row.update_stats(c.signal, c.packets)
        self._apply_client_ipv4_hints()
        self._apply_client_filter()
        self._update_history_separator()
        self._update_title()

    def _remove_row(self, mac: str) -> None:
        row = self._rows.pop(mac, None)
        if row is not None:
            row.remove()

    def set_deauth_enabled(self, enabled: bool) -> None:
        """Enable/disable every deauth control (✕)."""
        for row in self._rows.values():
            row.set_deauth_enabled(enabled)

    def set_associated_ap(self, ap) -> None:
        """Show the live associated access point above client rows (Client Focus)."""
        self._associated_ap = ap
        if not self.is_mounted:
            return
        banner = self.query_one("#associated-ap-banner", Static)
        if ap is None:
            banner.display = False
            banner.update("")
            return
        ssid = ap.ssid or "‹hidden›"
        banner.update(
            Text("🛜 AP  ", style="bold")
            + Text(ssid, style="bold")
            + Text("  ·  ", style="dim")
            + mac_address_text(ap.bssid, style="dim"),
        )
        banner.display = True

    def set_open_network_metadata(
        self,
        metadata: NetworkMetadata | None,
        *,
        enabled: bool,
    ) -> None:
        self._open_network_mode = enabled
        self._network_metadata = metadata
        self.query_one("#client-web-search-box").display = enabled
        self.query_one("#website-pane").display = enabled
        self.query_one("#client-pane").styles.height = "1fr"
        if not enabled:
            self._website_facts = []
            self._search_text = ""
            search = self.query_one("#client-web-search", Input)
            if search.value:
                search.value = ""
        if metadata is not None and metadata.revision != self._network_revision:
            if enabled:
                with metadata.lock:
                    self._website_facts = sorted(
                        metadata.facts.get("websites", ()),
                        key=lambda fact: fact.last_seen,
                        reverse=True,
                    )
            self._network_revision = metadata.revision
            self._apply_client_ipv4_hints()
        elif metadata is None:
            self._network_revision = -1
            self._apply_client_ipv4_hints()
        self._apply_filter()
        self._update_title()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "client-web-search":
            return
        self._search_text = event.value
        self._apply_filter()
        self._update_title()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "clear-client-web-search":
            return
        event.stop()
        search = self.query_one("#client-web-search", Input)
        search.value = ""
        sync_search_input_has_text(search)
        search.focus()

    def _apply_filter(self) -> None:
        self._apply_client_filter()
        self._paint_websites()

    def _ipv4_hint_for_mac(self, mac: str) -> str:
        metadata = self._network_metadata
        if metadata is None:
            return ""
        with metadata.lock:
            client = metadata.clients.get(mac.casefold())
            if client is None:
                return ""
            addresses = client.facts.get("ipv4_addresses", ())
            if not addresses:
                return ""
            return addresses[-1].value

    def _apply_client_ipv4_hints(self) -> None:
        for mac, row in self._rows.items():
            row.set_ipv4_hint(self._ipv4_hint_for_mac(mac))

    def _apply_client_filter(self) -> None:
        tokens = self._search_tokens()
        for row in self._rows.values():
            ipv4 = self._ipv4_hint_for_mac(row._mac)
            searchable = f"{row._mac} {row._manufacturer} {ipv4}".casefold()
            row.display = all(token in searchable for token in tokens)
        self._update_history_separator()

    def _paint_websites(self) -> None:
        if not self.is_mounted:
            return
        tokens = self._search_tokens()
        visible = [
            fact for fact in self._website_facts
            if all(
                token in f"{fact.value} {fact.source} {fact.confidence}".casefold()
                for token in tokens
            )
        ]
        content = Text()
        for index, fact in enumerate(visible):
            if index:
                content.append("\n")
            content.append(fact.value, style="cyan")
            content.append(f"  ·  {fact.source}", style="dim")
        if not visible:
            content.append(
                "No matching websites" if tokens else "Waiting for website traffic…",
                style="dim italic",
            )
        self.query_one("#website-content", Static).update(content)
        self.query_one("#website-title", Label).update(
            f"WEBSITES ({len(visible)}/{len(self._website_facts)})"
            if tokens else f"WEBSITES ({len(visible)})"
        )

    def _search_tokens(self) -> tuple[str, ...]:
        return tuple(self._search_text.casefold().split())

    def _update_title(self) -> None:
        visible = [row for row in self._rows.values() if row.display]
        historical = sum(row._is_historical for row in visible)
        live = len(visible) - historical
        self.border_title = (
            f"CLIENTS ({live} live · {historical} history) + WEBSITES"
            if self._open_network_mode and historical
            else f"CLIENTS ({live}) + WEBSITES"
            if self._open_network_mode
            else f"CLIENTS ({live} live · {historical} history)"
            if historical
            else f"CLIENTS ({live})"
        )
