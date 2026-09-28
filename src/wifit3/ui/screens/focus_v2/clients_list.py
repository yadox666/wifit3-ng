"""Clients list: List of related client MAC addresses underneath the AP."""
from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Tooltip
from rich.text import Text

from wifit3.id import Fingerprint, vendor_for_mac
from ...signal_bar import dbm_style
from ... import focus_model as fm


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

    def compose(self) -> ComposeResult:
        badge = (
            "[yellow]◈[/yellow]"
            if self._is_fake
            else "[dim]◌[/dim]"
            if self._is_historical
            else self._fp.emoji if self._fp else ""
        )
        self._fp_label = Label(badge, classes="cl-fp")
        self._mac_label = Label(self._mac, classes="cl-bssid")
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
            self._mfr_label.update(manufacturer)

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
        box = Vertical(
            *rows,
            Label(f"[dim]OUI: {self._mac[:8]}[/dim]"),
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
    def __init__(self, clients, **kwargs) -> None:
        super().__init__(**kwargs)
        self._clients = clients
        self._rows: dict[str, ClientWidget] = {}

    def compose(self) -> ComposeResult:
        # Broadcast button pinned at the top; only the row list scrolls below it.
        yield Button("Deauth all", id="deauth-all", classes="bcast-btn",
                     tooltip="Deauthenticate all clients (Broadcast)")
        with Horizontal(classes="client-columns"):
            yield Label("", classes="cl-fp")
            yield Label("CLIENT", classes="cl-bssid")
            yield Label("VENDOR", classes="cl-mfr")
            yield Label("PWR", classes="cl-pwr")
            yield Label("PKT", classes="cl-pkts")
            yield Label("", classes="cl-action")
        rows = []
        for c in self._clients:
            widget = ClientWidget(c)
            self._rows[c.mac] = widget
            rows.append(widget)
        yield VerticalScroll(*rows, id="client-rows")

    def on_mount(self) -> None:
        self._update_title()

    def _rows_host(self) -> VerticalScroll:
        """The scroll container the client rows live in (new rows mount here)."""
        return self.query_one("#client-rows", VerticalScroll)

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
                self._rows_host().mount(widget)
            else:
                row.update_stats(c.signal, c.packets)
        self._update_title()

    def _remove_row(self, mac: str) -> None:
        row = self._rows.pop(mac, None)
        if row is not None:
            row.remove()

    def set_deauth_enabled(self, enabled: bool) -> None:
        """Enable/disable every deauth control (✕)."""
        for row in self._rows.values():
            row.set_deauth_enabled(enabled)

    def _update_title(self) -> None:
        historical = sum(row._is_historical for row in self._rows.values())
        live = len(self._rows) - historical
        self.border_title = (
            f"CLIENTS ({live} live · {historical} history)"
            if historical
            else f"CLIENTS ({live})"
        )
