"""Client endpoint: the right column of Client Focus (station art + identity)."""
from __future__ import annotations

import math
import time

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Button, Label

from wifit3.id import fingerprint, vendor_for_mac
from wifit3.ui.mac_format import mac_address_text
from ...signal_bar import FULL_SCALE_RATE, dbm_style, render_signal_bar
from .art import BreathingArt, art_size, client_art_name


class ClientEndpoint(Vertical):
    class IdentityRequested(Message):
        def __init__(self, details: str) -> None:
            super().__init__()
            self.details = details

    def __init__(
        self,
        *,
        mac: str = "",
        label: str = "",
        power_dbm: int = -100,
        signal: float | None = None,
        fingerprint_summary: str = "",
        identity_details: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._mac = mac
        self._label = label
        self._power_dbm = power_dbm
        self._signal = signal
        self._fingerprint_summary = fingerprint_summary
        self._identity_details = identity_details
        self._art_name = client_art_name(mac)
        self._width = art_size(self._art_name)[0]
        self._last: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Label(self._power_line(), classes="ap-power", id="client-power")
        art = BreathingArt(self._art_name, classes="endpoint-art", id="client-art")
        art.tooltip = self._identity_details
        yield art
        yield Label(self._label_markup(), classes="ap-essid", id="client-label")
        yield Label(mac_address_text(self._mac), classes="ap-static", id="client-mac")
        yield Label(
            self._fingerprint_summary,
            classes="ap-static",
            id="client-fingerprint",
        )
        identity = Button(self._identity_button(), id="client-identity")
        identity.styles.line_pad = 0
        identity.disabled = self._identity_details is None
        if self._identity_details:
            identity.add_class("identity-known")
        yield identity

    def set_art(self, mac: str) -> None:
        name = client_art_name(mac)
        if name == self._art_name:
            return
        self._art_name = name
        self.query_one("#client-art", BreathingArt).set_art(name)

    def update(
        self,
        *,
        mac: str,
        label: str,
        power_dbm: int,
        signal: float | None,
        fingerprint_summary: str,
        identity_details: str | None,
    ) -> None:
        self.set_art(mac)
        self._mac, self._label = mac, label
        self._power_dbm, self._signal = power_dbm, signal
        self._fingerprint_summary = fingerprint_summary
        self._identity_details = identity_details
        self.query_one("#client-art", BreathingArt).tooltip = identity_details
        self._push("#client-power", self._power_line())
        self._push("#client-label", self._label_markup())
        self._push_mac("#client-mac", mac)
        self._push("#client-fingerprint", fingerprint_summary)
        self._push("#client-identity", self._identity_button())
        ident_btn = self.query_one("#client-identity", Button)
        ident_btn.disabled = identity_details is None
        ident_btn.set_class(bool(identity_details), "identity-known")

    def flicker(self) -> None:
        self.query_one("#client-art", BreathingArt).pulse()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "client-identity" and self._identity_details:
            event.stop()
            self.post_message(self.IdentityRequested(self._identity_details))

    def _push(self, sel: str, value: str) -> None:
        if self._last.get(sel) == value:
            return
        self._last[sel] = value
        widget = self.query_one(sel)
        if isinstance(widget, Button):
            widget.label = value
        else:
            widget.update(value)

    def _push_mac(self, sel: str, mac: str) -> None:
        if self._last.get(sel) == mac:
            return
        self._last[sel] = mac
        self.query_one(sel, Label).update(mac_address_text(mac))

    def _power_line(self) -> Text:
        """Rainbow meter from RSSI (packet rate is too sparse and triggered the dead ╳)."""
        dbm_label = f"{self._power_dbm} dBm"
        bar_w = max(4, self._width - len(dbm_label) - 1)
        rate = self._meter_rate()
        pulse = 0.5 + 0.5 * math.sin(time.time() * math.tau)
        line = Text(no_wrap=True)
        if rate is None:
            line.append_text(render_signal_bar(None, width=bar_w))
        elif rate <= 0.05:
            line.append_text(render_signal_bar(rate, width=bar_w, pulse=pulse))
        else:
            line.append_text(render_signal_bar(rate, width=bar_w))
        line.append(" ")
        line.append(dbm_label, style=dbm_style(self._power_dbm))
        return line

    def _meter_rate(self) -> float | None:
        """Map client RSSI to the same 0..FULL_SCALE meter the AP view uses."""
        dbm = self._power_dbm
        if dbm <= -99:
            return None
        clamped = max(-95, min(-30, dbm))
        return FULL_SCALE_RATE * (clamped + 95) / 65

    def _label_markup(self) -> str:
        fp = fingerprint(self._mac) if self._mac else None
        emoji = fp.emoji if fp else "💻"
        name = self._label or (fp.label if fp else vendor_for_mac(self._mac) or "Client")
        return f"{emoji} {escape(name)}"

    def _identity_button(self) -> str:
        vendor = vendor_for_mac(self._mac) or "Client details"
        return vendor[: self._width]
