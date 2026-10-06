"""Router endpoint: the right column. Power + signal sit *directly above* the
router art; the ESSID sits *directly below* it (the name labels the router),
then BSSID and the channel. Encryption is NOT shown here. It lives in the log
('Target acquired … WPA2'), the under-sparkline footer, and is implied by the
attack buttons; the channel alone keeps this column uncluttered.

The power line is the live reception-quality meter: the rainbow
``render_signal_bar`` (beacons/s out of ~9.8), widened to fill the column's
negative space, with the dBm flush right. No "Beacons:" prefix: the
bar *is* the readout."""
from __future__ import annotations

import math
import time

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Label

from wifit3.ui.mac_format import mac_address_text

from ...signal_bar import dbm_style, render_signal_bar
from .art import BreathingArt, art_size


class RouterEndpoint(Vertical):
    class IdentityRequested(Message):
        """User activated the identity details button."""
        def __init__(self, details: str) -> None:
            super().__init__()
            self.details = details

    def __init__(self, *, essid: str = "", bssid: str = "", channel: int = 0,
                 channel_label: str = "",
                 power_dbm: int = -100, signal: float | None = None,
                 uptime_us: int | None = None,
                 country_code: str | None = None,
                 ssid_note: str = "",
                 catalog: str = "",
                 fingerprint: str = "",
                 identity: str = "", identity_details: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._essid = essid
        self._bssid = bssid
        self._channel = channel
        self._channel_label = channel_label
        self._power_dbm = power_dbm
        self._signal = signal
        self._uptime_us = uptime_us
        self._country_code = country_code
        self._ssid_note = ssid_note
        self._catalog = catalog
        self._fingerprint = fingerprint
        self._identity = identity
        self._identity_details = identity_details
        self._width = art_size("focus-ap.ans")[0]      # endpoint column width
        self._last: dict[str, str] = {}                # last-pushed label value; skip no-op repaints

    def compose(self) -> ComposeResult:
        yield Label(self._power_line(), classes="ap-power", id="ap-power")
        art = BreathingArt("focus-ap.ans", classes="endpoint-art", id="router-art")
        art.tooltip = self._identity_details
        yield art
        yield Label(
            self._essid_markup(self._essid, self._ssid_note),
            classes="ap-essid", id="ap-essid",
        )
        catalog = Label(self._catalog, classes="ap-static", id="ap-catalog")
        catalog.display = bool(self._catalog)
        yield catalog
        yield Label(mac_address_text(self._bssid), classes="ap-static", id="ap-bssid")
        yield Label(
            self._fingerprint,
            classes="ap-static",
            id="ap-fingerprint",
        )
        yield Label(self._uptime_label(), classes="ap-static", id="ap-uptime")
        with Horizontal(classes="ap-static", id="ap-identity-row"):
            identity = Button(self._identity_label(), id="ap-identity")
            identity.styles.line_pad = 0
            identity.disabled = self._identity_details is None
            if self._identity_details:
                identity.add_class("identity-known")
            yield identity

    def update(self, *, essid: str, bssid: str, channel: int, channel_label: str,
               power_dbm: int, signal: float | None,
               uptime_us: int | None = None,
               country_code: str | None = None,
               ssid_note: str = "",
               catalog: str = "",
               fingerprint: str = "",
               identity: str = "", identity_details: str | None = None) -> None:
        """Update live power meter and target endpoint identity state."""
        self._essid, self._bssid, self._channel = essid, bssid, channel
        self._channel_label = channel_label
        self._power_dbm, self._signal = power_dbm, signal
        self._uptime_us = uptime_us
        self._country_code = country_code
        self._ssid_note = ssid_note
        self._catalog = catalog
        self._fingerprint = fingerprint
        self._identity, self._identity_details = identity, identity_details
        self.query_one("#ap-power", Label).update(self._power_line())
        self.query_one("#router-art", BreathingArt).tooltip = identity_details
        self._push("#ap-essid", self._essid_markup(essid, ssid_note))
        catalog_label = self.query_one("#ap-catalog", Label)
        catalog_label.display = bool(catalog)
        if catalog:
            self._push("#ap-catalog", catalog)
        self._push_mac("#ap-bssid", bssid)
        self._push("#ap-fingerprint", fingerprint)
        self._push("#ap-uptime", self._uptime_label())

        self._push("#ap-identity", self._identity_label())
        ident_btn = self.query_one("#ap-identity", Button)
        ident_btn.styles.line_pad = 0
        ident_btn.disabled = identity_details is None
        ident_btn.set_class(bool(identity_details), "identity-known")

    def _push(self, sel: str, value: str) -> None:
        """Update the label only when its value changed: skip the no-op repaint."""
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

    def flicker(self) -> None:
        """Pulse the router LED. The screen calls this on RX from the target."""
        self.query_one(BreathingArt).pulse()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ap-identity" and self._identity_details:
            event.stop()
            self.post_message(self.IdentityRequested(self._identity_details))

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len - 1] + "…"

    def _identity_label(self) -> str:
        return self._truncate(self._channel_label or f"channel {self._channel}", 20)

    def _uptime_label(self) -> str:
        if self._uptime_us is None:
            uptime = "uptime unknown"
        else:
            seconds = self._uptime_us // 1_000_000
            days, remainder = divmod(seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes, seconds = divmod(remainder, 60)
            if days:
                uptime = f"uptime {days}d {hours:02}h"
            elif hours:
                uptime = f"uptime {hours}h {minutes:02}m"
            elif minutes:
                uptime = f"uptime {minutes}m {seconds:02}s"
            else:
                uptime = f"uptime {seconds}s"
        if self._country_code:
            return f"{uptime} · {self._country_code}"
        return uptime

    @staticmethod
    def _essid_markup(essid: str, note: str = "") -> str:
        """The ESSID as a black-on-cyan chip so it pops as the AP's identity (it
        kept blending in as plain bold white). A cloaked AP stays a dim italic
        marker: no chip on a name we don't have."""
        if essid == "‹hidden›":
            return "[dim italic]‹hidden›[/dim italic]"
        if note:
            label = escape(f"{essid} [{note}]")
            return f"[black bold on yellow] {label} [/black bold on yellow]"
        return f"[black bold on cyan] {escape(essid)} [/black bold on cyan]"

    def _power_line(self) -> Text:
        """Rainbow signal bar (left, filling the negative space) + dBm (right).
        ``self._signal`` is the windowed beacons/s: None=warming, ~0=dead (a
        heartbeat-pulsing ╳)."""
        dbm = f"{self._power_dbm} dBm"
        bar_w = max(4, self._width - len(dbm) - 1)
        pulse = 0.5 + 0.5 * math.sin(time.time() * math.tau)   # dead-AP heartbeat
        line = Text(no_wrap=True)
        line.append_text(render_signal_bar(self._signal, width=bar_w, pulse=pulse))
        line.append(" ")
        line.append(dbm, style=dbm_style(self._power_dbm))
        return line
