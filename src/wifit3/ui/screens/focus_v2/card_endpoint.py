"""Card endpoint: the left column. The card art, then its static facts
(chipset/driver + the card's own BSSID when the driver exposes it) and the
dynamic line (what the card is doing right now). Just identity + live state (the
attack buttons live in the top "action area"), vertically centered against the
packet dashboard."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Label

from wifit3.ui.mac_format import mac_address_text

from .art import BreathingArt, display_name
from .tx_picker import TxDevicePicker


def campaign_expected_channel(iface, active) -> int | None:
    """Configured campaign channel for this iface (twin vs deauth leg), if any."""
    if active is None or iface is None:
        return None
    twin = getattr(active, "twin_iface", None)
    punt = getattr(active, "punt_iface", None)
    if iface is twin:
        return getattr(active, "twin_channel", None)
    if punt is not None and iface is punt and punt is not twin:
        return getattr(active, "target_channel", None)
    return None


def format_iface_channel(
    iface,
    *,
    claimed: bool = False,
    role: str = "",
    expected: int | None = None,
) -> str:
    """Live channel readout for the card column (locked lease / hop / width)."""
    if iface is None:
        return ""
    if getattr(iface, "_is_hopping", False):
        base = f"CH {getattr(iface, 'current_channel', '?')} · hop"
    else:
        live = getattr(iface, "current_channel", "?")
        if expected is not None and live != expected:
            base = f"CH {live} ≠ {expected}"
        else:
            base = f"CH {live}"
        spec = getattr(iface, "current_channel_spec", None)
        width = getattr(spec, "width_mhz", None) if spec is not None else None
        if width is not None and width != 20:
            base += f" · {width} MHz"
        if claimed:
            base += " · lock"
    if role:
        base += role
    return base


class CardEndpoint(Vertical):
    def __init__(self, *, chipset: str = "no card", bssid: str | None = None,
                 dynamic: str = "", enable_picker: bool = True, **kwargs) -> None:
        super().__init__(**kwargs)
        self._chipset = chipset
        self._bssid = bssid
        self._dynamic = dynamic
        self._enable_picker = enable_picker
        self._last_dynamic: str | None = None      # last-pushed dynamic line; skip no-op repaints
        self._last: dict[str, str] = {}            # last-pushed identity label values; skip no-op repaints

    def compose(self) -> ComposeResult:
        yield BreathingArt("focus-card.ans", classes="endpoint-art")
        yield Label("", classes="card-channel", id="card-channel")
        # The product-name slot is the TX-device picker: a plain label with one card, a dropdown
        # to pin the injection card with two or more. Driven by sync_picker from the screen tick.
        if self._enable_picker:
            yield TxDevicePicker(self._chipset, id="tx-picker")
            name = Label("", classes="card-slot-name", id="card-slot-name")
            name.display = False
            yield name
        else:
            yield Label(self._chipset, classes="card-slot-name", id="card-slot-name")
        # Always present (the card MAC is static per card) so a later tick can
        # show/hide it; hidden when the driver doesn't expose its own BSSID.
        bssid = Label(
            mac_address_text(self._bssid) if self._bssid else "",
            classes="card-static",
            id="card-bssid",
        )
        bssid.display = bool(self._bssid)
        yield bssid
        # The dynamic line ("● replaying" etc) is always composed so update()
        # can toggle it; hidden while the card is idle (passive capture).
        dyn = Label(self._dynamic, classes="card-dynamic", id="card-dynamic")
        dyn.display = bool(self._dynamic)
        yield dyn

    def update(self, *, dynamic: str) -> None:
        """Refresh the live 'what the card is doing' line, only when it changed
        (chipset / BSSID update on their own via ``sync_picker`` / ``update_bssid``).
        Textual's ``Label.update`` refreshes unconditionally, so the change check
        skips the no-op repaint that otherwise fires every tick."""
        if dynamic == self._last_dynamic:
            return
        self._last_dynamic = dynamic
        dyn = self.query_one("#card-dynamic", Label)
        dyn.update(dynamic)
        dyn.display = bool(dynamic)

    def sync_picker(self, members, channel, current, locked: bool) -> None:
        """Refresh the TX-device picker (trigger name + dropdown state) from the live pool."""
        if not self._enable_picker:
            return
        self.query_one("#tx-picker", TxDevicePicker).display = True
        self.query_one("#card-slot-name", Label).display = False
        self.query_one(TxDevicePicker).sync(members, channel, current, locked)

    def sync_iface(
        self, iface, *, claimed: bool = False, role: str = "", expected: int | None = None,
    ) -> None:
        """Dual-card mode: art + name + live channel for one pool member."""
        from . import art as artmod

        if iface is None:
            self.display = False
            return
        self.display = True
        self.set_art(artmod.art_path_for(iface))
        if self._enable_picker:
            self.query_one("#tx-picker", TxDevicePicker).display = False
            self._push("#card-slot-name", display_name(iface))
            self.query_one("#card-slot-name", Label).display = True
        else:
            self._push("#card-slot-name", display_name(iface))
        self.update_channel(
            format_iface_channel(iface, claimed=claimed, role=role, expected=expected),
        )

    def update_channel(self, line: str) -> None:
        self._push("#card-channel", line)

    def update_bssid(self, bssid: str | None) -> None:
        """Re-apply the card's own BSSID line. Shows only for a single card (a multi-card pool has
        no single MAC). The pool can change under us (plug/unplug) while Focus is open."""
        if self._push_mac("#card-bssid", bssid or ""):
            self.query_one("#card-bssid", Label).display = bool(bssid)

    def set_art(self, name: str) -> None:
        """Point the card art at ``name`` (BreathingArt.set_art no-ops when unchanged)."""
        self.query_one(BreathingArt).set_art(name)

    def _push(self, sel: str, value: str) -> bool:
        """Update a label only when its value changed; return whether it changed."""
        if self._last.get(sel) == value:
            return False
        self._last[sel] = value
        self.query_one(sel, Label).update(value)
        return True

    def _push_mac(self, sel: str, mac: str) -> bool:
        if self._last.get(sel) == mac:
            return False
        self._last[sel] = mac
        self.query_one(sel, Label).update(mac_address_text(mac) if mac else "")
        return True

    def flicker(self) -> None:
        """Pulse the card LED. The screen calls this when we TX a frame."""
        self.query_one(BreathingArt).pulse()
