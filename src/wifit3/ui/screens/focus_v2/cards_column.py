"""Left column of AP Focus: one or two card slots with live channel readouts."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Label

from . import art
from .card_endpoint import CardEndpoint, campaign_expected_channel, format_iface_channel


def _iface_role(iface, active) -> str:
    if active is None or iface is None:
        return ""
    twin = getattr(active, "twin_iface", None)
    punt = getattr(active, "punt_iface", None)
    if iface is twin:
        return " · AP"
    if punt is not None and iface is punt and punt is not twin:
        return " · deauth"
    return ""


def _ordered_members(members, primary):
    if not members:
        return []
    if primary is not None and primary in members:
        rest = [m for m in members if m is not primary]
        rest.sort(key=lambda m: m.name)
        return [primary] + rest
    return sorted(members, key=lambda m: m.name)


class CardsColumn(Vertical):
    """Shows every pool card side-by-side when two or more are attached."""

    DEFAULT_CSS = """
    CardsColumn { width: auto; height: auto; align: center middle; }
    CardsColumn #cards-inner { width: auto; height: auto; }
    CardsColumn .card-slot { width: 20; align: center middle; }
    CardsColumn .card-channel { text-style: bold; color: $accent; }
    CardsColumn .card-slot-name { height: 1; }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="cards-inner"):
            yield CardEndpoint(id="card-slot-0", classes="card-slot")
            second = CardEndpoint(
                id="card-slot-1", classes="card-slot",
                enable_picker=False, chipset="",
            )
            second.display = False
            yield second

    def on_mount(self) -> None:
        self._slot(1).display = False
        self.styles.width = 20

    def _slot(self, index: int) -> CardEndpoint:
        return self.query_one(f"#card-slot-{index}", CardEndpoint)

    def update(self, *, dynamic: str) -> None:
        self._slot(0).update(dynamic=dynamic)

    def flicker(self) -> None:
        self._slot(0).flicker()

    def update_bssid(self, bssid: str | None) -> None:
        self._slot(0).update_bssid(bssid)

    def sync(
        self,
        members,
        channel,
        primary,
        locked: bool,
        array,
        active,
    ) -> None:
        dual = len(members) >= 2
        slot1 = self._slot(1)
        slot1.display = dual
        self.styles.width = 40 if dual else 20

        ordered = _ordered_members(members, primary)
        if not dual:
            iface = primary or art.pick_primary(members)
            slot0 = self._slot(0)
            slot0.set_art(art.art_path_for(iface) if iface else art.pool_art(members))
            slot0.sync_picker(members, channel, primary, locked)
            slot0.update_bssid(members[0].mac_address if len(members) == 1 else None)
            claimed = array.is_claimed(iface) if array is not None and iface else False
            slot0.update_channel(
                format_iface_channel(
                    iface,
                    claimed=claimed,
                    role=_iface_role(iface, active),
                    expected=campaign_expected_channel(iface, active),
                ),
            )
            return

        for index in range(2):
            iface = ordered[index] if index < len(ordered) else None
            slot = self._slot(index)
            if iface is None:
                slot.display = False
                continue
            claimed = array.is_claimed(iface) if array is not None else False
            slot.sync_iface(
                iface,
                claimed=claimed,
                role=_iface_role(iface, active),
                expected=campaign_expected_channel(iface, active),
            )
            slot.query_one("#card-dynamic", Label).display = False
            slot.query_one("#card-bssid", Label).display = False
