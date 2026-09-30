from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.events import Click
from textual.reactive import Reactive, reactive
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Header, Static
from textual.widgets._header import (
    HeaderClock,
    HeaderClockSpace,
    HeaderIcon,
    HeaderTitle,
)

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


# Envelope (U+2709): compact in most terminals; tooltip carries the full label.
_NOTIFY_ICON = "✉"


class NotificationBell(Static):
    """Header message indicator with unread badge; click opens history."""

    can_focus = True

    DEFAULT_CSS = """
    NotificationBell {
        dock: right;
        width: auto;
        min-width: 7;
        padding: 0 1;
        content-align: center middle;
    }
    NotificationBell:hover {
        background: $primary 20%;
    }
    NotificationBell:focus {
        background: $primary 30%;
    }
    """

    unread_count: Reactive[int] = Reactive(0)

    def _trailing_readout_has_content(self) -> bool:
        parent = self.parent
        if parent is None:
            return False
        for node in parent.query("_ChannelReadout"):
            if (getattr(node, "channels", "") or "").strip():
                return True
        for node in parent.query("_BluetoothSortReadout"):
            if (getattr(node, "summary", "") or "").strip():
                return True
        return False

    def _needs_leading_separator(self) -> bool:
        """Separator before the icon when a clock (not readout) sits to the left."""
        if self._trailing_readout_has_content():
            return False
        parent = self.parent
        if parent is None:
            return False
        return bool(parent.query("HeaderClock"))

    def render(self) -> Text:
        count = self.unread_count
        if count > 99:
            badge = "99+"
        elif count > 0:
            badge = str(count)
        else:
            badge = ""
        text = Text()
        if self._needs_leading_separator():
            text.append("  |  ", style="dim")
        icon_style = "bold cyan" if badge else "bold"
        text.append(_NOTIFY_ICON, style=icon_style)
        if badge:
            text.append(f" {badge}", style="bold cyan")
        return text

    def on_mount(self) -> None:
        self.tooltip = "Notification history"
        app = self.app
        if hasattr(app, "unread_notifications"):
            self.unread_count = app.unread_notifications
            self.watch(app, "unread_notifications", self._sync_count)

    def _sync_count(self, count: int) -> None:
        self.unread_count = count

    async def on_click(self, event: Click) -> None:
        event.stop()
        if getattr(self.app, "action_notification_history", None):
            self.app.action_notification_history()


class WifiteHeader(Header):
    """App header with notification bell docked on the right (like the stock clock)."""

    def __init__(
        self,
        *,
        show_clock: bool = True,
        trailing: type | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(id=id, show_clock=False)
        self._show_clock = show_clock
        self._trailing = trailing

    def compose(self) -> ComposeResult:
        if getattr(self.app, "ENABLE_COMMAND_PALETTE", False):
            yield HeaderIcon().data_bind(Header.icon)
        yield HeaderTitle()
        if self._trailing is not None:
            yield self._trailing()
        elif self._show_clock:
            yield HeaderClock().data_bind(Header.time_format)
        else:
            yield HeaderClockSpace()
        yield NotificationBell(id="notification-bell")

    def _on_click(self) -> None:
        # Keep a single-line header; stock Header toggles tall mode on click.
        return


class NotificationHistoryModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close")]

    DEFAULT_CSS = """
    NotificationHistoryModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.4);
    }
    NotificationHistoryModal #notify-dialog {
        width: 78;
        max-width: 94%;
        height: 28;
        max-height: 85%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    NotificationHistoryModal #notify-title {
        text-style: bold;
        text-align: center;
        height: 1;
        margin-bottom: 1;
    }
    NotificationHistoryModal #notify-table {
        height: 1fr;
        margin-bottom: 1;
    }
    NotificationHistoryModal #notify-actions {
        height: auto;
        align: right middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="notify-dialog"):
            yield Static("Notifications", id="notify-title")
            yield DataTable(id="notify-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="notify-actions"):
                yield Button("Close", id="notify-close")

    def on_mount(self) -> None:
        app: WifiteApp = self.app  # type: ignore[assignment]
        store = app.notification_store
        store.mark_all_read()
        app.unread_notifications = 0
        table = self.query_one("#notify-table", DataTable)
        table.add_columns("WHEN", "TITLE", "MESSAGE")
        items = store.recent()
        if not items:
            table.add_row("-", "No notifications yet", "Toasts are saved here after they appear.")
        for item in items:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item.created_at))
            title = item.title or "-"
            severity = (item.severity or "information").casefold()
            severity_style = {
                "error": "bold red",
                "warning": "bold yellow",
                "information": "cyan",
                "info": "cyan",
            }.get(severity, "")
            table.add_row(
                when,
                Text(title, style=severity_style) if severity_style else title,
                item.message,
                key=item.id,
            )
        if table.row_count:
            table.move_cursor(row=0)

    def action_close(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#notify-close")
    def close_pressed(self) -> None:
        self.action_close()
