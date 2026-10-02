from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.events import Click
from textual.reactive import Reactive, reactive
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Header, Label, Static
from textual.widgets._header import (
    HeaderClock,
    HeaderClockSpace,
    HeaderIcon,
    HeaderTitle,
)

if TYPE_CHECKING:
    from wifit3.persist.notifications import StoredNotification
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
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("c", "copy_notification", "Copy"),
        Binding("space", "toggle_detail", "Expand", show=False),
    ]

    DEFAULT_CSS = """
    NotificationHistoryModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.4);
    }
    NotificationHistoryModal #notify-dialog {
        width: 100;
        max-width: 96%;
        height: 34;
        max-height: 92%;
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
    NotificationHistoryModal #notify-detail {
        display: none;
        height: 10;
        min-height: 7;
        margin-bottom: 1;
        border: round $primary-darken-1;
        border-title-color: $accent;
        border-title-style: bold;
        padding: 0 1;
    }
    NotificationHistoryModal #notify-detail.expanded {
        display: block;
    }
    NotificationHistoryModal #notify-detail-title {
        height: 1;
        text-style: bold;
        margin-bottom: 1;
    }
    NotificationHistoryModal #notify-detail-meta {
        height: 1;
        color: $text-muted;
        margin-bottom: 1;
    }
    NotificationHistoryModal #notify-detail-message {
        height: auto;
        min-height: 1;
    }
    NotificationHistoryModal #notify-actions {
        height: 3;
        align: right middle;
    }
    NotificationHistoryModal #notify-actions Button {
        width: 14;
        min-width: 10;
        margin-left: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._items: dict[str, StoredNotification] = {}
        self._expanded_id: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="notify-dialog"):
            yield Static(
                "Notifications  [dim]Enter/click to expand · C to copy[/dim]",
                id="notify-title",
            )
            yield DataTable(id="notify-table", cursor_type="row", zebra_stripes=True)
            with VerticalScroll(id="notify-detail"):
                yield Label("", id="notify-detail-title")
                yield Label("", id="notify-detail-meta")
                yield Static("", id="notify-detail-message")
            with Horizontal(id="notify-actions"):
                yield Button(
                    "Copy",
                    id="notify-copy",
                    variant="primary",
                    disabled=True,
                )
                yield Button("Close", id="notify-close")

    def on_mount(self) -> None:
        app: WifiteApp = self.app  # type: ignore[assignment]
        store = app.notification_store
        store.mark_all_read()
        app.unread_notifications = 0
        table = self.query_one("#notify-table", DataTable)
        table.add_column("", key="marker", width=1)
        table.add_column("WHEN", key="when")
        table.add_column("TITLE", key="title")
        table.add_column("MESSAGE", key="message")
        items = store.recent()
        if not items:
            table.add_row(
                " ",
                "—",
                "No notifications yet",
                "Important warnings, errors, and flagged events appear here.",
                key="__empty__",
            )
        for item in items:
            self._items[item.id] = item
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item.created_at))
            title = item.title or "—"
            severity = (item.severity or "information").casefold()
            severity_style = {
                "error": "bold red",
                "warning": "bold yellow",
                "information": "cyan",
                "info": "cyan",
            }.get(severity, "")
            table.add_row(
                Text("▸", style="bold cyan"),
                when,
                Text(title, style=severity_style) if severity_style else title,
                item.message,
                key=item.id,
            )
        if table.row_count:
            table.move_cursor(row=0)

    def _selected_id(self) -> str | None:
        table = self.query_one("#notify-table", DataTable)
        if not table.row_count:
            return None
        try:
            return str(
                table.coordinate_to_cell_key(
                    table.cursor_coordinate,
                ).row_key.value
            )
        except Exception:
            return None

    def _show_detail(self, notification_id: str) -> None:
        item = self._items.get(notification_id)
        if item is None:
            return
        severity = (item.severity or "information").upper()
        when = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(item.created_at),
        )
        title = item.title or "Notification"
        style = {
            "ERROR": "bold red",
            "WARNING": "bold yellow",
            "INFORMATION": "bold cyan",
            "INFO": "bold cyan",
        }.get(severity, "bold")
        self.query_one("#notify-detail-title", Label).update(
            Text(title, style=style),
        )
        self.query_one("#notify-detail-meta", Label).update(
            f"{when} · {severity}",
        )
        self.query_one("#notify-detail-message", Static).update(
            Text(item.message),
        )
        detail = self.query_one("#notify-detail", VerticalScroll)
        detail.set_class(True, "expanded")
        detail.border_title = "FULL NOTIFICATION"
        detail.scroll_home(animate=False)
        self.query_one("#notify-copy", Button).disabled = False
        self._expanded_id = notification_id
        self._refresh_markers()

    def _hide_detail(self) -> None:
        self.query_one("#notify-detail", VerticalScroll).set_class(
            False,
            "expanded",
        )
        self.query_one("#notify-copy", Button).disabled = True
        self._expanded_id = None
        self._refresh_markers()

    def _refresh_markers(self) -> None:
        table = self.query_one("#notify-table", DataTable)
        for notification_id in self._items:
            marker = "▾" if notification_id == self._expanded_id else "▸"
            table.update_cell(
                notification_id,
                "marker",
                Text(marker, style="bold cyan"),
            )

    def action_toggle_detail(self) -> None:
        notification_id = self._selected_id()
        if notification_id is None or notification_id not in self._items:
            return
        if self._expanded_id == notification_id:
            self._hide_detail()
        else:
            self._show_detail(notification_id)

    def action_copy_notification(self) -> None:
        item = self._items.get(self._expanded_id or "")
        if item is None:
            notification_id = self._selected_id()
            item = self._items.get(notification_id or "")
        if item is None:
            self.notify("Select a notification first.", severity="warning")
            return
        when = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(item.created_at),
        )
        title = item.title or "Notification"
        text = (
            f"{when} [{item.severity.upper()}] {title}\n"
            f"{item.message}"
        )
        self.app.copy_to_clipboard(text)
        self.notify("Full notification copied to clipboard")

    def action_close(self) -> None:
        self.dismiss()

    @on(DataTable.RowSelected, "#notify-table")
    def notification_selected(self, event: DataTable.RowSelected) -> None:
        notification_id = str(event.row_key.value)
        if self._expanded_id == notification_id:
            self._hide_detail()
        else:
            self._show_detail(notification_id)

    @on(DataTable.RowHighlighted, "#notify-table")
    def notification_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._expanded_id is not None:
            self._show_detail(str(event.row_key.value))

    @on(Button.Pressed, "#notify-copy")
    def copy_pressed(self) -> None:
        self.action_copy_notification()

    @on(Button.Pressed, "#notify-close")
    def close_pressed(self) -> None:
        self.action_close()
