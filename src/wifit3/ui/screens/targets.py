from __future__ import annotations

import time

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label

from wifit3.persist.targets import TargetStoreError


class TargetsModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    TargetsModal { align: center middle; }
    TargetsModal #targets-dialog {
        width: 90%; height: 80%; border: thick $primary;
        background: $surface; padding: 1 2;
    }
    TargetsModal #targets-title { height: 1; text-align: center; text-style: bold; }
    TargetsModal #targets-table { height: 1fr; margin: 1 0; }
    TargetsModal #targets-alias-row { height: 3; }
    TargetsModal #targets-alias { width: 1fr; }
    TargetsModal #targets-actions { height: auto; align: right middle; }
    TargetsModal Button { width: auto; min-width: 10; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="targets-dialog"):
            yield Label("Saved Targets", id="targets-title")
            table = DataTable(cursor_type="row", id="targets-table")
            table.add_columns("ALIAS", "ACTIVE", "TYPE", "IDENTIFIER", "LAST LOCK")
            yield table
            with Horizontal(id="targets-alias-row"):
                yield Input(placeholder="Alias", id="targets-alias", max_length=64)
                yield Button("Save Alias", id="targets-save-alias")
            with Horizontal(id="targets-actions"):
                yield Button("Enable / Disable", id="targets-toggle")
                yield Button("Move Up", id="targets-up")
                yield Button("Move Down", id="targets-down")
                yield Button("Delete", id="targets-delete", variant="error")
                yield Button("Close", id="targets-close")

    def on_mount(self) -> None:
        self._reload()
        self.query_one("#targets-table", DataTable).focus()

    def _reload(self, selected_id: str | None = None) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        targets = self.app.target_store.ordered()
        for target in targets:
            last_lock = (
                time.strftime("%Y-%m-%d %H:%M", time.localtime(target.last_locked_at))
                if target.last_locked_at else "never"
            )
            table.add_row(
                target.alias,
                "yes" if target.enabled else "no",
                f"{target.medium}/{target.kind}",
                target.identifier,
                last_lock,
                key=target.id,
            )
        if table.row_count:
            if selected_id is not None:
                try:
                    table.move_cursor(row=table.get_row_index(selected_id))
                except Exception:
                    table.move_cursor(row=0)
            self._sync_alias()
        else:
            self.query_one("#targets-alias", Input).value = ""

    def _selected_id(self) -> str | None:
        table = self.query_one("#targets-table", DataTable)
        if not table.row_count:
            return None
        try:
            return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None

    def _sync_alias(self) -> None:
        target = self.app.target_store.get(self._selected_id())
        if target is not None:
            self.query_one("#targets-alias", Input).value = target.alias

    @on(DataTable.RowHighlighted, "#targets-table")
    def row_highlighted(self) -> None:
        self._sync_alias()

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "targets-close":
            self.dismiss()
            return
        target_id = self._selected_id()
        target = self.app.target_store.get(target_id)
        if target is None:
            return
        try:
            if event.button.id == "targets-save-alias":
                alias = self.query_one("#targets-alias", Input).value.strip()
                if not alias:
                    self.notify("Alias is required", severity="warning")
                    return
                target.alias = alias
                self.app.target_store.save()
            elif event.button.id == "targets-delete":
                self.app.target_store.delete(target.id)
                if self.app.locked_target_id == target.id:
                    self.app.locked_target_id = None
            elif event.button.id == "targets-toggle":
                target.enabled = not target.enabled
                self.app.target_store.save()
            elif event.button.id in {"targets-up", "targets-down"}:
                ordered = self.app.target_store.ordered()
                index = ordered.index(target)
                step = -1 if event.button.id == "targets-up" else 1
                destination = max(0, min(len(ordered) - 1, index + step))
                ordered[index], ordered[destination] = ordered[destination], ordered[index]
                for priority, item in enumerate(ordered):
                    item.priority = priority
                self.app.target_store.targets = ordered
                self.app.target_store.save()
        except TargetStoreError as exc:
            self.notify(str(exc), title="Targets", severity="error")
            return
        self._reload(target.id)
