from __future__ import annotations

from dataclasses import dataclass

from rich.markup import escape
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from wifit3.targeting import TargetCandidate


@dataclass(frozen=True)
class NewTargetResult:
    alias: str
    lock: bool


class NewTargetModal(ModalScreen[NewTargetResult | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    NewTargetModal { align: center middle; }
    NewTargetModal #target-dialog {
        width: 68; max-height: 90%; border: thick $primary;
        background: $surface; padding: 1 2;
    }
    NewTargetModal #target-title { text-style: bold; text-align: center; }
    NewTargetModal #target-details {
        height: auto; max-height: 16; margin: 1 0; padding: 1;
        border: round $primary; overflow-y: auto;
    }
    NewTargetModal #target-error { height: 1; color: $error; }
    NewTargetModal #target-actions { height: auto; align: right middle; }
    NewTargetModal Button { width: auto; min-width: 13; }
    """

    def __init__(self, candidate: TargetCandidate) -> None:
        super().__init__()
        self.candidate = candidate

    def compose(self) -> ComposeResult:
        candidate = self.candidate
        with Vertical(id="target-dialog"):
            yield Label("New Target", id="target-title")
            yield Label(
                f"[bold]{escape(candidate.title)}[/bold]  "
                f"[dim]{escape(candidate.medium)} / {escape(candidate.kind)}[/dim]"
            )
            lines = [
                f"[dim]{escape(str(key).replace('_', ' ').title())}[/dim]  "
                f"{escape(self._display_value(value))}"
                for key, value in candidate.details.items()
                if value not in (None, "", [], {})
            ]
            yield Static("\n".join(lines), id="target-details")
            yield Input(
                placeholder="Required alias",
                id="target-alias",
                max_length=64,
            )
            yield Label("", id="target-error")
            with Horizontal(id="target-actions"):
                yield Button("Save & Continue", id="target-save")
                yield Button("Save & Lock", id="target-lock", variant="primary")
                yield Button("Cancel", id="target-cancel")

    @staticmethod
    def _display_value(value) -> str:
        if isinstance(value, list):
            return ", ".join(str(item) for item in value) or "-"
        if isinstance(value, dict):
            populated = [
                f"{key}={item}" for key, item in value.items()
                if item not in (None, "", [], {}, False)
            ]
            return ", ".join(populated) or "-"
        return str(value)

    def on_mount(self) -> None:
        self.query_one("#target-alias", Input).focus()

    @on(Input.Submitted, "#target-alias")
    def alias_submitted(self) -> None:
        self._finish(lock=True)

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "target-cancel":
            self.action_cancel()
        elif event.button.id == "target-save":
            self._finish(lock=False)
        elif event.button.id == "target-lock":
            self._finish(lock=True)

    def _finish(self, *, lock: bool) -> None:
        alias = self.query_one("#target-alias", Input).value.strip()
        if not alias:
            self.query_one("#target-error", Label).update("Alias is required")
            return
        self.dismiss(NewTargetResult(alias=alias, lock=lock))

    def action_cancel(self) -> None:
        self.dismiss(None)
