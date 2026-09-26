from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class ConfirmActiveActionModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("n", "cancel", "Cancel"),
        Binding("y", "confirm", "Proceed"),
    ]

    DEFAULT_CSS = """
    ConfirmActiveActionModal { align: center middle; }
    ConfirmActiveActionModal #active-dialog {
        width: 64; max-width: 92%; height: auto;
        border: thick $warning; background: $surface; padding: 1 2;
    }
    ConfirmActiveActionModal #active-title {
        text-style: bold; color: $warning; text-align: center; margin-bottom: 1;
    }
    ConfirmActiveActionModal #active-body { margin-bottom: 1; }
    ConfirmActiveActionModal #active-buttons { height: auto; align: center middle; }
    """

    def __init__(self, action_name: str, target: str, impact: str) -> None:
        super().__init__()
        self._action_name = action_name
        self._target = target
        self._impact = impact

    def compose(self) -> ComposeResult:
        with Vertical(id="active-dialog"):
            yield Label("Active wireless action", id="active-title")
            yield Label(
                f"[bold]{self._action_name}[/bold]\n"
                f"Target: [cyan]{self._target}[/cyan]\n\n"
                f"{self._impact}\n\n"
                "[dim]Proceed only on networks you own or are authorized to test.[/dim]",
                id="active-body",
            )
            with Horizontal(id="active-buttons"):
                yield Button("Cancel", id="active-cancel")
                yield Button("Proceed", variant="warning", id="active-confirm")

    @on(Button.Pressed, "#active-confirm")
    def confirm_button(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#active-cancel")
    def cancel_button(self) -> None:
        self.dismiss(False)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
