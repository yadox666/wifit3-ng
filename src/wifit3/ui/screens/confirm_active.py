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


class ConfirmLeaveFocusModal(ModalScreen[bool]):
    """Warn before leaving Focus while wireless actions are still running."""

    BINDINGS = [
        Binding("escape", "cancel", "Stay"),
        Binding("n", "cancel", "Stay"),
        Binding("y", "confirm", "Leave"),
    ]

    DEFAULT_CSS = """
    ConfirmLeaveFocusModal { align: center middle; }
    ConfirmLeaveFocusModal #leave-dialog {
        width: 64; max-width: 92%; height: auto;
        border: thick $warning; background: $surface; padding: 1 2;
    }
    ConfirmLeaveFocusModal #leave-title {
        text-style: bold; color: $warning; text-align: center; margin-bottom: 1;
    }
    ConfirmLeaveFocusModal #leave-body { margin-bottom: 1; }
    ConfirmLeaveFocusModal #leave-buttons { height: auto; align: center middle; }
    """

    def __init__(self, running_actions: list[str], *, destination: str) -> None:
        super().__init__()
        self._running_actions = running_actions
        self._destination = destination

    def compose(self) -> ComposeResult:
        bullets = "\n".join(f"• {name}" for name in self._running_actions)
        with Vertical(id="leave-dialog"):
            yield Label("Leave focus?", id="leave-title")
            yield Label(
                f"The following are still running:\n\n{bullets}\n\n"
                f"Leaving will stop them and return to {self._destination}.",
                id="leave-body",
            )
            with Horizontal(id="leave-buttons"):
                yield Button("Stay", id="leave-cancel")
                yield Button("Stop and leave", variant="warning", id="leave-confirm")

    @on(Button.Pressed, "#leave-confirm")
    def confirm_button(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#leave-cancel")
    def cancel_button(self) -> None:
        self.dismiss(False)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
