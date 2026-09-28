from __future__ import annotations

from dataclasses import dataclass

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label


CONFIRMATION_TEXT = "DELETE NOW!"


@dataclass(frozen=True, slots=True)
class HistoryClearSelection:
    wifi: bool
    bluetooth: bool


class ClearHistoryModal(ModalScreen[HistoryClearSelection | None]):
    """Select histories and require an explicit destructive phrase."""

    DEFAULT_CSS = """
    ClearHistoryModal { align: center middle; }
    ClearHistoryModal #history-dialog {
        width: 72; max-width: 92%; height: auto; max-height: 92%;
        border: thick $error; background: $surface; padding: 1 2;
    }
    ClearHistoryModal #history-title {
        width: 100%; height: 1; text-align: center;
        text-style: bold; color: $error; margin-bottom: 1;
    }
    ClearHistoryModal #history-description { width: 100%; height: auto; }
    ClearHistoryModal #history-kept {
        width: 100%; height: auto; color: $text-muted;
    }
    ClearHistoryModal #history-options {
        width: 100%; height: auto; margin: 1 0;
    }
    ClearHistoryModal #history-options Checkbox { width: 100%; height: 1; }
    ClearHistoryModal #history-confirm-label {
        width: 100%; height: 1;
    }
    ClearHistoryModal #history-confirmation { width: 100%; }
    ClearHistoryModal #history-actions {
        width: 100%; height: auto; align: right middle;
    }
    ClearHistoryModal #history-actions Button {
        width: auto; min-width: 14; margin-left: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="history-dialog"):
            yield Label("CLEAR SAVED DEVICE HISTORY", id="history-title")
            yield Label(
                "Deletes reusable observations, saved targets and database events.",
                id="history-description",
            )
            yield Label(
                "Kept: PCAPs, keys, reports and scan exports.",
                id="history-kept",
            )
            with Vertical(id="history-options"):
                yield Checkbox(
                    "Wi-Fi · APs, SSIDs, profiles and Enterprise sessions",
                    id="clear-wifi-history",
                )
                yield Checkbox(
                    "Bluetooth / BLE · devices and event history",
                    id="clear-bluetooth-history",
                )
            yield Label(
                f"Type [bold]{CONFIRMATION_TEXT}[/bold] to confirm:",
                id="history-confirm-label",
            )
            yield Input(placeholder=CONFIRMATION_TEXT, id="history-confirmation")
            with Horizontal(id="history-actions"):
                yield Button("Cancel", id="cancel-history-clear")
                yield Button(
                    "Delete selected",
                    "error",
                    id="confirm-history-clear",
                    disabled=True,
                )

    @on(Input.Changed, "#history-confirmation")
    def confirmation_changed(self) -> None:
        self._update_confirmation()

    @on(Checkbox.Changed)
    def selection_changed(self) -> None:
        self._update_confirmation()

    def _update_confirmation(self) -> None:
        phrase = self.query_one("#history-confirmation", Input).value
        wifi = self.query_one("#clear-wifi-history", Checkbox).value
        bluetooth = self.query_one("#clear-bluetooth-history", Checkbox).value
        self.query_one("#confirm-history-clear", Button).disabled = not (
            phrase == CONFIRMATION_TEXT and (wifi or bluetooth)
        )

    @on(Button.Pressed, "#cancel-history-clear")
    def cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#confirm-history-clear")
    def confirm(self) -> None:
        if self.query_one("#history-confirmation", Input).value != CONFIRMATION_TEXT:
            return
        selection = HistoryClearSelection(
            wifi=self.query_one("#clear-wifi-history", Checkbox).value,
            bluetooth=self.query_one("#clear-bluetooth-history", Checkbox).value,
        )
        if selection.wifi or selection.bluetooth:
            self.dismiss(selection)

    def action_cancel(self) -> None:
        self.dismiss(None)
