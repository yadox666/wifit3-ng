"""Modal for the startup background monitor: progress, live counts, and stop."""
from __future__ import annotations

from collections.abc import Callable

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, ProgressBar, Static


class BackgroundMonitorModal(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "stop", "Stop scan"),
    ]

    DEFAULT_CSS = """
    BackgroundMonitorModal { align: center middle; }
    BackgroundMonitorModal #background-monitor-dialog {
        width: 44; max-width: 92%; height: auto;
        border: thick $warning; background: $surface; padding: 1 2;
    }
    BackgroundMonitorModal #background-monitor-title {
        width: 1fr; text-align: center; text-style: bold; margin-bottom: 1;
    }
    BackgroundMonitorModal #background-monitor-hint {
        width: 1fr; text-align: center; color: $text-muted; margin-bottom: 1;
    }
    BackgroundMonitorModal #background-progress-bar {
        width: 1fr; margin-bottom: 0;
    }
    BackgroundMonitorModal #background-progress-bar Bar { width: 1fr; }
    BackgroundMonitorModal #background-progress-rule {
        width: 1fr; height: 1; color: $primary-darken-1;
        text-align: center; margin: 1 0 0 0;
    }
    BackgroundMonitorModal #background-progress-stats {
        width: 1fr; height: 2; color: $text-muted;
        text-align: center; margin-bottom: 1;
    }
    BackgroundMonitorModal #background-monitor-buttons {
        height: auto; align: center middle;
    }
    BackgroundMonitorModal #background-monitor-buttons Button { margin: 0 1; }
    """

    def __init__(self, *, on_stop: Callable[[], None]) -> None:
        super().__init__()
        self._on_stop = on_stop

    def compose(self) -> ComposeResult:
        with Vertical(id="background-monitor-dialog"):
            yield Label("Background monitor", id="background-monitor-title")
            yield Static(
                "Recording on the startup screen. Close when you are done.",
                id="background-monitor-hint",
            )
            yield ProgressBar(total=None, show_eta=False, id="background-progress-bar")
            yield Static(
                "────────────────────────────────────",
                id="background-progress-rule",
                markup=False,
            )
            yield Static("", id="background-progress-stats", markup=False)
            with Horizontal(id="background-monitor-buttons"):
                yield Button("Stop scan", variant="error", id="background-stop")

    def on_mount(self) -> None:
        bar = self.query_one("#background-progress-bar", ProgressBar)
        bar.update(total=None)
        try:
            percentage = bar.query_one("#percentage")
            percentage.display = False
        except Exception:
            pass
        self.query_one("#background-stop", Button).focus()

    def update_stats(self, text: str) -> None:
        if self.is_mounted:
            self.query_one("#background-progress-stats", Static).update(text)

    def set_stopping(self) -> None:
        if not self.is_mounted:
            return
        self.query_one("#background-stop", Button).disabled = True
        self.query_one("#background-monitor-hint", Static).update("Stopping…")

    def action_stop(self) -> None:
        self._on_stop()

    @on(Button.Pressed, "#background-stop")
    def _on_stop_pressed(self, _event: Button.Pressed) -> None:
        self._on_stop()
