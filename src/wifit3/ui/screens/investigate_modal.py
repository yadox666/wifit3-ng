"""Scrollable investigation report for the focused AP or station."""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from wifit3.persist.config import Config
from wifit3.ui.investigate import InvestigateReport, save_investigation_markdown


class InvestigateModal(ModalScreen[None]):
    """Read-only explanation of the focused AP or client."""

    BINDINGS = [Binding("escape", "dismiss", "Close", show=False)]

    DEFAULT_CSS = """
    InvestigateModal {
        align: center middle;
        background: $background 85%;
    }
    InvestigateModal > #investigate-box {
        width: 88;
        max-width: 96%;
        height: 90%;
        border: round $primary;
        background: $panel;
        padding: 0 1 1 1;
    }
    InvestigateModal > #investigate-box > #investigate-title {
        height: 1;
        text-style: bold;
        color: $accent;
    }
    InvestigateModal .section-heading {
        height: auto;
        margin-top: 1;
        text-style: bold;
        color: $text;
    }
    InvestigateModal .detail-row {
        width: 100%;
        height: auto;
        color: $text-muted;
    }
    InvestigateModal .conclusion {
        width: 100%;
        height: auto;
        margin-top: 1;
        margin-bottom: 1;
        padding: 0 1;
        border-left: heavy $primary;
        background: $primary 10%;
        color: $text;
    }
    InvestigateModal #investigate-actions {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    InvestigateModal #investigate-actions Button {
        width: auto;
        min-width: 16;
        margin: 0 2;
    }
    """

    def __init__(self, report: InvestigateReport) -> None:
        super().__init__()
        self._report = report

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="investigate-box"):
            yield Label(self._report.title, id="investigate-title")
            for paragraph in self._report.conclusion.split("\n\n"):
                if paragraph.strip():
                    yield Static(paragraph, classes="conclusion")
            for section in self._report.sections:
                yield Label(section.title, classes="section-heading")
                for line in section.lines:
                    yield Static(line, classes="detail-row")
            with Horizontal(id="investigate-actions"):
                yield Button("Close", id="close-investigate")
                yield Button("Save to MD", id="save-investigate")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-investigate":
            self.dismiss()
        elif event.button.id == "save-investigate":
            self._save_markdown()

    def _save_markdown(self) -> None:
        dest = Path(Config.captures_dir) / "scan_exports"
        try:
            path = save_investigation_markdown(self._report, dest)
        except OSError as exc:
            self.notify(str(exc), title="Investigate", severity="error")
            return
        self.notify(f"Saved {path.name}", title="Investigate")
