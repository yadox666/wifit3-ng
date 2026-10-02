"""Prompt for the app scan session name and optional notes at startup."""
from __future__ import annotations

from dataclasses import dataclass

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from wifit3.gps import GpsStatus
from wifit3.models.location import LocationFix


@dataclass(frozen=True, slots=True)
class SessionStartInput:
    name: str
    description: str


class SessionStartModal(ModalScreen[SessionStartInput]):
    BINDINGS = [
        Binding("escape", "cancel", "Use suggested name"),
        Binding("enter", "confirm", "Start session", show=False),
    ]

    DEFAULT_CSS = """
    SessionStartModal { align: center middle; }
    SessionStartModal #session-dialog {
        width: 70; max-width: 94%; height: auto;
        border: thick $accent; background: $surface; padding: 1 2;
    }
    SessionStartModal #session-title {
        text-style: bold; text-align: center; margin-bottom: 1;
    }
    SessionStartModal #session-hint {
        color: $text-muted; margin-bottom: 1;
    }
    SessionStartModal .session-row { height: auto; margin-bottom: 1; }
    SessionStartModal .session-label {
        width: 14; height: 3; content-align: left middle;
        color: $text-muted;
    }
    SessionStartModal Input { width: 1fr; }
    SessionStartModal #session-gps { height: auto; margin-bottom: 1; }
    SessionStartModal #session-buttons { height: auto; align: center middle; }
    SessionStartModal #session-buttons Button { margin: 0 1; }
    """

    def __init__(
        self,
        default_name: str,
        *,
        gps_fix: LocationFix | None = None,
        gps_status: GpsStatus | None = None,
        gps_configured_port: str = "",
    ) -> None:
        super().__init__()
        self._default_name = default_name
        self._gps_fix = gps_fix
        self._gps_status = gps_status
        self._gps_configured_port = gps_configured_port.strip()

    def _gps_summary(self) -> str | None:
        """Markup for the GPS row, or None when no receiver is in play."""
        if self._gps_fix is not None:
            fix = self._gps_fix
            alt = (
                f", alt {fix.altitude_m:.0f} m"
                if fix.altitude_m is not None
                else ""
            )
            return (
                f"[green]GPS fix[/green] · {fix.latitude:.5f}, {fix.longitude:.5f}"
                f"{alt} · ±{fix.accuracy_m:.0f} m"
            )
        if self._gps_status is not None:
            label = self._gps_status.label
            return (
                f"[dim]GPS connected ({label}) — waiting for satellite fix…[/dim]"
            )
        if self._gps_configured_port:
            return (
                f"[dim]Looking for GPS on {self._gps_configured_port}…[/dim]"
            )
        return None

    def compose(self) -> ComposeResult:
        with Vertical(id="session-dialog"):
            yield Label("Scan session", id="session-title")
            yield Static(
                "Name this run for Offline DB and history. "
                "Sightings are grouped under this label until you quit.",
                id="session-hint",
            )
            with Horizontal(classes="session-row"):
                yield Label("Name", classes="session-label")
                yield Input(
                    value=self._default_name,
                    placeholder="memorable-session-name",
                    id="session-name",
                )
            with Horizontal(classes="session-row"):
                yield Label("Notes", classes="session-label")
                yield Input(
                    placeholder="Site, client, band plan, …",
                    id="session-description",
                )
            gps_summary = self._gps_summary()
            if gps_summary is not None:
                yield Static(gps_summary, id="session-gps")
            with Horizontal(id="session-buttons"):
                yield Button("Start session", variant="primary", id="session-start")

    def on_mount(self) -> None:
        self.query_one("#session-name", Input).focus()

    def _confirm(self) -> None:
        name = self.query_one("#session-name", Input).value.strip()
        if not name:
            name = self._default_name
        description = self.query_one("#session-description", Input).value.strip()
        self.dismiss(SessionStartInput(name=name, description=description))

    @on(Button.Pressed, "#session-start")
    def start_pressed(self) -> None:
        self._confirm()

    def action_confirm(self) -> None:
        self._confirm()

    def action_cancel(self) -> None:
        self.dismiss(
            SessionStartInput(name=self._default_name, description=""),
        )
