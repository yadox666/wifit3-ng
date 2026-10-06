from __future__ import annotations

import platform
import webbrowser

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from wifit3 import __version__
from wifit3.updates import RELEASES_URL, UpdateInfo, can_install_update


class UpdateAvailableModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Later")]

    DEFAULT_CSS = """
    UpdateAvailableModal { align: center middle; }
    UpdateAvailableModal #update-dialog {
        width: 58; max-width: 92%; height: auto;
        border: thick $success; background: $surface; padding: 1 2;
    }
    UpdateAvailableModal #update-title {
        text-style: bold; color: $success; text-align: center; margin-bottom: 1;
    }
    UpdateAvailableModal #update-details { text-align: center; margin-bottom: 1; }
    UpdateAvailableModal #update-actions { height: auto; align: center middle; }
    """

    def __init__(self, update: UpdateInfo) -> None:
        super().__init__()
        self._update = update

    def compose(self) -> ComposeResult:
        with Vertical(id="update-dialog"):
            yield Label("wifit3-ng update available", id="update-title")
            yield Static(
                f"Installed: [bold]{self._update.current_version}[/bold]\n"
                f"Available: [bold green]{self._update.latest_version}[/bold green]\n\n"
                "A verified release is available for your operating system.",
                id="update-details",
            )
            with Horizontal(id="update-actions"):
                if can_install_update(self._update):
                    yield Button("Install update", variant="success", id="update-install")
                else:
                    yield Button("Open release", variant="success", id="update-open")
                yield Button("Later", id="update-later")

    @on(Button.Pressed, "#update-install")
    def install_update(self) -> None:
        self.app.install_update(self._update)
        self.dismiss()

    @on(Button.Pressed, "#update-open")
    def open_release(self) -> None:
        webbrowser.open(self._update.release_url)
        self.dismiss()

    @on(Button.Pressed, "#update-later")
    def close(self) -> None:
        self.dismiss()


class AboutModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    AboutModal { align: center middle; }
    AboutModal #about-dialog {
        width: 66; max-width: 92%; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    AboutModal #about-title { text-style: bold; text-align: center; margin-bottom: 1; }
    AboutModal #about-details { margin-bottom: 1; }
    AboutModal #about-actions { height: auto; align: center middle; }
    """

    def compose(self) -> ComposeResult:
        array = getattr(self.app, "array", None)
        members = array.members if array is not None else []
        adapter_text = (
            "\n".join(
                f"• {member.name}: {member.description} [{member.chipset or 'unknown'}]"
                for member in members
            )
            or "No active Wi-Fi adapters"
        )
        with Vertical(id="about-dialog"):
            yield Label(f"wifit3-ng {__version__}", id="about-title")
            yield Static(
                f"[dim]Platform[/dim]  {platform.system()} {platform.release()}\n"
                f"[dim]Python[/dim]    {platform.python_version()}\n\n"
                f"[bold]Active hardware[/bold]\n{adapter_text}\n\n"
                "[dim]Update checks contact only GitHub's official releases API and never "
                "send scan results, identifiers, or credentials.[/dim]",
                id="about-details",
            )
            with Horizontal(id="about-actions"):
                yield Button("Check for updates", variant="primary", id="about-check")
                yield Button("Open releases", id="about-releases")
                yield Button("Close", id="about-close")

    @on(Button.Pressed, "#about-check")
    def check_updates(self) -> None:
        self.app.check_updates(show_current=True)

    @on(Button.Pressed, "#about-releases")
    def open_releases(self) -> None:
        webbrowser.open(RELEASES_URL)

    @on(Button.Pressed, "#about-close")
    def close(self) -> None:
        self.dismiss()
