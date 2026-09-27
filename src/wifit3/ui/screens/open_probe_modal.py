from __future__ import annotations

import time

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Select


class OpenProbeSsidModal(ModalScreen[tuple[str, int, str] | None]):
    """Configure an automated probe honeypot test."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    OpenProbeSsidModal { align: center middle; }
    OpenProbeSsidModal #dialog {
        width: 64; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    OpenProbeSsidModal #title {
        width: 1fr; text-align: center; text-style: bold; margin-bottom: 1;
    }
    OpenProbeSsidModal #description { height: auto; color: $text-muted; margin-bottom: 1; }
    OpenProbeSsidModal .field-label { margin-top: 1; }
    OpenProbeSsidModal #buttons { height: auto; align: center middle; margin-top: 1; }
    OpenProbeSsidModal #buttons Button { margin: 0 1; }
    """

    def __init__(self, client) -> None:
        super().__init__()
        self.client = client

    def compose(self) -> ComposeResult:
        now = time.time()
        options = []
        for ssid in sorted(self.client.probed_ssids):
            observation = self.client.probe_observations.get(ssid)
            if observation is None:
                continue
            age = max(0, int(now - observation.last_seen))
            history = " · history" if observation.historical else ""
            options.append((
                f"{escape(ssid)} · CH {observation.channel} · "
                f"{observation.count} probes · {age}s ago{history}",
                ssid,
            ))
        with Vertical(id="dialog"):
            yield Label("Automated Probe Honeypot Test", id="title")
            yield Label(
                "Select an observed SSID, advertised security, and duration. WiFiT3 "
                "automatically chooses the interface, channel, and random BSSID.",
                id="description",
            )
            yield Label("Probe SSID", classes="field-label")
            yield Select(
                options,
                value=options[0][1] if options else Select.BLANK,
                allow_blank=False,
                id="probe-ssid",
            )
            yield Label("Advertised security", classes="field-label")
            yield Select(
                [
                    ("OPEN (association and DHCP observation)", "OPEN"),
                    ("WPA2-PSK (capture M1/M2 material to Vault)", "WPA2"),
                ],
                value="OPEN",
                allow_blank=False,
                id="probe-encryption",
            )
            yield Label("Duration", classes="field-label")
            yield Select(
                [(f"{minutes} minute{'s' if minutes > 1 else ''}", minutes * 60)
                 for minutes in range(1, 6)],
                value=60,
                allow_blank=False,
                id="probe-duration",
            )
            with Horizontal(id="buttons"):
                yield Button("Start Honeypot", variant="warning", id="start")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            ssid = self.query_one("#probe-ssid", Select).value
            duration = self.query_one("#probe-duration", Select).value
            encryption = self.query_one("#probe-encryption", Select).value
            self.dismiss(
                (ssid, duration, encryption)
                if (
                    isinstance(ssid, str)
                    and isinstance(duration, int)
                    and encryption in ("OPEN", "WPA2")
                )
                else None
            )
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)
