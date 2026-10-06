from __future__ import annotations

import re

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from wifit3.models import AccessPoint


_BSSID_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


class VaultImportModal(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    VaultImportModal { align: center middle; }
    VaultImportModal #import-dialog {
        width: 62; max-width: 92%; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    VaultImportModal #import-title { text-style: bold; text-align: center; margin-bottom: 1; }
    VaultImportModal Label { color: $text-muted; }
    VaultImportModal Input, VaultImportModal Select { margin-bottom: 1; }
    VaultImportModal #import-error { color: $error; min-height: 1; }
    VaultImportModal #import-actions { height: auto; align: right middle; }
    """

    def __init__(
        self,
        access_point: AccessPoint | None = None,
        *,
        credential_type: str = "wpa",
    ) -> None:
        super().__init__()
        self._access_point = access_point
        self._credential_type = credential_type

    def compose(self) -> ComposeResult:
        ssid = self._access_point.ssid if self._access_point is not None else ""
        bssid = self._access_point.bssid if self._access_point is not None else ""
        with Vertical(id="import-dialog"):
            yield Label("Add credential", id="import-title")
            yield Label("Network name")
            yield Input(value=ssid or "", placeholder="SSID", id="import-ssid")
            yield Label(self._bssid_label(self._credential_type), id="import-bssid-label")
            yield Input(
                value=bssid,
                placeholder="Optional for WPA - blank covers every AP of this SSID",
                id="import-bssid",
            )
            yield Label("Credential type")
            yield Select(
                [("WPA/WPA2 passphrase", "wpa"), ("WEP key (hex)", "wep"),
                 ("WPS PIN + passphrase", "wps")],
                value=self._credential_type, allow_blank=False, id="import-type",
            )
            yield Label("Credential")
            yield Input(placeholder="Passphrase or hexadecimal WEP key", password=True, id="import-secret")
            yield Label("WPS PIN (only for WPS imports)")
            yield Input(placeholder="8 digits", id="import-pin")
            yield Static("", id="import-error")
            with Horizontal(id="import-actions"):
                yield Button("Cancel", id="import-cancel")
                yield Button("Save", variant="primary", id="import-save")

    def on_mount(self) -> None:
        if self._access_point is not None:
            self.query_one("#import-secret", Input).focus()

    @staticmethod
    def _bssid_label(kind: str) -> str:
        if kind == "wpa":
            return "Access point address (optional)"
        return "Access point address"

    @on(Select.Changed, "#import-type")
    def _credential_type_changed(self, event: Select.Changed) -> None:
        self.query_one("#import-bssid-label", Label).update(self._bssid_label(str(event.value)))

    @on(Button.Pressed, "#import-save")
    def save(self) -> None:
        ssid = self.query_one("#import-ssid", Input).value.strip()
        bssid = self.query_one("#import-bssid", Input).value.strip().lower()
        kind = str(self.query_one("#import-type", Select).value)
        secret = self.query_one("#import-secret", Input).value
        pin = self.query_one("#import-pin", Input).value.strip()
        error = self._validate(ssid, bssid, kind, secret, pin)
        if error:
            self.query_one("#import-error", Static).update(error)
            return
        ap = AccessPoint(bssid=bssid, ssid=ssid)
        if kind == "wpa":
            result = self.app.vault.save_wpa_psk(ap, secret)
        elif kind == "wep":
            result = self.app.vault.save_wep_key(ap, bytes.fromhex(secret))
        else:
            result = self.app.vault.save_wps_pin(ap, pin, secret)
        if result is None:
            self.query_one("#import-error", Static).update("Credential could not be saved")
            return
        self.dismiss(True)

    def _validate(self, ssid: str, bssid: str, kind: str, secret: str, pin: str) -> str:
        if not ssid or len(ssid.encode("utf-8")) > 32:
            return "SSID must contain 1 to 32 bytes"
        if bssid:
            if not _BSSID_RE.fullmatch(bssid):
                return "Enter a BSSID such as AA:BB:CC:DD:EE:FF, or leave it blank for WPA"
        elif kind != "wpa":
            return "WEP and WPS credentials need an access point address"
        if kind in {"wpa", "wps"}:
            if not (8 <= len(secret) <= 63 or (
                len(secret) == 64 and all(char in "0123456789abcdefABCDEF" for char in secret)
            )):
                return "WPA passphrases require 8–63 characters, or 64 hexadecimal digits"
        if kind == "wep":
            if len(secret) not in {10, 26, 32, 58}:
                return "WEP keys require 10, 26, 32, or 58 hexadecimal digits"
            if any(char not in "0123456789abcdefABCDEF" for char in secret):
                return "WEP keys must be hexadecimal"
        if kind == "wps" and (len(pin) != 8 or not pin.isdigit()):
            return "WPS PIN must contain exactly 8 digits"
        return ""

    @on(Button.Pressed, "#import-cancel")
    def cancel_button(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)
