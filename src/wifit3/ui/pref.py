"""Ctrl+P preferences modal."""
from rich.padding import Padding
from rich.style import Style
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Horizontal, Vertical, VerticalGroup, VerticalScroll
from textual.events import Event
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import Button, Checkbox, ContentSwitcher, Input, Label, Select, Tab, Tabs

from wifit3.persist.config import Config
from wifit3.ui.screens.targets_editor import TargetsEditorDrawer


_PREF_SECTION_CSS = """
.pref-section {
    height: auto;
    margin-bottom: 1;
}
.pref-tag {
    text-style: bold;
    color: $accent;
    height: 1;
    margin-top: 1;
}
.pref-section > .pref-tag:first-child,
.pref-field > .pref-tag:first-child {
    margin-top: 0;
}
.pref-field {
    height: auto;
    margin-bottom: 1;
}
"""


def _pref_tag(text: str) -> Label:
    return Label(text, classes="pref-tag")


class ThemeSetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS
    def compose(self) -> ComposeResult:
        yield _pref_tag("Color theme")
        yield Select(self._theme_options(), id="theme",
                     value=self.app.theme, allow_blank=False)

    @on(Select.Changed, "#theme")
    def select_theme(self, event: Select.Changed) -> None:
        self.app.theme = event.value

    def _theme_options(self) -> list[tuple[Text, str]]:
        options = []
        themes = sorted(self.app.available_themes.items(), key=self._sort_key)
        for name, theme in themes:
            fg = Color.parse(theme.primary).rich_color if theme.primary else None
            bg = Color.parse(theme.background).rich_color if theme.background else None
            styled_fg = Text(name, style=Style(color=fg, bold=True))
            styled_option = Padding(styled_fg, 0, style=Style(bgcolor=bg))
            options.append((styled_option, name))
        return options

    def _sort_key(self, key_value: tuple[str, Theme]):
        name, theme = key_value
        if 'wifit3' in name:
            return '0' + name
        return '1' + name if theme.dark else '2' + name


class SortDelaySetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS

    OPTIONS: list[tuple[str, float]] = [
        ("Instant", 0.0),
        ("0.25 seconds", 0.25),
        ("1 second", 1.0),
        ("2 seconds", 2.0),
        ("3 seconds", 3.0),
        ("5 seconds", 5.0),
        ("Never", -1.0),
    ]

    def compose(self) -> ComposeResult:
        yield _pref_tag("AP / client table sort delay")
        current = Config.scanner_sort_delay
        values = [val for _, val in self.OPTIONS]
        value = current if current in values else 2.0
        yield Select(self.OPTIONS, id="sort_delay", value=value, allow_blank=False)

    @on(Select.Changed, "#sort_delay")
    def select_sort_delay(self, event: Select.Changed) -> None:
        if event.value is not None:
            Config.scanner_sort_delay = float(event.value)


class ApExpirySetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS

    OPTIONS: list[tuple[str, float]] = [
        ("15 seconds", 15.0),
        ("30 seconds", 30.0),
        ("1 minute", 60.0),
        ("2 minutes", 120.0),
        ("5 minutes", 300.0),
        ("10 minutes", 600.0),
        ("Never", -1.0),
    ]

    def compose(self) -> ComposeResult:
        yield _pref_tag("Hide inactive Wi‑Fi and Bluetooth rows")
        current = Config.scanner_ap_expiry
        values = [value for _, value in self.OPTIONS]
        value = current if current in values else 30.0
        yield Select(self.OPTIONS, id="ap_expiry", value=value, allow_blank=False)

    @on(Select.Changed, "#ap_expiry")
    def select_ap_expiry(self, event: Select.Changed) -> None:
        if event.value is not None:
            Config.scanner_ap_expiry = float(event.value)


class ActiveIntensitySetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS

    def compose(self) -> ComposeResult:
        yield _pref_tag("Deauth / broadcast frame intensity")
        yield Select(
            [
                ("Low · 3 client rounds / 6 broadcast frames", "low"),
                ("Normal · 10 client rounds / 20 broadcast frames", "normal"),
                ("High · 20 client rounds / 40 broadcast frames", "high"),
            ],
            value=Config.active_action_intensity,
            allow_blank=False,
            id="active_action_intensity",
        )


class CapturesDirSetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS
    def compose(self) -> ComposeResult:
        yield _pref_tag("Handshake and capture save directory")
        yield Input(Config.captures_dir, id="captures_dir")


class GpsSetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS

    def compose(self) -> ComposeResult:
        yield _pref_tag("GPS serial port")
        yield Input(Config.gps_port, placeholder="COM3 or /dev/ttyUSB0 - blank = auto", id="gps_port")
        yield _pref_tag("Movement distance before logging a new fix (metres)")
        yield Input(
            str(Config.gps_movement_threshold_m),
            type="number",
            id="gps_movement_threshold_m",
        )
        yield _pref_tag("Maximum acceptable fix error radius (metres)")
        yield Input(
            str(Config.gps_max_accuracy_m),
            type="number",
            id="gps_max_accuracy_m",
        )


class TargetCaptureSetting(VerticalGroup):
    DEFAULT_CSS = _PREF_SECTION_CSS

    def compose(self) -> ComposeResult:
        yield _pref_tag("Wait for locked target to reappear")
        yield Select(
            [
                ("Reacquire for 30 seconds", 30.0),
                ("Reacquire for 1 minute", 60.0),
                ("Reacquire for 2 minutes", 120.0),
                ("Reacquire for 5 minutes", 300.0),
            ],
            value=Config.target_reacquire_timeout,
            allow_blank=False,
            id="target_reacquire_timeout",
        )
        yield _pref_tag("Locked-target capture file size")
        yield Select(
            [("25 MiB per file", 25), ("50 MiB per file", 50),
             ("100 MiB per file", 100), ("250 MiB per file", 250)],
            value=Config.target_capture_max_mb,
            allow_blank=False,
            id="target_capture_max_mb",
        )
        yield _pref_tag("Rotating capture parts per target")
        yield Select(
            [("1 capture part", 1), ("3 capture parts", 3),
             ("5 capture parts", 5), ("10 capture parts", 10),
             ("Unlimited capture parts", 0)],
            value=Config.target_capture_max_parts,
            allow_blank=False,
            id="target_capture_max_parts",
        )


class SaveFooter(Horizontal):
    DEFAULT_CSS = """
    SaveFooter {
        height: auto; margin: 0;
        align: right middle;
        background: transparent; }
    SaveFooter Button { height: auto }
    """

    def compose(self) -> ComposeResult:
        yield Button("Save", variant="primary", id="save")
        yield Button("Cancel", id="cancel")


class PreferencesModal(ModalScreen):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("a", "about", "About"),
        Binding("t", "targets", "Targets"),
    ]

    DEFAULT_CSS = """
    PreferencesModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.4);
    }
    PreferencesModal #dialog {
        width: 64;
        max-width: 92%;
        height: 28;
        max-height: 85%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    PreferencesModal #title {
        text-style: bold;
        text-align: center;
        height: 1;
        margin-bottom: 1;
    }
    PreferencesModal #prefs-tabs {
        margin-bottom: 1;
    }
    PreferencesModal #prefs-panels {
        height: 1fr;
        border: round $primary-darken-1;
        padding: 0 1;
        margin-bottom: 1;
    }
    PreferencesModal .pref-panel-scroll {
        height: 1fr;
    }
    PreferencesModal SaveFooter {
        margin-top: 0;
    }
    PreferencesModal .pref-tag {
        text-style: bold;
        color: $accent;
        height: 1;
        margin-top: 1;
    }
    PreferencesModal .pref-field > .pref-tag:first-child {
        margin-top: 0;
    }
    PreferencesModal .pref-field {
        height: auto;
        margin-bottom: 1;
    }
    """

    _TAB_PANELS: dict[str, str] = {
        "tab-general": "panel-general",
        "tab-scanner": "panel-scanner",
        "tab-safety": "panel-safety",
        "tab-captures": "panel-captures",
        "tab-gps": "panel-gps",
    }

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Preferences", id="title")
            yield Tabs(
                Tab("General", id="tab-general"),
                Tab("Scanner", id="tab-scanner"),
                Tab("Safety", id="tab-safety"),
                Tab("Captures", id="tab-captures"),
                Tab("GPS", id="tab-gps"),
                id="prefs-tabs",
            )
            with ContentSwitcher(id="prefs-panels", initial="panel-general"):
                with VerticalScroll(id="panel-general", classes="pref-panel-scroll"):
                    yield ThemeSetting()
                    with Vertical(classes="pref-field"):
                        yield _pref_tag("Application updates")
                        yield Checkbox(
                            "Check for updates on startup",
                            value=Config.auto_check_updates,
                            id="auto_check_updates",
                        )
                with VerticalScroll(id="panel-scanner", classes="pref-panel-scroll"):
                    yield SortDelaySetting()
                    yield ApExpirySetting()
                with VerticalScroll(id="panel-safety", classes="pref-panel-scroll"):
                    yield ActiveIntensitySetting()
                    with Vertical(classes="pref-field"):
                        yield _pref_tag("Confirmation before attacks")
                        yield Checkbox(
                            "Ask before deauth, twins, and similar actions",
                            value=Config.confirm_active_actions,
                            id="confirm_active_actions",
                        )
                    with Vertical(classes="pref-field"):
                        yield _pref_tag("WPS Push Button")
                        yield Checkbox(
                            "Auto-capture when a PBC window is detected",
                            value=Config.auto_wps_pbc,
                            id="auto_wps_pbc",
                        )
                with VerticalScroll(id="panel-captures", classes="pref-panel-scroll"):
                    yield CapturesDirSetting()
                    with Vertical(classes="pref-field"):
                        yield _pref_tag("Handshake archives")
                        yield Checkbox(
                            "Also write .pcap files for handshakes",
                            value=Config.save_pcap,
                            id="save_pcap",
                        )
                    yield TargetCaptureSetting()
                    with Vertical(classes="pref-field"):
                        yield _pref_tag("Target lock behavior")
                        yield Checkbox(
                            "Auto-lock when a saved target is seen",
                            value=Config.auto_lock_targets,
                            id="auto_lock_targets",
                        )
                    yield Label(
                        "[dim]Targets library: [bold]t[/bold] here or "
                        "[bold]Shift+T[/bold] from the scanner.[/dim]",
                        markup=True,
                    )
                with VerticalScroll(id="panel-gps", classes="pref-panel-scroll"):
                    yield GpsSetting()
            yield SaveFooter()

    @on(Tabs.TabActivated, "#prefs-tabs")
    def prefs_tab_activated(self, event: Tabs.TabActivated) -> None:
        tab_id = event.tab.id or "tab-general"
        panel_id = self._TAB_PANELS.get(tab_id, "panel-general")
        self.query_one("#prefs-panels", ContentSwitcher).current = panel_id

    def on_mount(self) -> None:
        self._original_theme = self.app.theme
        self._original_sort_delay = Config.scanner_sort_delay
        self._original_ap_expiry = Config.scanner_ap_expiry

    @on(Button.Pressed, "#save")
    def save_pressed(self, event: Event):
        Config.theme = self.app.theme
        Config.captures_dir = self.query_one("#captures_dir", Input).value
        old_gps_port = Config.gps_port
        Config.gps_port = self.query_one("#gps_port", Input).value.strip()
        try:
            Config.gps_movement_threshold_m = max(
                20.0,
                float(self.query_one("#gps_movement_threshold_m", Input).value),
            )
        except ValueError:
            self.notify("Movement distance must be a number", title="GPS", severity="error")
            return
        try:
            Config.gps_max_accuracy_m = max(
                1.0,
                float(self.query_one("#gps_max_accuracy_m", Input).value),
            )
        except ValueError:
            self.notify("GPS accuracy must be a number", title="GPS", severity="error")
            return
        if Config.gps_port != old_gps_port:
            self.app.reconfigure_gps(Config.gps_port)
        self.app.vault.refresh()
        Config.save_pcap = self.query_one("#save_pcap", Checkbox).value
        Config.auto_check_updates = self.query_one("#auto_check_updates", Checkbox).value
        Config.confirm_active_actions = self.query_one("#confirm_active_actions", Checkbox).value
        Config.auto_wps_pbc = self.query_one("#auto_wps_pbc", Checkbox).value
        self.app.pbc_enabled = Config.auto_wps_pbc
        Config.auto_lock_targets = self.query_one("#auto_lock_targets", Checkbox).value
        Config.target_reacquire_timeout = float(
            self.query_one("#target_reacquire_timeout", Select).value
        )
        Config.target_capture_max_mb = int(
            self.query_one("#target_capture_max_mb", Select).value
        )
        Config.target_capture_max_parts = int(
            self.query_one("#target_capture_max_parts", Select).value
        )
        Config.active_action_intensity = str(
            self.query_one("#active_action_intensity", Select).value
        )
        Config.scanner_sort_delay = float(self.query_one("#sort_delay", Select).value)
        Config.scanner_ap_expiry = float(self.query_one("#ap_expiry", Select).value)
        self._save_and_dismiss()

    def _save_and_dismiss(self) -> None:
        try:
            Config.save()
        except Exception as e:
            self.notify(str(e), title="Config Error")
        self.dismiss()

    @on(Button.Pressed, "#cancel")
    def cancel_pressed(self, event: Event):
        self.action_cancel()

    def action_cancel(self) -> None:
        self.app.theme = self._original_theme
        Config.scanner_sort_delay = self._original_sort_delay
        Config.scanner_ap_expiry = self._original_ap_expiry
        self.dismiss()

    def action_about(self) -> None:
        self.app.action_about()

    def action_targets(self) -> None:
        self.app.push_screen(TargetsEditorDrawer())

