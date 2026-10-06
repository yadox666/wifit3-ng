from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Footer, DataTable, Static
from textual.screen import ModalScreen
from textual import events, on
from textual.binding import Binding

from .vault_table import VaultTable
from .vault_item import VaultItemView
from .vault_import import VaultImportModal
from wifit3.ui.vault.job_pane import JobTrackerPane

if TYPE_CHECKING:
    from wifit3.models import AccessPoint


class VaultDrawer(ModalScreen):
    """The Vault drawer overlay."""

    BINDINGS = [
        Binding("v", "dismiss_drawer", "Close", show=False),
        Binding("escape", "dismiss_drawer", "Close", show=True),
        Binding("z", "export_zip", "Export Zip", show=True),
        Binding("o", "show_directory", "Show Dir", show=True),
        Binding("a", "add_credential", "Add", show=True),
        Binding("p", "add_psk", "Add PSK", show=True),
    ]

    CSS = """
    VaultDrawer {
        align: center bottom;
        background: rgba(0, 0, 0, 0.4);
    }
    #vault-content {
        width: 100%;
        max-height: 75%;
        background: $surface;
        offset-y: 100%;
        transition: offset 200ms in_out_cubic;
    }
    VaultDrawer.open #vault-content {
        offset-y: 0%;
    }
    #vault-ap-context {
        display: none;
        height: 3;
        padding: 0 1;
        background: $boost;
        align: left middle;
    }
    #vault-ap-context.visible { display: block; }
    #vault-ap-context-label {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }
    #vault-add-psk {
        width: auto;
        min-width: 18;
        height: 3;
    }
    """

    def __init__(self, access_point: "AccessPoint | None" = None) -> None:
        super().__init__()
        self._access_point = access_point

    def compose(self) -> ComposeResult:
        with Container(id="vault-content"):
            with Horizontal(
                id="vault-ap-context",
                classes="visible" if self._access_point is not None else "",
            ):
                yield Static(self._context_label(), id="vault-ap-context-label")
                yield Button("Add PSK", id="vault-add-psk", variant="primary")
            with Horizontal():
                yield VaultTable(id="vault-table")
                yield VaultItemView(id="vault-item")
            yield JobTrackerPane()
            yield Footer()

    def on_mount(self) -> None:
        self.call_after_refresh(lambda: self.add_class("open"))
        self.call_after_refresh(self._focus_list)

    def _focus_list(self) -> None:
        """Land focus on the AP list so up/down works without a Tab press."""
        try:
            self.query_one("#vault-aps", DataTable).focus()
        except Exception:
            pass

    def _context_label(self) -> str:
        if self._access_point is None:
            return ""
        name = self._access_point.ssid or "‹hidden SSID›"
        return f"Selected AP: {name}  ·  {self._access_point.bssid}"

    def action_dismiss_drawer(self) -> None:
        if self.has_class("open"):
            self.remove_class("open")
            def _do_dismiss():
                self.dismiss()
            self.set_timer(0.35, _do_dismiss)

    @on(events.Click)
    def on_click(self, event: events.Click) -> None:
        # Dismiss if clicking outside the #vault-content container
        # Since ModalScreen catches clicks outside its children, `event.control == self` means background.
        if event.control == self:
            self.action_dismiss_drawer()

    def _load_widget(self, bssid: str) -> None:
        widget = self.query_one("#vault-item", VaultItemView)
        table = self.query_one("#vault-table", VaultTable)
        entry = table._aps.get(bssid)
        if entry is not None:
            widget.load(bssid, entry[0], entry[1])
        else:
            widget.load("", None, [])

    @on(VaultTable.TableReloaded)
    def _table_reloaded(self, event: VaultTable.TableReloaded) -> None:
        table = self.query_one("#vault-aps", DataTable)
        if table.row_count > 0:
            try:
                key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
                self._load_widget(key)
            except Exception:
                from textual.coordinate import Coordinate
                key = table.coordinate_to_cell_key(Coordinate(0, 0)).row_key.value
                self._load_widget(key)
        else:
            self._load_widget("")

    @on(DataTable.RowHighlighted, "#vault-aps")
    def _ap_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value is not None:
            self._load_widget(event.row_key.value)

    @on(VaultItemView.CapturesChanged)
    def _captures_changed(self) -> None:
        self.query_one("#vault-table", VaultTable).reload_table()

    def action_export_zip(self) -> None:
        try:
            out = self.app.vault.zip_captures(self.app.vault.all_captures())
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        if out is None:
            self.notify("Nothing to export", severity="warning")
            return
        self.notify(f"Exported to {out}")

    def action_show_directory(self) -> None:
        try:
            self.app.vault.open_directory()
        except OSError as exc:
            self.notify(f"Could not open captures dir: {exc}", severity="error")

    def action_add_credential(self) -> None:
        self._open_import("wpa")

    def action_add_psk(self) -> None:
        self._open_import("wpa")

    @on(Button.Pressed, "#vault-add-psk")
    def _add_psk_pressed(self) -> None:
        self.action_add_psk()

    def _open_import(self, credential_type: str) -> None:
        def imported(saved: bool | None) -> None:
            if not saved:
                return
            self.query_one("#vault-table", VaultTable).reload_table()
            self.notify("Credential added to the local Vault")

        self.app.push_screen(
            VaultImportModal(
                self._access_point,
                credential_type=credential_type,
            ),
            imported,
        )
