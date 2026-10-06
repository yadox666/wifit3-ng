"""Pick a product-catalog family to pin on one offline AP or BT/BLE row."""
from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

from wifit3.observe.product_catalog import families, matching_families
from wifit3.ui.search_input import SearchInput, sync_search_input_has_text


class CatalogAssignModal(ModalScreen[str | None]):
    """Returns a catalog family id, or None when dismissed."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    CSS = """
    CatalogAssignModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.45);
    }
    #catalog-assign-panel {
        width: 72;
        max-width: 96%;
        height: 24;
        max-height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 0 1;
    }
    #catalog-assign-title {
        height: 2;
        content-align: center middle;
        text-style: bold;
    }
    #catalog-assign-hint {
        height: 1;
        color: $text-muted;
        margin-bottom: 1;
    }
    #catalog-assign-search {
        margin-bottom: 1;
    }
    #catalog-assign-table {
        height: 1fr;
        border: round $primary-darken-2;
    }
    #catalog-assign-toolbar {
        height: auto;
        margin-top: 1;
        align: left middle;
    }
    #catalog-assign-toolbar Button {
        margin-right: 1;
    }
    """

    def __init__(self, *, subject: str) -> None:
        super().__init__()
        self._subject = subject
        self._query = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="catalog-assign-panel"):
            yield Static("Assign product family", id="catalog-assign-title")
            yield Static(self._subject, id="catalog-assign-hint")
            yield SearchInput(
                placeholder="Search class, label, or family id…",
                id="catalog-assign-search",
            )
            yield DataTable(id="catalog-assign-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="catalog-assign-toolbar"):
                yield Button("Assign", variant="primary", id="catalog-assign-ok", compact=True)
                yield Button("Clear manual", id="catalog-assign-clear", compact=True)
                yield Button("Cancel", id="catalog-assign-cancel", compact=True)

    def on_mount(self) -> None:
        table = self.query_one("#catalog-assign-table", DataTable)
        table.add_column("CLASS", key="class", width=16)
        table.add_column("FAMILY", key="label")
        table.add_column("ID", key="id", width=22)
        self._refresh_rows()
        self.call_after_refresh(self._focus_search)

    def _focus_search(self) -> None:
        self.query_one("#catalog-assign-search", SearchInput).focus()

    def _refresh_rows(self) -> None:
        table = self.query_one("#catalog-assign-table", DataTable)
        table.clear()
        shown = matching_families(self._query, "all")
        for family in shown:
            table.add_row(
                family.catalog_class or "·",
                family.label,
                family.id,
                key=family.id,
            )

    @on(Input.Changed, "#catalog-assign-search")
    def _search_changed(self, event: Input.Changed) -> None:
        if event.input.id != "catalog-assign-search":
            return
        sync_search_input_has_text(self.query_one("#catalog-assign-search", SearchInput))
        self._query = event.value.strip()
        self._refresh_rows()

    def _selected_family_id(self) -> str | None:
        table = self.query_one("#catalog-assign-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None
        if row_key.startswith("empty"):
            return None
        return row_key

    @on(Button.Pressed, "#catalog-assign-ok")
    @on(DataTable.RowSelected, "#catalog-assign-table")
    def _assign(self, _event: object = None) -> None:
        family_id = self._selected_family_id()
        if not family_id:
            self.notify("Select a family row first.", severity="warning")
            return
        self.dismiss(family_id)

    @on(Button.Pressed, "#catalog-assign-clear")
    def _clear_manual(self) -> None:
        self.dismiss("")

    @on(Button.Pressed, "#catalog-assign-cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)
