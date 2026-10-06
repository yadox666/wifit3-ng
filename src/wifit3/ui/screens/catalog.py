"""Browsable and editable product catalog (stock + user overrides)."""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, Static

from wifit3.ui.search_input import SearchInput, sync_search_input_has_text

from wifit3.observe.product_catalog import (
    name_regex_reference_lines,
    CatalogFamily,
    families,
    family_classes,
    matching_families,
    reload_catalog,
)
from wifit3.ui.notification_center import WifiteHeader
from wifit3.ui.screens.catalog_editor import CatalogEditPanel
from wifit3.ui.screens.vault_item import ConfirmModal


class CatalogView(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("f", "focus_filter", "Search"),
        Binding("/", "focus_filter", "Search", show=False),
        Binding("e", "toggle_edit", "Edit"),
        Binding("n", "new_family", "New"),
        Binding("d", "apply_to_offline_db", "Apply to DB rows"),
        Binding("s", "save_family", "Save", show=False),
    ]

    CSS = """
    CatalogView { layout: vertical; background: $surface; }
    #catalog-body { height: 1fr; padding: 0 1; }
    #catalog-title {
        height: 1;
        content-align: center middle;
        text-style: bold;
        color: $accent;
    }
    #catalog-hint {
        height: 1;
        content-align: center middle;
        color: $text-muted;
    }
    #catalog-filters { height: 3; }
    #catalog-filter-class { width: 28; margin-right: 1; }
    #catalog-filter-text-box {
        width: 1fr;
        min-width: 16;
        height: auto;
        padding: 0;
        margin: 0;
    }
    #catalog-filter-text {
        width: 1fr;
        min-width: 12;
        border: none;
        padding: 0 1;
        margin: 0;
        background: transparent;
    }
    #catalog-filter-text.-has-text { background: $surface-darken-2; }
    #clear-catalog-filter-text {
        width: 3;
        min-width: 3;
        max-width: 3;
        height: 1;
        min-height: 1;
        border: none;
        padding: 0;
        margin: 0;
        background: transparent;
        color: $text-muted;
        content-align: center middle;
    }
    #clear-catalog-filter-text:hover,
    #clear-catalog-filter-text:focus {
        background: $primary;
        color: $text;
    }
    #catalog-split { height: 1fr; }
    #catalog-table {
        width: 3fr;
        height: 1fr;
        border: round $primary;
        border-title-color: $accent;
        border-title-style: bold;
    }
    #catalog-detail-scroll {
        width: 2fr;
        height: 1fr;
        margin-left: 1;
        border: round $accent;
        border-title-color: $accent;
        border-title-style: bold;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }
    #catalog-detail { height: auto; }
    CatalogEditPanel { display: none; height: auto; width: 100%; }
    CatalogView.-editing CatalogEditPanel { display: block; }
    CatalogView.-editing #catalog-detail { display: none; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._query = ""
        self._catalog_class = "all"
        self._ready = False
        self._editing = False
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        yield WifiteHeader(show_clock=False)
        with Vertical(id="catalog-body"):
            yield Static("PRODUCT CATALOG", id="catalog-title")
            yield Static(
                "Stock + your families · e edit · n new · d reapply to offline DB rows",
                id="catalog-hint",
            )
            with Horizontal(id="catalog-filters"):
                yield Select(
                    [("All classes", "all")],
                    value="all",
                    allow_blank=False,
                    compact=True,
                    id="catalog-filter-class",
                )
                yield Horizontal(
                    SearchInput(
                        placeholder="family, class, clue, note…",
                        compact=True,
                        id="catalog-filter-text",
                    ),
                    Button(
                        "×",
                        id="clear-catalog-filter-text",
                        tooltip="Clear search",
                        compact=True,
                    ),
                    id="catalog-filter-text-box",
                )
            with Horizontal(id="catalog-split"):
                yield DataTable(
                    id="catalog-table",
                    cursor_type="row",
                    zebra_stripes=True,
                )
                yield VerticalScroll(
                    Static("", id="catalog-detail"),
                    CatalogEditPanel(),
                    id="catalog-detail-scroll",
                )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#catalog-table", DataTable)
        table.add_column("", key="mark", width=3)
        table.add_column("", key="src", width=3)
        table.add_column("CLASS", key="class", width=16)
        table.add_column("FAMILY", key="family")
        table.add_column("CLUES", key="clues", width=7)
        self.query_one("#catalog-detail-scroll").border_title = "FAMILY"
        self._refresh_class_filter()
        self._ready = True
        self._fill_table()

    def _refresh_class_filter(self) -> None:
        select = self.query_one("#catalog-filter-class", Select)
        options = [("All classes", "all"), *((name, name) for name in family_classes())]
        select.set_options(options)
        if self._catalog_class not in {value for _label, value in options}:
            self._catalog_class = "all"
            select.value = "all"

    def on_input_changed(self, event: Input.Changed) -> None:
        if not self._ready or event.input.id != "catalog-filter-text":
            return
        self._query = event.value
        self._fill_table()

    def on_select_changed(self, event: Select.Changed) -> None:
        if not self._ready or event.select.id != "catalog-filter-class":
            return
        self._catalog_class = str(event.value)
        self._fill_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "clear-catalog-filter-text":
            return
        event.stop()
        search = self.query_one("#catalog-filter-text", Input)
        if not self._query:
            search.focus()
            return
        search.value = ""
        self._query = ""
        sync_search_input_has_text(search)
        self._fill_table()
        search.focus()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.data_table.id != "catalog-table":
            return
        self._selected_id = str(event.row_key.value)
        if self._editing:
            self.query_one(CatalogEditPanel).load_family(self._selected_id)
        else:
            self._show(self._selected_id)

    @on(CatalogEditPanel.Saved)
    def _on_editor_saved(self, event: CatalogEditPanel.Saved) -> None:
        self._selected_id = event.family_id
        self._refresh_class_filter()
        self._fill_table()
        self._exit_edit(select_id=event.family_id)

    @on(CatalogEditPanel.Deleted)
    def _on_editor_deleted(self) -> None:
        self._exit_edit()
        self._refresh_class_filter()
        self._fill_table()

    def action_back(self) -> None:
        if self._editing:
            self._exit_edit()
            return
        self.app.pop_screen()

    def action_focus_filter(self) -> None:
        self.query_one("#catalog-filter-text", Input).focus()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "apply_to_offline_db" and self._editing:
            return False
        return True

    def action_apply_to_offline_db(self) -> None:
        if self._editing:
            return
        self.app.push_screen(
            ConfirmModal(
                "Re-run the current catalog against every Wi-Fi access point and "
                "Bluetooth device in the offline history databases?\n\n"
                "[dim]Raw advertisement bytes are not stored in history, so only "
                "name, OUI, company-id, service UUID, and protocol rules can "
                "match again.[/dim]",
            ),
            self._on_apply_offline_catalog,
        )

    def _on_apply_offline_catalog(self, confirmed: bool | None) -> None:
        if not confirmed:
            return
        self._run_catalog_reapply()

    @work(thread=True, group="catalog_reapply", exit_on_error=False)
    def _run_catalog_reapply(self) -> None:
        reload_catalog()
        wifi = self.app.ap_history_store.reapply_product_catalog()
        bluetooth = self.app.bluetooth_history_store.reapply_product_catalog()
        self.app.call_from_thread(self._notify_catalog_reapply, wifi, bluetooth)

    def _notify_catalog_reapply(self, wifi: int, bluetooth: int) -> None:
        self.notify(
            f"Updated catalog on {wifi:,} Wi-Fi AP(s) and "
            f"{bluetooth:,} Bluetooth row(s).",
            title="Offline database",
        )

    def action_toggle_edit(self) -> None:
        if self._editing:
            self._exit_edit()
            return
        family_id = self._selected_id or _selected_family_id(
            self.query_one("#catalog-table", DataTable),
        )
        if not family_id:
            self.notify("Select a family to edit", severity="warning")
            return
        self._enter_edit(family_id)

    def action_new_family(self) -> None:
        self._editing = True
        self.add_class("-editing")
        self.query_one("#catalog-detail-scroll").border_title = "EDIT FAMILY"
        editor = self.query_one(CatalogEditPanel)
        editor.begin_new()
        self.refresh_bindings()

    def action_save_family(self) -> None:
        if self._editing:
            self.query_one(CatalogEditPanel).query_one("#catalog-save", Button).press()

    def _enter_edit(self, family_id: str) -> None:
        self._editing = True
        self.add_class("-editing")
        self.query_one("#catalog-detail-scroll").border_title = "EDIT FAMILY"
        self.query_one(CatalogEditPanel).load_family(family_id)
        self.refresh_bindings()

    def _exit_edit(self, *, select_id: str | None = None) -> None:
        self._editing = False
        self.remove_class("-editing")
        self.query_one("#catalog-detail-scroll").border_title = "FAMILY"
        self.refresh_bindings()
        if select_id:
            self._selected_id = select_id
        self._show(self._selected_id)

    def _fill_table(self) -> None:
        table = self.query_one("#catalog-table", DataTable)
        previous = self._selected_id or _selected_family_id(table)
        shown = matching_families(self._query, self._catalog_class)
        total = len(families())
        table.clear()
        for family in shown:
            table.add_row(
                Text("◆", style="bold yellow") if family.attention else Text("·", style="dim"),
                Text("U" if family.user_owned else "S", style="cyan" if family.user_owned else "dim"),
                Text(family.catalog_class or "·", style="cyan" if family.catalog_class else "dim"),
                Text(family.label, style="bold"),
                Text(str(len(family.clues)), style="dim", justify="right"),
                key=family.id,
            )
        if shown:
            count = f"{len(shown):,} / {total:,}" if len(shown) != total else f"{total:,}"
        else:
            count = f"0 / {total:,}"
        table.border_title = f"FAMILIES · {count}"
        if not shown:
            self._selected_id = None
            if not self._editing:
                self._show(None)
            return
        selected = previous if any(family.id == previous for family in shown) else shown[0].id
        self._selected_id = selected
        try:
            table.move_cursor(row=table.get_row_index(selected))
        except Exception:
            pass
        if self._editing:
            self.query_one(CatalogEditPanel).load_family(selected)
        else:
            self._show(selected)

    def _show(self, family_id: str | None) -> None:
        family = next((item for item in families() if item.id == family_id), None)
        shown = matching_families(self._query, self._catalog_class)
        self.query_one("#catalog-detail", Static).update(
            _family_detail(family, shown=len(shown), total=len(families())),
        )


def open_catalog(screen: Screen) -> None:
    """Push the catalog browser unless it is already in front."""
    if isinstance(screen.app.screen, CatalogView):
        return
    screen.app.push_screen(CatalogView())


def _selected_family_id(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    try:
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
    except Exception:
        return None


def _family_detail(family: CatalogFamily | None, *, shown: int, total: int) -> str:
    if family is None:
        return (
            "[dim]No family matches this search.[/dim]\n\n"
            f"[dim]{shown:,} of {total:,} families.[/dim]\n"
            "[dim]Press [bold]n[/bold] to add a family or [bold]e[/bold] to edit.[/dim]"
        )
    source = (
        "[cyan]User family[/cyan]"
        if family.user_owned
        else "[dim]Stock[/dim] · Save on edit keeps your override"
    )
    attention = (
        f"\n[bold yellow]◆[/bold yellow] {escape(family.attention)}\n"
        if family.attention else "\n"
    )
    notes = f"{escape(family.notes)}\n" if family.notes else ""
    clues = "\n".join(
        f"  [cyan]•[/cyan] {escape(clue)}" for clue in family.clues
    ) or "  [dim]none[/dim]"
    if any(clue.startswith("name regex ") for clue in family.clues):
        ex1, ex2 = name_regex_reference_lines()
        clues += (
            f"\n  [dim]Regex examples (full SSID): {escape(ex1)} · "
            f"{escape(ex2)}[/dim]"
        )
    return (
        f"[bold]{escape(family.label)}[/bold]  [dim]({escape(family.id)})[/dim]\n"
        f"[dim]{escape(family.catalog_class or 'Unclassified')}[/dim] · {source}"
        f"{attention}\n"
        f"{notes}\n"
        f"[bold]Clues[/bold]  [dim]{len(family.clues)} · any one is enough[/dim]\n"
        f"{clues}\n\n"
        "[dim]A hit is a hypothesis about the advertisement. "
        "[bold]e[/bold] edits · [bold]n[/bold] new · [bold]d[/bold] apply to DB rows.[/dim]\n"
        "[dim]Clues follow the public Fieldwatch catalog "
        "(MIT, Off Grid Pete LLC, 2026).[/dim]"
    )
