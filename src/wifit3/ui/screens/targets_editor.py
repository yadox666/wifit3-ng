from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Select, Static, Tab, Tabs

from wifit3.persist.targets import SavedTarget, TargetStoreError
from wifit3.targeting import (
    TargetCandidate,
    editor_category,
    editor_category_label,
    observation_display_markup,
    observation_kind_subtitle,
)


class TargetsEditorDrawer(ModalScreen[SavedTarget | None]):
    """Centered modal for targets, whitelist entries, and manual additions."""

    BINDINGS = [
        Binding("escape", "close_editor", "Close", show=True),
        Binding("/", "focus_search", "Search", show=False),
    ]

    CSS = """
    TargetsEditorDrawer {
        align: center middle;
        background: rgba(0, 0, 0, 0.4);
    }
    #targets-editor-content {
        width: 100;
        max-width: 96%;
        height: 27;
        min-height: 22;
        max-height: 92%;
        background: $surface;
        border: thick $primary;
        padding: 0 1;
    }
    #targets-editor-title {
        height: 2;
        content-align: center middle;
        text-align: center;
        text-style: bold;
    }
    #targets-list-title {
        text-align: center;
        text-style: bold;
        height: 1;
        margin-bottom: 1;
    }
    #targets-editor-body {
        height: 1fr;
    }
    #targets-list-pane {
        width: 40;
        height: 1fr;
        border: round $primary-darken-1;
        padding: 0 1;
    }
    #targets-search {
        margin: 0 0 1 0;
    }
    #targets-table {
        height: 1fr;
    }
    #targets-detail-pane {
        width: 1fr;
        height: 1fr;
        margin-left: 1;
        border: round $primary-darken-1;
        padding: 0 1;
    }
    #targets-detail-pane.draft-mode {
        border: round $accent;
        background: $surface;
        padding: 0 1;
    }
    #targets-detail-header {
        height: auto;
        margin-bottom: 1;
    }
    #targets-detail-title {
        height: 1;
        text-style: bold;
    }
    #targets-detail-pane.draft-mode #targets-detail-title {
        color: $accent;
        text-align: center;
    }
    #targets-detail-meta {
        height: 1;
        color: $text-muted;
        text-align: center;
    }
    #targets-detail-pane.draft-mode #targets-detail-meta {
        text-style: italic;
    }
    #targets-detail-body {
        height: 1fr;
        min-height: 10;
    }
    #targets-detail-pane.draft-mode #targets-detail-body {
        height: 1fr;
        min-height: 0;
    }
    #targets-alias-block {
        height: 3;
        width: 100%;
        margin: 0;
    }
    #targets-alias-label {
        width: 8;
        height: 3;
        content-align: right middle;
        text-style: bold;
        padding-right: 1;
    }
    #targets-alias {
        width: 1fr;
        height: 3;
    }
    #targets-match-row {
        height: auto;
        min-height: 3;
        margin-bottom: 0;
    }
    #targets-detail-pane.draft-mode #targets-match-row {
        display: none;
    }
    #targets-detail-pane.draft-mode.show-match-row #targets-match-row {
        display: block;
    }
    #targets-observed-scroll {
        height: 1fr;
        min-height: 6;
    }
    #targets-detail-pane.draft-mode #targets-observed-scroll {
        height: 1fr;
        min-height: 5;
        max-height: 14;
        scrollbar-size-vertical: 0;
    }
    #targets-observed-card {
        height: auto;
        min-height: 5;
        border: round $primary-darken-2;
        background: $surface-darken-1;
        padding: 0 1 1 1;
        margin-bottom: 1;
        border-title-color: $accent;
        border-title-style: bold;
    }
    #targets-detail-pane.draft-mode #targets-observed-card {
        border: round $primary-darken-1;
        border-title-color: $accent;
        margin-bottom: 0;
    }
    #targets-detail-fields {
        width: 1fr;
        height: auto;
        padding: 0 0 0 0;
    }
    #targets-detail-actions {
        height: 3;
        min-height: 3;
        align: right middle;
    }
    #targets-detail-pane.draft-mode #targets-detail-actions {
        align: center middle;
    }
    #targets-detail-actions Button {
        width: 1fr;
        min-width: 0;
        margin-right: 1;
        height: 3;
    }
    #targets-detail-actions #targets-close {
        margin-right: 0;
        background: $surface-lighten-2;
        color: $text;
        border: tall $surface-lighten-3;
    }
    #targets-detail-actions #targets-close:focus,
    #targets-detail-actions #targets-close:hover {
        background: $surface-lighten-3;
    }
    #targets-list-actions {
        height: auto;
        margin-top: 1;
        align: center middle;
    }
    #targets-list-actions Button {
        width: 100%;
        margin: 0;
    }
    #targets-detail-error {
        color: $error;
        height: auto;
        min-height: 0;
    }
    """

    def __init__(
        self,
        *,
        prefill: TargetCandidate | None = None,
        select_id: str | None = None,
        default_category: str = "all",
        on_saved: Callable[[SavedTarget], None] | None = None,
    ) -> None:
        super().__init__()
        self._select_id = select_id
        self._category = default_category
        self._on_saved = on_saved
        self._search = ""
        self._context_candidate = prefill
        self._draft: TargetCandidate | None = None
        self._draft_role = "target"
        self._draft_match_mode = "id"
        self._suppress_row_highlight = False

    def compose(self) -> ComposeResult:
        with Container(id="targets-editor-content"):
            yield Static(
                "TARGETS & WHITELIST  [dim]Browse saved entries or create from the current selection[/dim]",
                id="targets-editor-title",
            )
            with Horizontal(id="targets-editor-body"):
                with Vertical(id="targets-list-pane"):
                    yield Label("Saved entries", id="targets-list-title")
                    yield Input(placeholder="Search alias or identifier…", id="targets-search")
                    yield Tabs(
                        Tab("All", id="tab-all"),
                        Tab("AP", id="tab-ap"),
                        Tab("STA", id="tab-sta"),
                        Tab("BLE", id="tab-ble"),
                        Tab("BT", id="tab-bt"),
                        Tab("Whitelist", id="tab-whitelist"),
                        id="targets-tabs",
                    )
                    yield DataTable(id="targets-table", cursor_type="row", zebra_stripes=True)
                    with Horizontal(id="targets-list-actions"):
                        yield Button("＋ New", id="targets-new", variant="primary")
                with Vertical(id="targets-detail-pane"):
                    with Vertical(id="targets-detail-header"):
                        yield Label("Select an entry", id="targets-detail-title")
                        yield Label("", id="targets-detail-meta")
                    with Vertical(id="targets-detail-body"):
                        with Horizontal(id="targets-alias-block"):
                            yield Label("Alias", id="targets-alias-label")
                            yield Input(
                                placeholder="Name this target…",
                                id="targets-alias",
                                max_length=64,
                            )
                        with Horizontal(id="targets-match-row"):
                            yield Select(
                                [("Target", "target"), ("Whitelist", "whitelist")],
                                id="targets-role",
                                value="target",
                            )
                            yield Select(
                                [
                                    ("Match ID / MAC / UUID", "id"),
                                    ("Match name / SSID", "name"),
                                    ("Match directed probe SSID", "probe"),
                                ],
                                id="targets-match-mode",
                                value="id",
                            )
                            yield Select(
                                [
                                    ("Wi-Fi AP", "wifi:ap"),
                                    ("Wi-Fi STA", "wifi:client"),
                                    ("Bluetooth", "bluetooth:device"),
                                ],
                                id="targets-kind",
                                value="wifi:ap",
                            )
                            yield Input(
                                placeholder="Identifier or name",
                                id="targets-identifier",
                            )
                        with VerticalScroll(id="targets-observed-scroll"):
                            with Container(id="targets-observed-card"):
                                yield Static("", id="targets-detail-fields", markup=True)
                    yield Label("", id="targets-detail-error")
                    with Horizontal(id="targets-detail-actions"):
                        yield Button("Save", id="targets-save", variant="primary")
                        yield Button("Delete", id="targets-delete", variant="error")
                        yield Button("Close", id="targets-close")

    def on_mount(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.add_columns("ALIAS", "ROLE", "TYPE")
        new_button = self.query_one("#targets-new", Button)
        if self._context_candidate is not None:
            new_button.label = "＋ New from selection"
            new_button.tooltip = self._context_candidate.title
        else:
            new_button.label = "＋ New manual target"
        self._reload_table(select_id=self._select_id)
        self.call_after_refresh(self._focus_list)

    def _focus_alias(self) -> None:
        try:
            self.query_one("#targets-alias", Input).focus()
        except Exception:
            pass

    def _focus_list(self) -> None:
        try:
            self.query_one("#targets-search", Input).focus()
        except Exception:
            pass

    def action_focus_search(self) -> None:
        self.query_one("#targets-search", Input).focus()

    def action_close_editor(self) -> None:
        self.dismiss(None)

    @on(events.Click)
    def on_click(self, event: events.Click) -> None:
        if event.control == self:
            self.action_close_editor()

    @on(Input.Changed, "#targets-search")
    def search_changed(self, event: Input.Changed) -> None:
        self._search = event.value.strip().casefold()
        self._reload_table()

    @on(Tabs.TabActivated, "#targets-tabs")
    def tab_changed(self, event: Tabs.TabActivated) -> None:
        mapping = {
            "tab-all": "all",
            "tab-ap": "ap",
            "tab-sta": "sta",
            "tab-ble": "ble",
            "tab-bt": "bt",
            "tab-whitelist": "whitelist",
        }
        self._category = mapping.get(event.tab.id or "", "all")
        self._reload_table()

    @on(DataTable.RowHighlighted, "#targets-table")
    def row_highlighted(self) -> None:
        if self._suppress_row_highlight or self._draft is not None:
            return
        target_id = self._selected_target_id()
        target = self.app.target_store.get(target_id)
        if target is not None:
            self._load_target(target)

    @on(DataTable.RowSelected, "#targets-table")
    def row_selected(self) -> None:
        if self._draft is None:
            return
        target_id = self._selected_target_id()
        if target_id is None:
            return
        target = self.app.target_store.get(target_id)
        if target is not None:
            self._load_target(target)

    def _filtered_targets(self) -> list[SavedTarget]:
        items = self.app.target_store.ordered()
        if self._category != "all":
            if self._category == "whitelist":
                items = [item for item in items if item.role == "whitelist"]
            else:
                items = [
                    item for item in items
                    if item.role == "target" and editor_category(item) == self._category
                ]
        if self._search:
            items = [
                item for item in items
                if self._search in item.alias.casefold()
                or self._search in item.identifier.casefold()
                or self._search in editor_category_label(editor_category(item)).casefold()
            ]
        return items

    def _reload_table(self, *, select_id: str | None = None) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        for target in self._filtered_targets():
            role = "whitelist" if target.role == "whitelist" else "target"
            table.add_row(
                target.alias,
                role,
                editor_category_label(editor_category(target)),
                key=target.id,
            )
        self._suppress_row_highlight = True
        try:
            if table.row_count:
                row = 0
                if select_id is not None:
                    try:
                        row = table.get_row_index(select_id)
                    except Exception:
                        pass
                table.move_cursor(row=row)
                if self._draft is not None:
                    self._load_draft(self._draft)
                elif select_id is not None:
                    target = self.app.target_store.get(select_id)
                    if target is not None:
                        self._load_target(target)
                else:
                    target = self.app.target_store.get(self._selected_target_id())
                    if target is not None:
                        self._load_target(target)
            elif self._draft is not None:
                self._load_draft(self._draft)
            else:
                self._clear_detail()
        finally:
            self._suppress_row_highlight = False

    def _selected_target_id(self) -> str | None:
        table = self.query_one("#targets-table", DataTable)
        if not table.row_count:
            return None
        try:
            return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None

    def _category_for_draft(self) -> str:
        if self._draft is None:
            return "ap"
        if self._draft.medium == "wifi" and self._draft.kind == "ap":
            return "ap"
        if self._draft.medium == "wifi" and self._draft.kind == "client":
            return "sta"
        radios = {
            str(item).casefold()
            for item in (self._draft.details.get("radio_types") or [])
        }
        if "classic" in radios or "br/edr" in radios:
            return "bt"
        return "ble"

    def _clear_detail(self) -> None:
        self._set_draft_presentation(False)
        self.query_one("#targets-detail-title", Label).update("Select an entry")
        self.query_one("#targets-detail-meta", Label).update("")
        self.query_one("#targets-detail-fields", Static).update("")
        self.query_one("#targets-alias", Input).value = ""
        self.query_one("#targets-detail-error", Label).update("")

    def _set_draft_presentation(self, is_draft: bool, *, manual: bool = False) -> None:
        pane = self.query_one("#targets-detail-pane")
        pane.set_class(is_draft, "draft-mode")
        pane.set_class(manual, "show-match-row")
        self.query_one("#targets-delete", Button).label = (
            "Discard" if is_draft else "Delete"
        )

    def _set_observation_summary(
        self,
        medium: str,
        kind: str,
        details: dict[str, Any],
        *,
        identifier: str,
        headline: str = "",
        draft_layout: bool = False,
    ) -> None:
        card = self.query_one("#targets-observed-card", Container)
        card.border_title = (
            "From your scan" if draft_layout else "Stored snapshot"
        )
        self.query_one("#targets-detail-fields", Static).update(
            observation_display_markup(
                medium,
                kind,
                details,
                identifier=identifier,
                headline=headline,
                layout="draft" if draft_layout else "card",
            ),
        )

    def _load_draft(self, candidate: TargetCandidate) -> None:
        self._draft = candidate
        self._draft_match_mode = candidate.match_mode
        self._draft_role = "target"
        manual = not candidate.identifier
        self._set_draft_presentation(True, manual=manual)
        self.query_one("#targets-detail-title", Label).update("New target")
        self.query_one("#targets-detail-meta", Label).update(
            (
                "SSID rule · all matching APs"
                if candidate.details.get("infrastructure")
                else observation_kind_subtitle(candidate.medium, candidate.kind)
            ),
        )
        self._set_observation_summary(
            candidate.medium,
            candidate.kind,
            candidate.details,
            identifier=candidate.identifier,
            headline=candidate.title,
            draft_layout=True,
        )
        self.query_one("#targets-alias", Input).value = ""
        self.query_one("#targets-role", Select).value = "target"
        self.query_one("#targets-match-mode", Select).value = candidate.match_mode
        medium_kind = f"{candidate.medium}:{candidate.kind}"
        self.query_one("#targets-kind", Select).value = medium_kind
        self.query_one("#targets-identifier", Input).value = candidate.identifier
        self.query_one("#targets-detail-error", Label).update("")

    def _load_target(self, target: SavedTarget) -> None:
        self._draft = None
        self._set_draft_presentation(False)
        last_lock = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(target.last_locked_at))
            if target.last_locked_at else "never"
        )
        self.query_one("#targets-detail-title", Label).update(target.alias)
        role = "Whitelist" if target.role == "whitelist" else "Target"
        self.query_one("#targets-detail-meta", Label).update(
            f"{role} · last seen in range {last_lock}"
        )
        self._set_observation_summary(
            target.medium,
            target.kind,
            target.details,
            identifier=target.identifier,
            headline=target.alias,
            draft_layout=False,
        )
        self.query_one("#targets-alias", Input).value = target.alias
        self.query_one("#targets-role", Select).value = target.role
        self.query_one("#targets-match-mode", Select).value = target.match_mode
        self.query_one("#targets-kind", Select).value = f"{target.medium}:{target.kind}"
        self.query_one("#targets-identifier", Input).value = target.identifier
        self.query_one("#targets-detail-error", Label).update("")

    @on(Button.Pressed, "#targets-close")
    def close_pressed(self) -> None:
        self.action_close_editor()

    @on(Button.Pressed, "#targets-new")
    def new_target(self) -> None:
        candidate = self._context_candidate or TargetCandidate(
            medium="wifi",
            kind="ap",
            identifier="",
            title="Manual entry",
            details={},
        )
        self._load_draft(candidate)
        self._draft_role = (
            "whitelist"
            if self._context_candidate is None and self._category == "whitelist"
            else "target"
        )
        self.query_one("#targets-role", Select).value = self._draft_role
        self.query_one("#targets-alias", Input).focus()

    @on(Button.Pressed, "#targets-save")
    def save_pressed(self) -> None:
        self._save_entry()

    @on(Button.Pressed, "#targets-delete")
    def delete_pressed(self) -> None:
        if self._draft is not None:
            self._draft = None
            self._clear_detail()
            self._reload_table()
            return
        target_id = self._selected_target_id()
        if target_id is None:
            return
        try:
            self.app.target_store.delete(target_id)
            if self.app.locked_target_id == target_id:
                self.app.locked_target_id = None
        except TargetStoreError as exc:
            self.query_one("#targets-detail-error", Label).update(str(exc))
            return
        self._reload_table()

    def _save_entry(self) -> None:
        alias = self.query_one("#targets-alias", Input).value.strip()
        if not alias:
            self.query_one("#targets-detail-error", Label).update("Alias is required")
            return
        role = str(self.query_one("#targets-role", Select).value)
        match_mode = str(self.query_one("#targets-match-mode", Select).value)
        medium_kind = str(self.query_one("#targets-kind", Select).value)
        identifier = self.query_one("#targets-identifier", Input).value.strip()
        if not identifier:
            self.query_one("#targets-detail-error", Label).update("Identifier is required")
            return
        try:
            medium, kind = medium_kind.split(":", 1)
        except ValueError:
            self.query_one("#targets-detail-error", Label).update("Invalid type")
            return
        details: dict[str, Any] = {}
        if self._draft is not None:
            details = dict(self._draft.details)
            if match_mode == "name" and kind == "ap":
                details.setdefault("ssid", identifier)
            if match_mode == "name" and kind == "device":
                details.setdefault("name", identifier)
            if match_mode == "probe":
                details.setdefault("probe_ssid", identifier)
        try:
            target = self.app.target_store.upsert(
                alias=alias,
                medium=medium,
                kind=kind,
                identifier=identifier,
                details=details,
                role=role,
                match_mode=match_mode,
            )
        except TargetStoreError as exc:
            self.query_one("#targets-detail-error", Label).update(str(exc))
            return
        self.app.clear_target_sighting(target.id)
        self._draft = None
        self._reload_table(select_id=target.id)
        self.notify(f"Saved {target.alias}", title="Targets")
        self._refresh_target_filters()
        if self._on_saved is not None:
            self._on_saved(target)

    def _refresh_target_filters(self) -> None:
        from textual.widgets import Select

        from wifit3.ui.screens.filter import FilterBar
        from wifit3.ui.screens.offline_filter import OfflineFilterBar
        from wifit3.ui.target_filter import refresh_target_select

        store = self.app.target_store
        for bar in self.app.query(FilterBar):
            bar.refresh_target_options()
        for bar in self.app.query(OfflineFilterBar):
            bar.refresh_target_options()
        for select in self.app.query("#bluetooth-filter-target"):
            if isinstance(select, Select):
                refresh_target_select(select, store)

# Re-export for preferences and legacy imports.
TargetsModal = TargetsEditorDrawer


def open_targets_editor(
    app,
    *,
    prefill: TargetCandidate | None = None,
    select_id: str | None = None,
    default_category: str = "all",
    on_saved: Callable[[SavedTarget], None] | None = None,
) -> None:
    app.push_screen(
        TargetsEditorDrawer(
            prefill=prefill,
            select_id=select_id,
            default_category=default_category,
            on_saved=on_saved,
        ),
    )
