from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from rich.markup import escape
from rich.text import Text
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
    match_candidate,
)


def _detail_lines(details: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in details.items():
        if value in (None, "", [], {}):
            continue
        label = str(key).replace("_", " ").title()
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif isinstance(value, dict):
            populated = [
                f"{sub_key}={item}"
                for sub_key, item in value.items()
                if item not in (None, "", [], {}, False)
            ]
            text = ", ".join(populated) or "-"
        else:
            text = str(value)
        lines.append(f"[dim]{escape(label)}[/dim]  {escape(text)}")
    return lines


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
        width: 86;
        max-width: 92%;
        height: 24;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 1;
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
        width: 36;
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
    #targets-detail-scroll {
        height: 1fr;
        max-height: 14;
        margin-bottom: 1;
    }
    #targets-detail-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #targets-detail-meta {
        margin-bottom: 1;
        color: $text-muted;
    }
    #targets-detail-fields {
        border: round $primary-darken-2;
        padding: 1;
        margin-bottom: 1;
    }
    #targets-alias-row {
        height: auto;
        margin-bottom: 1;
    }
    #targets-alias {
        width: 1fr;
    }
    #targets-detail-actions {
        height: auto;
        align: right middle;
    }
    #targets-detail-actions Button {
        margin-left: 1;
        min-width: 12;
    }
    #targets-list-actions {
        height: auto;
        margin-top: 1;
        align: center middle;
    }
    #targets-list-actions Button {
        margin: 0 1;
    }
    #targets-detail-error {
        color: $error;
        height: 1;
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
        self._prefill = prefill
        self._select_id = select_id
        self._category = default_category
        self._on_saved = on_saved
        self._search = ""
        self._draft: TargetCandidate | None = prefill
        self._draft_role = "target"
        self._draft_match_mode = "id"

    def compose(self) -> ComposeResult:
        with Container(id="targets-editor-content"):
            with Horizontal(id="targets-editor-body"):
                with Vertical(id="targets-list-pane"):
                    yield Label("Targets & whitelist", id="targets-list-title")
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
                        yield Button("Add manual", id="targets-add-manual", variant="primary")
                with Vertical(id="targets-detail-pane"):
                    with VerticalScroll(id="targets-detail-scroll"):
                        yield Label("Select an entry", id="targets-detail-title")
                        yield Label("", id="targets-detail-meta")
                        yield Static("", id="targets-detail-fields", markup=True)
                        with Horizontal(id="targets-alias-row"):
                            yield Input(placeholder="Alias", id="targets-alias", max_length=64)
                        with Horizontal():
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
                            yield Input(placeholder="Identifier or name", id="targets-identifier")
                    yield Label("", id="targets-detail-error")
                    with Horizontal(id="targets-detail-actions"):
                        yield Button("Save", id="targets-save", variant="primary")
                        yield Button("Delete", id="targets-delete", variant="error")
                        yield Button("Close", id="targets-close")

    def on_mount(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.add_columns("ALIAS", "ROLE", "TYPE")
        if self._prefill is not None:
            self._load_draft(self._prefill)
        self._reload_table(select_id=self._select_id)
        self.call_after_refresh(self._focus_list)

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
        target_id = self._selected_target_id()
        if target_id == "__draft__":
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
        if self._draft is not None:
            table.add_row(
                Text("New entry", style="bold cyan"),
                self._draft_role,
                editor_category_label(
                    "whitelist" if self._draft_role == "whitelist" else self._category_for_draft()
                ),
                key="__draft__",
            )
        for target in self._filtered_targets():
            role = "whitelist" if target.role == "whitelist" else "target"
            table.add_row(
                target.alias,
                role,
                editor_category_label(editor_category(target)),
                key=target.id,
            )
        if table.row_count:
            row = 0
            if select_id is not None:
                try:
                    row = table.get_row_index(select_id)
                except Exception:
                    pass
            table.move_cursor(row=row)
            if select_id and select_id != "__draft__":
                target = self.app.target_store.get(select_id)
                if target is not None:
                    self._load_target(target)
            elif self._draft is not None:
                self._load_draft(self._draft)
        else:
            if self._draft is not None:
                self._load_draft(self._draft)
            else:
                self._clear_detail()

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
        self.query_one("#targets-detail-title", Label).update("Select an entry")
        self.query_one("#targets-detail-meta", Label).update("")
        self.query_one("#targets-detail-fields", Static).update("")
        self.query_one("#targets-alias", Input).value = ""
        self.query_one("#targets-detail-error", Label).update("")

    def _load_draft(self, candidate: TargetCandidate) -> None:
        self._draft = candidate
        self._draft_match_mode = "id"
        self._draft_role = "target"
        self.query_one("#targets-detail-title", Label).update(
            f"New - {candidate.title}"
        )
        self.query_one("#targets-detail-meta", Label).update(
            f"{candidate.medium} / {candidate.kind} · match {candidate.identifier}"
        )
        self.query_one("#targets-detail-fields", Static).update(
            "\n".join(_detail_lines(candidate.details)) or "[dim]No extra fields[/dim]"
        )
        self.query_one("#targets-alias", Input).value = ""
        self.query_one("#targets-role", Select).value = "target"
        self.query_one("#targets-match-mode", Select).value = "id"
        medium_kind = f"{candidate.medium}:{candidate.kind}"
        self.query_one("#targets-kind", Select).value = medium_kind
        self.query_one("#targets-identifier", Input).value = candidate.identifier
        self.query_one("#targets-detail-error", Label).update("")

    def _load_target(self, target: SavedTarget) -> None:
        self._draft = None
        last_lock = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(target.last_locked_at))
            if target.last_locked_at else "never"
        )
        self.query_one("#targets-detail-title", Label).update(target.alias)
        self.query_one("#targets-detail-meta", Label).update(
            f"{target.medium}/{target.kind} · {target.match_mode}={target.identifier} · "
            f"{'enabled' if target.enabled else 'disabled'} · last lock {last_lock}"
        )
        self.query_one("#targets-detail-fields", Static).update(
            "\n".join(_detail_lines(target.details)) or "[dim]No stored details[/dim]"
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

    @on(Button.Pressed, "#targets-add-manual")
    def add_manual(self) -> None:
        self._draft = TargetCandidate(
            medium="wifi",
            kind="ap",
            identifier="",
            title="Manual entry",
            details={},
        )
        self._draft_role = "whitelist" if self._category == "whitelist" else "target"
        self._reload_table()
        self._load_draft(self._draft)
        self.query_one("#targets-role", Select).value = self._draft_role
        self.query_one("#targets-alias", Input).focus()

    @on(Button.Pressed, "#targets-save")
    def save_pressed(self) -> None:
        self._save_entry()

    @on(Button.Pressed, "#targets-delete")
    def delete_pressed(self) -> None:
        target_id = self._selected_target_id()
        if target_id in (None, "__draft__"):
            self._draft = None
            self._clear_detail()
            self._reload_table()
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
    existing = match_candidate(app.target_store, prefill) if prefill is not None else None
    if existing is not None:
        prefill = None
        select_id = existing.id
    app.push_screen(
        TargetsEditorDrawer(
            prefill=prefill,
            select_id=select_id,
            default_category=default_category,
            on_saved=on_saved,
        ),
    )
