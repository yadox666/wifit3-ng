"""Editable product-catalog family form (clues use the same rule language as matching)."""
from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, Input, Label, Select, Static

from wifit3.observe.product_catalog import (
    NAME_REGEX_WORKED_EXAMPLES,
    RADIO_CHOICES,
    RULE_KIND_CHOICES,
    build_rule_dict,
    catalog_family_record,
    delete_catalog_family,
    name_regex_reference_lines,
    name_regex_syntax_error,
    name_regex_try_worked_examples,
    save_catalog_family,
    suggest_family_id,
)


class CatalogEditPanel(Vertical):
    """Right-hand editor for one catalog family (scroll via #catalog-detail-scroll)."""

    DEFAULT_CSS = """
    CatalogEditPanel {
        height: auto;
        width: 100%;
    }
    CatalogEditPanel #catalog-clue-rows {
        height: auto;
        width: 100%;
        min-height: 1;
    }
    CatalogEditPanel .catalog-edit-label {
        color: $text-muted;
        height: 1;
        margin-top: 1;
    }
    CatalogEditPanel .catalog-edit-label-first {
        margin-top: 0;
    }
    CatalogEditPanel Input {
        width: 1fr;
        margin-bottom: 1;
    }
    CatalogEditPanel #catalog-edit-id {
        width: 1fr;
    }
    CatalogEditPanel .catalog-clue-row {
        height: auto;
        width: 100%;
        margin-bottom: 1;
        border-bottom: solid $primary-darken-2;
        padding-bottom: 1;
    }
    CatalogEditPanel .catalog-clue-head {
        height: auto;
        width: 100%;
        margin-bottom: 0;
    }
    CatalogEditPanel .catalog-clue-kind {
        width: 1fr;
    }
    CatalogEditPanel .catalog-clue-text {
        width: 100%;
        margin-bottom: 0;
    }
    CatalogEditPanel .catalog-clue-extra {
        height: auto;
        width: 100%;
    }
    CatalogEditPanel .catalog-clue-company {
        width: 1fr;
        margin-right: 1;
    }
    CatalogEditPanel .catalog-clue-prefix {
        width: 1fr;
        margin-right: 1;
    }
    CatalogEditPanel .catalog-clue-radio {
        width: 1fr;
    }
    CatalogEditPanel .catalog-clue-remove {
        width: 3;
        min-width: 3;
        max-width: 3;
        border: none;
        padding: 0;
        margin: 0;
        background: transparent;
        color: $text-muted;
    }
    CatalogEditPanel #catalog-edit-toolbar {
        height: auto;
        margin-top: 1;
        align: left middle;
    }
    CatalogEditPanel #catalog-edit-toolbar Button {
        margin-right: 1;
    }
    CatalogEditPanel #catalog-edit-status {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }
    CatalogEditPanel #catalog-regex-cheatsheet {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }
    CatalogEditPanel .catalog-clue-regex-hint {
        height: auto;
        color: $text-muted;
        margin-bottom: 0;
        display: none;
    }
    CatalogEditPanel .catalog-clue-row.-regex-kind .catalog-clue-regex-hint {
        display: block;
    }
    CatalogEditPanel .catalog-clue-regex-status {
        height: auto;
        margin-bottom: 0;
        display: none;
    }
    CatalogEditPanel .catalog-clue-row.-regex-kind .catalog-clue-regex-status {
        display: block;
    }
    CatalogEditPanel .catalog-clue-regex-status.-invalid {
        color: $error;
    }
    CatalogEditPanel .catalog-clue-regex-status.-valid {
        color: $success;
    }
    """

    class Changed(Message):
        pass

    class Saved(Message):
        def __init__(self, family_id: str) -> None:
            super().__init__()
            self.family_id = family_id

    class Deleted(Message):
        pass

    def __init__(self) -> None:
        super().__init__()
        self._family_id: str | None = None
        self._new_family = False

    def compose(self) -> ComposeResult:
        yield Static("", id="catalog-edit-status")
        yield Label("Family id", classes="catalog-edit-label catalog-edit-label-first")
        yield Input(placeholder="unique-id", compact=True, id="catalog-edit-id")
        yield Label("Label", classes="catalog-edit-label")
        yield Input(placeholder="Display name", compact=True, id="catalog-edit-label")
        yield Label("Class", classes="catalog-edit-label")
        yield Input(placeholder="Finder, Phone, Surveillance…", compact=True, id="catalog-edit-class")
        yield Label("Notes", classes="catalog-edit-label")
        yield Input(placeholder="What this family means", compact=True, id="catalog-edit-notes")
        yield Label("Attention", classes="catalog-edit-label")
        yield Input(placeholder="Optional highlight line", compact=True, id="catalog-edit-attention")
        yield Label("Clues (any one matches)", classes="catalog-edit-label")
        ex1, ex2 = name_regex_reference_lines()
        yield Static(
            f"Name regex matches the whole SSID (^…$). Examples: {ex1} · {ex2}",
            id="catalog-regex-cheatsheet",
        )
        yield Vertical(id="catalog-clue-rows")
        with Horizontal(id="catalog-edit-toolbar"):
            yield Button("Add clue", id="catalog-add-clue", compact=True)
            yield Button("Save", variant="primary", id="catalog-save", compact=True)
            yield Button("Delete family", id="catalog-delete", compact=True)
            yield Button("Cancel", id="catalog-cancel", compact=True)

    def begin_new(self) -> None:
        self._family_id = None
        self._new_family = True
        self.query_one("#catalog-edit-id", Input).value = ""
        self.query_one("#catalog-edit-id", Input).disabled = False
        self.query_one("#catalog-edit-label", Input).value = ""
        self.query_one("#catalog-edit-class", Input).value = ""
        self.query_one("#catalog-edit-notes", Input).value = ""
        self.query_one("#catalog-edit-attention", Input).value = ""
        self._set_clues([("name_contains", "", "", "", "")])
        self._set_status("New family - add clues, then Save.")

    def load_family(self, family_id: str) -> None:
        record = catalog_family_record(family_id)
        if record is None:
            return
        self._family_id = family_id
        self._new_family = False
        id_input = self.query_one("#catalog-edit-id", Input)
        id_input.value = record["id"]
        id_input.disabled = not record["user_owned"]
        self.query_one("#catalog-edit-label", Input).value = record["label"]
        self.query_one("#catalog-edit-class", Input).value = record["class"]
        self.query_one("#catalog-edit-notes", Input).value = record["notes"]
        self.query_one("#catalog-edit-attention", Input).value = record["attention"]
        clues = [
            (
                str(rule.get("kind") or "name_contains"),
                str(rule.get("text") or ""),
                _company_text(rule.get("company_id")),
                str(rule.get("prefix") or rule.get("flags") or ""),
                str(rule.get("radio") or ""),
            )
            for rule in record["rules"]
        ]
        self._set_clues(clues)
        if record["user_owned"]:
            self._set_status("User family - editable.")
        elif record["stock"]:
            self._set_status(
                "Stock family - Save writes your override; Delete hides the stock row.",
            )
        else:
            self._set_status("Editable catalog family.")

    def _set_status(self, text: str) -> None:
        self.query_one("#catalog-edit-status", Static).update(text)

    def _set_clues(self, rows: list[tuple[str, str, str, str, str]]) -> None:
        container = self.query_one("#catalog-clue-rows", Vertical)
        container.remove_children()
        for index, row in enumerate(rows):
            container.mount(_ClueRow(index, row))
        if not rows:
            container.mount(_ClueRow(0, ("name_contains", "", "", "", "")))

    @on(Input.Changed)
    def _field_changed(self, _event: Input.Changed) -> None:
        self.post_message(self.Changed())

    @on(Select.Changed)
    def _select_changed(self, _event: Select.Changed) -> None:
        self.post_message(self.Changed())

    @on(Button.Pressed, "#catalog-add-clue")
    def _add_clue(self) -> None:
        container = self.query_one("#catalog-clue-rows", Vertical)
        index = len(container.children)
        row = _ClueRow(index, ("name_contains", "", "", "", ""))
        container.mount(row)
        self._scroll_detail_panel()

        def _focus_new_clue() -> None:
            try:
                row.query_one(".catalog-clue-text", Input).focus()
            except Exception:
                pass

        self.call_after_refresh(_focus_new_clue)

    def _scroll_detail_panel(self) -> None:
        parent = self.parent
        if isinstance(parent, VerticalScroll):
            parent.scroll_end(animate=False)

    @on(Button.Pressed, "#catalog-save")
    def _save(self) -> None:
        label = self.query_one("#catalog-edit-label", Input).value.strip()
        family_id = self.query_one("#catalog-edit-id", Input).value.strip()
        if self._new_family and not family_id:
            family_id = suggest_family_id(label or "family")
            self.query_one("#catalog-edit-id", Input).value = family_id
        rules = []
        for row in self.query(_ClueRow):
            message = row.validate()
            if message:
                self._set_status(message)
                self.notify(message, severity="warning")
                return
            rule = row.to_rule_dict()
            if rule is not None:
                rules.append(rule)
        record = {
            "id": family_id,
            "label": label,
            "class": self.query_one("#catalog-edit-class", Input).value.strip(),
            "notes": self.query_one("#catalog-edit-notes", Input).value.strip(),
            "attention": self.query_one("#catalog-edit-attention", Input).value.strip(),
            "rules": rules,
        }
        ok, message = save_catalog_family(record)
        if not ok:
            self._set_status(message)
            self.notify(message, severity="warning")
            return
        self._family_id = family_id
        self._new_family = False
        self.query_one("#catalog-edit-id", Input).disabled = True
        self._set_status(message)
        self.notify(message, title="Catalog")
        self.post_message(self.Saved(family_id))

    @on(Button.Pressed, "#catalog-delete")
    def _delete(self) -> None:
        family_id = self.query_one("#catalog-edit-id", Input).value.strip()
        if not family_id:
            return
        ok, message = delete_catalog_family(family_id)
        if not ok:
            self._set_status(message)
            self.notify(message, severity="warning")
            return
        self.notify(message, title="Catalog")
        self.post_message(self.Deleted())

    @on(Button.Pressed, "#catalog-cancel")
    def _cancel(self) -> None:
        self.post_message(self.Deleted())


class _ClueRow(Vertical):
    """One clue block: kind, value fields, radio scope, remove."""

    DEFAULT_CSS = """
    _ClueRow {
        height: auto;
        width: 100%;
    }
    """

    _REGEX_HINT = (
        "Pattern must match the full name (use ^ and $). "
        "Flags: s = case-sensitive; default ignores case."
    )

    def __init__(self, index: int, row: tuple[str, str, str, str, str]) -> None:
        super().__init__(classes="catalog-clue-row")
        self._index = index
        self._row = row

    def compose(self) -> ComposeResult:
        kind, text, company, prefix, radio = self._row
        with Horizontal(classes="catalog-clue-head"):
            yield Select(
                list(RULE_KIND_CHOICES),
                value=kind,
                allow_blank=False,
                compact=True,
                classes="catalog-clue-kind",
            )
            yield Button("×", classes="catalog-clue-remove", compact=True)
        yield Input(
            text,
            placeholder="text / OUI / UUID",
            compact=True,
            classes="catalog-clue-text",
        )
        yield Static(self._REGEX_HINT, classes="catalog-clue-regex-hint")
        yield Static("", classes="catalog-clue-regex-status")
        with Horizontal(classes="catalog-clue-extra"):
            yield Input(
                company,
                placeholder="company 0x…",
                compact=True,
                classes="catalog-clue-company",
            )
            yield Input(
                prefix,
                placeholder="hex prefix / regex flags (i,s,m)",
                compact=True,
                classes="catalog-clue-prefix",
            )
            yield Select(
                list(RADIO_CHOICES),
                value=radio,
                allow_blank=False,
                compact=True,
                classes="catalog-clue-radio",
            )

    def on_mount(self) -> None:
        self._sync_regex_kind()
        self._refresh_regex_status()

    def _sync_regex_kind(self) -> None:
        kind = str(self.query_one(".catalog-clue-kind", Select).value or "")
        is_regex = kind == "name_regex"
        self.set_class(is_regex, "-regex-kind")
        text_input = self.query_one(".catalog-clue-text", Input)
        if kind == "manufacturer":
            text_input.placeholder = "BSSID OUI (94:BA:06) or vendor name (Sagemcom)"
        elif is_regex:
            text_input.placeholder = "Python regex - full SSID/name match (^…$)"
        else:
            text_input.placeholder = "text / OUI / UUID"

    def _refresh_regex_status(self) -> None:
        status = self.query_one(".catalog-clue-regex-status", Static)
        kind = str(self.query_one(".catalog-clue-kind", Select).value or "")
        if kind != "name_regex":
            status.update("")
            status.set_class(False, "-invalid")
            status.set_class(False, "-valid")
            return
        pattern = self.query_one(".catalog-clue-text", Input).value
        flags = self.query_one(".catalog-clue-prefix", Input).value
        err = name_regex_syntax_error(pattern, flags)
        if err:
            status.update(f"Syntax error: {err}")
            status.set_class(True, "-invalid")
            status.set_class(False, "-valid")
            return
        if not pattern.strip():
            status.update("Enter a regex pattern")
            status.set_class(False, "-invalid")
            status.set_class(False, "-valid")
            return
        match_a, match_b = name_regex_try_worked_examples(pattern, flags)
        sample_a = NAME_REGEX_WORKED_EXAMPLES[0]["sample"]
        sample_b = NAME_REGEX_WORKED_EXAMPLES[1]["sample"]
        status.update(
            "Syntax OK · "
            f"{sample_a}: {'matches' if match_a else 'no match'} · "
            f"{sample_b}: {'matches' if match_b else 'no match'}",
        )
        status.set_class(False, "-invalid")
        status.set_class(True, "-valid")

    def validate(self) -> str | None:
        kind = str(self.query_one(".catalog-clue-kind", Select).value or "")
        if kind != "name_regex":
            return None
        pattern = self.query_one(".catalog-clue-text", Input).value
        flags = self.query_one(".catalog-clue-prefix", Input).value
        if not pattern.strip():
            return "Name regex clue needs a pattern"
        err = name_regex_syntax_error(pattern, flags)
        if err:
            return f"Invalid regex: {err}"
        return None

    @on(Select.Changed)
    def _row_select_changed(self, event: Select.Changed) -> None:
        if event.select.has_class("catalog-clue-kind"):
            self._sync_regex_kind()
        self._refresh_regex_status()

    @on(Input.Changed)
    def _row_input_changed(self, event: Input.Changed) -> None:
        if event.input.has_class("catalog-clue-text") or event.input.has_class(
            "catalog-clue-prefix",
        ):
            self._refresh_regex_status()

    def to_rule_dict(self) -> dict | None:
        kind = str(self.query_one(".catalog-clue-kind", Select).value or "")
        text = self.query_one(".catalog-clue-text", Input).value
        company = self.query_one(".catalog-clue-company", Input).value
        prefix = self.query_one(".catalog-clue-prefix", Input).value
        radio = str(self.query_one(".catalog-clue-radio", Select).value or "")
        return build_rule_dict(
            kind,
            text,
            company_id=company,
            prefix=prefix,
            radio=radio,
        )

    @on(Button.Pressed, ".catalog-clue-remove")
    def _remove(self, event: Button.Pressed) -> None:
        if event.button in self.query(".catalog-clue-remove"):
            self.remove()


def _company_text(value: object) -> str:
    if not isinstance(value, int):
        return ""
    return f"0x{value:04X}"
