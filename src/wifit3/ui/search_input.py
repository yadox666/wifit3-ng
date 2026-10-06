"""Search boxes that darken when they contain text."""
from __future__ import annotations

from textual.widgets import Input

_HAS_TEXT_CLASS = "-has-text"


class SearchInput(Input):
    """Filter/search field with a darker background while non-empty."""

    DEFAULT_CSS = f"""
    SearchInput.-has-text {{
        background: $surface-darken-2;
    }}
    """

    def on_mount(self) -> None:
        sync_search_input_has_text(self)

    def watch_value(self, value: str) -> None:
        sync_search_input_has_text(self, value)


def sync_search_input_has_text(field: Input, value: str | None = None) -> None:
    text = value if value is not None else field.value
    if text:
        field.add_class(_HAS_TEXT_CLASS)
    else:
        field.remove_class(_HAS_TEXT_CLASS)
