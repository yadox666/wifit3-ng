"""Scan-table markers for saved targets and whitelist entries."""

from __future__ import annotations

from rich.text import Text


def target_row_prefix() -> Text:
    return Text("⌖ ", style="bold cyan")


def whitelist_row_prefix() -> Text:
    return Text("◇ ", style="bold green")
