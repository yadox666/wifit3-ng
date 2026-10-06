"""Scan-table markers for saved targets and whitelist entries."""

from __future__ import annotations

from rich.text import Text


def target_row_prefix() -> Text:
    return Text("⌖ ", style="bold red")


def whitelist_row_prefix() -> Text:
    return Text("◇ ", style="bold green")


def plain_row_prefix() -> Text:
    """Placeholder so SSID text lines up with target/whitelist rows (``⌖ `` / ``◇ ``)."""
    return Text("  ")


def target_group_cell(target) -> Text:
    """Target column: icon + saved group alias (offline DB, exports)."""
    from wifit3.targeting import is_target_entry, is_whitelisted_entry

    if target is None or not getattr(target, "enabled", True):
        return Text("·", style="dim")
    if is_whitelisted_entry(target):
        cell = whitelist_row_prefix()
        cell.append(target.alias, style="bold green")
        return cell
    if is_target_entry(target):
        cell = target_row_prefix()
        cell.append(target.alias, style="bold red")
        return cell
    return Text("·", style="dim")
