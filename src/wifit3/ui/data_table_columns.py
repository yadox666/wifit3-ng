"""Fixed-width DataTable columns that must shrink after row removal."""
from __future__ import annotations

from rich.protocol import is_renderable
from textual.render import measure
from textual.widgets import DataTable
from textual.widgets.data_table import ColumnKey

MAC_ADDRESS_COL_WIDTH: int = 17
OFFLINE_TEXT_COL_WIDTH: int = 32
OFFLINE_CLASS_COL_WIDTH: int = 16
OFFLINE_SESSION_COL_WIDTH: int = 18
OFFLINE_TARGET_COL_WIDTH: int = 28


def offline_column_caps() -> dict[str, dict[str, int]]:
    mac = MAC_ADDRESS_COL_WIDTH
    text = OFFLINE_TEXT_COL_WIDTH
    target = OFFLINE_TARGET_COL_WIDTH
    return {
        "aps": {
            "target": target,
            "ssid": text,
            "bssid": mac,
            "catalog_class": OFFLINE_CLASS_COL_WIDTH,
            "catalog_family": text,
            "session": OFFLINE_SESSION_COL_WIDTH,
        },
        "clients": {
            "target": target,
            "client_mac": mac,
            "last_ssid": text,
            "last_bssid": mac,
            "session": OFFLINE_SESSION_COL_WIDTH,
        },
        "bluetooth": {
            "target": target,
            "name": text,
            "model": 14,
            "catalog_class": OFFLINE_CLASS_COL_WIDTH,
            "catalog_family": text,
            "radio": 8,
            "device_type": text,
            "manufacturer": text,
            "services": text,
            "protocol": OFFLINE_CLASS_COL_WIDTH,
            "address": mac,
            "address_kind": 12,
            "location": text,
        },
    }


def _detail_row_key(row_key: str) -> bool:
    return row_key.startswith("detail:")


def reclamp_column(
    table: DataTable,
    key: str,
    cap: int,
    *,
    main_rows_only: bool = False,
) -> None:
    """Set a column width from visible cells, never wider than ``cap``."""
    column_key = ColumnKey(key)
    column = table.columns.get(column_key)
    if column is None:
        return
    console = table.app.console
    label_width = measure(console, column.label, 1)
    widths = [label_width]
    if main_rows_only:
        for row_key in table.rows:
            key_str = str(row_key.value)
            if _detail_row_key(key_str):
                continue
            try:
                cell = table.get_cell(key_str, key)
            except Exception:
                continue
            renderable = cell if is_renderable(cell) else str(cell)
            widths.append(measure(console, renderable, 1))
    else:
        for cell in table.get_column(column_key):
            renderable = cell if is_renderable(cell) else str(cell)
            widths.append(measure(console, renderable, 1))
    column.content_width = min(cap, max(widths))


def reclamp_columns(
    table: DataTable,
    caps: dict[str, int],
    *,
    main_rows_only: bool = False,
) -> None:
    for key, cap in caps.items():
        reclamp_column(table, key, cap, main_rows_only=main_rows_only)


def reclamp_offline_table(table: DataTable, kind: str) -> None:
    """Re-measure offline DB columns from collapsed (main) rows only."""
    reclamp_columns(
        table,
        offline_column_caps().get(kind, {}),
        main_rows_only=True,
    )
