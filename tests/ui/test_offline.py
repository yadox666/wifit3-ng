from rich.text import Text
import pytest
from textual.widgets import Button, DataTable, Input, Static
from textual.widgets.data_table import ColumnKey

from wifit3.persist.targets import TargetStore
from wifit3.ui.app import WifiteApp
from wifit3.ui.data_table_columns import (
    MAC_ADDRESS_COL_WIDTH,
    OFFLINE_TEXT_COL_WIDTH,
)
from wifit3.ui.screens.offline import OfflineDatabaseView, _OfflineDataTable


def _row_keys(table: DataTable, prefix: str) -> list[str]:
    return [
        str(row_key.value)
        for row_key in table.rows
        if str(row_key.value).startswith(prefix)
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_columns_sort_and_full_gps_map_link(monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(
        "wifit3.ui.screens.offline.webbrowser.open",
        lambda url: opened.append(url),
    )
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        offline._records["aps"] = [
            {
                "bssid": "00:11:22:33:44:55",
                "ssid": "Zulu",
                "channel": 11,
                "encryption": "WPA2",
                "capabilities": {
                    "catalog_labels": ["Flock Safety Cameras"],
                    "catalog_class": "Surveillance",
                    "catalog_attention": "Roadside camera match.",
                },
                "last_seen": 1,
                "clients": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
                "positions": [
                    {
                        "latitude": 10.0,
                        "longitude": 20.0,
                        "altitude_m": None,
                        "accuracy_m": 4.0,
                        "observed_at": 1.0,
                        "source": "gps",
                        "rssi": -30,
                    },
                    {
                        "latitude": 30.0,
                        "longitude": 40.0,
                        "altitude_m": None,
                        "accuracy_m": 8.0,
                        "observed_at": 2.0,
                        "source": "gps",
                        "rssi": -80,
                    },
                ],
            },
            {
                "bssid": "00:11:22:33:44:66",
                "ssid": "Alpha",
                "channel": 1,
                "encryption": "OPEN",
                "last_seen": 2,
                "clients": [],
                "positions": [],
            },
        ]
        offline._render_table("aps")
        table = offline.query_one("#offline-aps", DataTable)

        assert [key.value for key in table.columns] == [
            "ssid",
            "bssid",
            "channel",
            "encryption",
            "clients",
            "catalog_class",
            "catalog_family",
            "session",
            "last_seen",
            "location",
            "target",
        ]
        row = table.get_row("aps:00:11:22:33:44:55")
        assert str(row[0]) == "Zulu"
        assert str(row[1]) == "00:11:22:33:44:55"
        assert str(row[2]) == "11"
        assert str(row[3]) == "WPA2"
        assert row[5].plain == "Surveillance"
        assert "Flock Safety Cameras" in row[6].plain
        assert row[-2].plain.endswith("🌐")
        assert str(row[-1]) == "·"

        assert offline._open_maps_from_table("aps:00:11:22:33:44:55")
        assert "10.0000000%2C20.0000000" in opened[0]

        ssid_key = next(key for key in table.columns if key.value == "ssid")
        event = DataTable.HeaderSelected(table, ssid_key, 0, Text("SSID"))
        offline.on_data_table_header_selected(event)
        assert _row_keys(table, "aps:") == [
            "aps:00:11:22:33:44:66",
            "aps:00:11:22:33:44:55",
        ]
        offline.on_data_table_header_selected(event)
        assert _row_keys(table, "aps:") == [
            "aps:00:11:22:33:44:55",
            "aps:00:11:22:33:44:66",
        ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_bluetooth_splits_main_and_secondary_tables():
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        offline._records["bluetooth"] = [
            {
                "identifier": "AA:BB:CC:DD:EE:01",
                "name": "Living Room TV",
                "address_type": "public",
                "radio_types": ["BLE"],
                "manufacturer_ids": [0x0075],
                "last_seen": 2,
            },
            {
                "identifier": "41C28AFD-7223-CCD1-6681-2C4127D8F06E",
                "name": "<Unknown>",
                "address_type": "platform-opaque",
                "radio_types": ["BLE"],
                "manufacturer_ids": [],
                "last_seen": 1,
            },
        ]
        offline._active = "bluetooth"
        offline.set_class(True, "-bt-active")
        offline._render_bluetooth_tables()
        main = offline.query_one("#offline-bluetooth", DataTable)
        secondary = offline.query_one("#offline-bluetooth-secondary", DataTable)
        assert _row_keys(main, "bluetooth:") == ["bluetooth:AA:BB:CC:DD:EE:01"]
        assert _row_keys(secondary, "bluetooth-secondary:") == [
            "bluetooth-secondary:41C28AFD-7223-CCD1-6681-2C4127D8F06E",
        ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_ap_row_shows_target_group(tmp_path):
    app = WifiteApp()
    app.target_store = TargetStore(tmp_path / "targets.sqlite3")
    app.target_store.upsert(
        alias="Lab APs",
        medium="wifi",
        kind="ap",
        identifier="00:11:22:33:44:55",
        details={},
    )
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        offline._records["aps"] = [
            {
                "bssid": "00:11:22:33:44:55",
                "ssid": "Zulu",
                "channel": 1,
                "encryption": "WPA2",
                "last_seen": 1,
                "clients": [],
            },
        ]
        offline._render_table("aps")
        table = offline.query_one("#offline-aps", DataTable)
        row = table.get_row("aps:00:11:22:33:44:55")
        target_cell = row[-1]
        assert "⌖" in target_cell.plain
        assert "Lab APs" in target_cell.plain
        assert "red" in row[0].markup


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_bssid_column_shrinks_after_expand_collapse():
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        offline._records["aps"] = [
            {
                "bssid": "00:11:22:33:44:55",
                "ssid": "WideRow",
                "channel": 6,
                "encryption": "WPA2",
                "last_seen": 1,
                "clients": [],
                "capabilities": {
                    "notes": "x" * 120,
                    "nested": {"payload": "y" * 120},
                },
            },
        ]
        identity = "00:11:22:33:44:55"
        offline._detail_focus = ("aps", identity)
        offline._render_table("aps", selected_identity=identity)
        table = offline.query_one("#offline-aps", _OfflineDataTable)
        bssid_col = table.columns[ColumnKey("bssid")]
        assert not any(str(key.value).startswith("detail:") for key in table.rows)
        detail = offline.query_one("#offline-detail", Static)
        assert "capabilities.notes" in _plain(detail)
        assert bssid_col.content_width <= MAC_ADDRESS_COL_WIDTH

        ssid_col = table.columns[ColumnKey("ssid")]
        bssid_col.content_width = 80
        ssid_col.content_width = 200
        offline._detail_focus = None
        offline._render_table("aps")
        assert bssid_col.content_width <= MAC_ADDRESS_COL_WIDTH
        assert ssid_col.content_width <= OFFLINE_TEXT_COL_WIDTH


def _plain(widget: Static) -> str:
    rendered = widget.render()
    return rendered.plain if hasattr(rendered, "plain") else str(rendered)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_clear_search_button_clears_filter_text():
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        offline.query_one("#offline-filter-text", Input).value = "zulu"
        await pilot.pause(0)
        offline.query_one("#clear-offline-filter-text", Button).press()
        await pilot.pause(0.2)
        assert offline.query_one("#offline-filter-text", Input).value == ""
        assert offline._filters.text == ""


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_offline_filter_focus_keeps_catalog_footer_shortcut():
    app = WifiteApp()
    async with app.run_test() as pilot:
        pilot.app.screen.action_offline()
        await pilot.pause(0)
        offline = pilot.app.screen
        assert isinstance(offline, OfflineDatabaseView)
        baseline = {
            binding.description
            for _, binding, _, _ in offline.active_bindings.values()
            if binding.show
        }
        assert "Catalog" in baseline
        offline.query_one("#offline-filter-text", Input).focus()
        await pilot.pause(0)
        focused = {
            binding.description
            for _, binding, _, _ in offline.active_bindings.values()
            if binding.show
        }
        assert "Catalog" in focused
