from rich.text import Text
import pytest
from textual.widgets import DataTable

from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.offline import OfflineDatabaseView


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
            "marker",
            "ssid",
            "bssid",
            "channel",
            "encryption",
            "clients",
            "last_seen",
            "location",
        ]
        row = table.get_row("aps:00:11:22:33:44:55")
        assert str(row[1]) == "Zulu"
        assert str(row[2]) == "00:11:22:33:44:55"
        assert str(row[3]) == "11"
        assert str(row[4]) == "WPA2"
        assert row[-1].plain.endswith("🌐")

        assert offline._open_maps_from_table("aps:00:11:22:33:44:55")
        assert "10.0000000%2C20.0000000" in opened[0]

        ssid_key = next(key for key in table.columns if key.value == "ssid")
        event = DataTable.HeaderSelected(table, ssid_key, 1, Text("SSID"))
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
