import time
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from rich.text import Text
from textual.widgets import Checkbox, DataTable, Input, Select
from textual.widgets.data_table import ColumnKey

from wifit3.models import BluetoothDevice, SignalPosition
from wifit3.bluetooth.connection import BluetoothConnectionError
from wifit3.bluetooth.manager import OsBleSourceStatus
from wifit3.bluetooth.usb_hci import UsbBluetoothController
from wifit3.persist.config import Config
from wifit3.persist.targets import TargetStore
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.bluetooth_scanner import (
    _BluetoothSortReadout,
    BluetoothScannerView,
    _connection_error_message,
    _device_has_expired,
    _group_anonymous_apple_devices,
)
from wifit3.ui.screens.splash import SplashView


def _anonymous_apple(identifier: str, *, rssi: int = -70) -> BluetoothDevice:
    now = time.time()
    return BluetoothDevice(
        identifier=identifier,
        name="<Unknown>",
        rssi=rssi,
        service_uuids=("180f",),
        service_data_uuids=(),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=8,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=3,
        advertisement_interval=0.2,
        first_seen=now - 5,
        last_seen=now,
    )


def test_timeout_error_has_actionable_ble_message():
    try:
        raise BluetoothConnectionError("TimeoutError") from TimeoutError()
    except BluetoothConnectionError as exc:
        assert _connection_error_message(exc) == (
            "BLE GATT connection timed out. The device may currently accept "
            "Bluetooth Classic only."
        )


def test_bluetooth_expiry_uses_shared_scanner_preference(monkeypatch):
    monkeypatch.setattr(Config, "scanner_ap_expiry", 120.0)
    assert _device_has_expired(119.9) is False
    assert _device_has_expired(120.0) is True

    monkeypatch.setattr(Config, "scanner_ap_expiry", -1.0)
    assert _device_has_expired(100_000.0) is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_can_start_bluetooth_without_wifi_device(monkeypatch):
    app = WifiteApp()
    app.bluetooth_manager.start = AsyncMock()
    switched = []
    monkeypatch.setattr(app, "switch_screen", switched.append)

    async with app.run_test() as pilot:
        splash = app.screen
        assert isinstance(splash, SplashView)
        assert not splash.query_one("#bluetooth-btn").disabled

        splash.action_start_bluetooth()
        for _ in range(40):
            await pilot.pause(0)
            if switched:
                break

        app.bluetooth_manager.start.assert_awaited_once()
        assert switched == ["bluetooth"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_shows_and_can_disable_os_ble_source():
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        panel = splash.query_one("#os-ble-picker")

        assert panel.border_title == "Operating-system BLE"
        assert "Test vendor TestBleak" in panel.query_one(".os-ble-name").render().plain
        assert panel.query_one(".os-ble-state").render().plain == "OS-READY"
        assert not splash.query_one("#bluetooth-btn").disabled

        splash.query_one("#os-ble-enabled", Checkbox).value = False
        await pilot.pause(0)

        assert app.bluetooth_manager.os_ble_enabled is False
        assert Config.os_ble_enabled is False
        assert panel.query_one(".os-ble-state").render().plain == "APP-DISABLED"
        assert splash.query_one("#bluetooth-btn").disabled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_marks_unavailable_os_ble_layer_in_red():
    app = WifiteApp()
    status = OsBleSourceStatus(
        True,
        False,
        "OS-DISABLED",
        "CoreBluetooth",
        "macOS",
        "Apple",
        "System adapter",
        "Bluetooth is turned off",
    )

    async def unavailable():
        app.bluetooth_manager.os_ble_status = status
        return status

    app.bluetooth_manager.probe_os_ble = unavailable
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        state = app.screen.query_one(".os-ble-state").render()

        assert state.plain == "OS-DISABLED"
        assert any("red" in str(span.style) for span in state.spans)
        assert app.screen.query_one("#bluetooth-btn").disabled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_primary_buttons_share_a_centered_row():
    app = WifiteApp()
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.pause(0)
        wifi = app.screen.query_one("#start-btn").region
        bluetooth = app.screen.query_one("#bluetooth-btn").region
        offline = app.screen.query_one("#offline-btn").region
        assert wifi.y == bluetooth.y == offline.y
        assert bluetooth.x >= wifi.right + 2
        assert offline.x >= bluetooth.right + 2
        assert abs((wifi.x + offline.right) - 100) <= 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_wifi_and_bluetooth_buttons_have_hotkeys():
    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        wifi = splash.query_one("#start-btn")
        bluetooth = splash.query_one("#bluetooth-btn")
        offline = splash.query_one("#offline-btn")
        assert wifi.label.plain == "START WI-FI"
        assert bluetooth.label.plain == "SCAN BLE"
        assert offline.label.plain == "OFFLINE DB"
        assert any("yellow" in str(span.style) for span in wifi.label.spans)
        assert any("yellow" in str(span.style) for span in bluetooth.label.spans)
        assert any("yellow" in str(span.style) for span in offline.label.spans)

        called = []
        splash.action_start = lambda: called.append("wifi")
        splash.action_start_bluetooth = lambda: called.append("bluetooth")
        splash.action_offline = lambda: called.append("offline")
        await pilot.press("w", "b", "o")
        assert called == ["wifi", "bluetooth", "offline"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_shows_separate_dual_mode_button_when_controller_is_detected(monkeypatch):
    app = WifiteApp()
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    app.bluetooth_manager.available_usb_controllers = lambda: [controller]
    app.bluetooth_manager.start_usb = AsyncMock()
    switched = []
    monkeypatch.setattr(app, "switch_screen", switched.append)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        button = splash.query_one("#bluetooth-usb-btn")
        picker = splash.query_one("#bluetooth-picker")
        assert button.display
        assert button.label.plain == "BT/BLE Scan"
        assert picker.display
        assert picker.region.height == 3
        assert picker.selected_controllers() == [controller]

        splash.action_start_usb_bluetooth()
        for _ in range(40):
            await pilot.pause(0)
            if switched:
                break

        app.bluetooth_manager.start_usb.assert_awaited_once_with(controller)
        assert switched == ["bluetooth"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecked_bluetooth_adapter_is_not_started():
    app = WifiteApp()
    first = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    second = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 3,
        supports_le=False,
    )
    app.bluetooth_manager.available_usb_controllers = lambda: [first, second]
    app.bluetooth_manager.start_usb = AsyncMock()

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        assert picker.region.height == 4
        assert [str(mode.content) for mode in picker.query(".bt-mode")] == ["BT+BLE", "BT"]

        splash.query_one("#bt-chk-0", Checkbox).value = False
        await pilot.pause(0)
        button = splash.query_one("#bluetooth-usb-btn")
        assert not button.disabled
        splash.action_start_usb_bluetooth()
        for _ in range(20):
            await pilot.pause(0)
            if app.bluetooth_manager.start_usb.await_count:
                break
        app.bluetooth_manager.start_usb.assert_awaited_once_with(second)

        splash.query_one("#bt-chk-1", Checkbox).value = False
        await pilot.pause(0)
        assert button.disabled
        app.bluetooth_manager.start_usb.reset_mock()
        splash.action_start_usb_bluetooth()
        await pilot.pause(0)
        app.bluetooth_manager.start_usb.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_picker_rebuilds_rows():
    app = WifiteApp()
    first = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    second = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 3,
        supports_le=False,
    )
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        picker.set_controllers([first, second])
        await pilot.pause()
        picker.set_controllers([second])
        await pilot.pause()
        assert len(list(picker.query(".bt-row"))) == 1
        assert splash.query_one("#bt-chk-0", Checkbox).value is True
        assert str(picker.query_one(".bt-name").content) == second.label


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_scanner_renders_discovered_device():
    app = WifiteApp()
    now = time.time()
    device = BluetoothDevice(
        identifier="AA:BB:CC:DD:EE:FF",
        name="Test Beacon",
        rssi=-42,
        service_uuids=("0000180f-0000-1000-8000-00805f9b34fb",),
        service_data_uuids=("0000180f-0000-1000-8000-00805f9b34fb",),
        manufacturer_ids=(0x004C,),
        manufacturer_data_bytes=8,
        service_data_bytes=1,
        tx_power=-8,
        advertisement_count=12,
        advertisement_interval=0.25,
        first_seen=now,
        last_seen=now,
        positions=[
            SignalPosition(51.503, -0.144, None, 5.0, now, "gps", -42),
        ],
    )
    app.bluetooth_manager.devices = lambda: [device]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        assert isinstance(scanner, BluetoothScannerView)
        assert app.check_action("toggle_vault", ()) is False
        app.action_toggle_vault()
        assert app.screen is scanner

        scanner.refresh_table()
        table = scanner.query_one("#bluetooth-table", DataTable)
        expected_widths = scanner._COLUMN_WIDTHS
        assert {
            key: table.columns[ColumnKey(key)].width for key in expected_widths
        } == expected_widths
        row = table.get_row("AA:BB:CC:DD:EE:FF")
        assert row[0].plain == "Test Beacon"
        assert row[1].plain == "-42 dBm"
        assert row[2].plain == "BLE Beacon"
        assert row[3].plain == "12"
        assert row[4].plain == "250 ms"
        assert row[5].plain == "now"
        assert row[6].plain == "now"
        assert row[7].plain == "Apple, Inc. (004C)"
        assert row[8].plain == "Battery Service"
        assert row[9].plain == "AA:BB:CC:DD:EE:FF"
        assert row[10].plain == "51.50300, -0.14400 ±5m"

        device = replace(
            device,
            advertisement_count=123_456,
            advertisement_interval=123.456,
            service_uuids=(
                "0000180f-0000-1000-8000-00805f9b34fb",
                "0000180a-0000-1000-8000-00805f9b34fb",
                "0000180d-0000-1000-8000-00805f9b34fb",
            ),
        )
        scanner.refresh_table()
        assert {
            key: table.columns[ColumnKey(key)].width for key in expected_widths
        } == expected_widths


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_saved_target_row_is_red_and_marked(tmp_path):
    app = WifiteApp()
    device = replace(_anonymous_apple("AA:BB:CC:DD:EE:FF"), name="Watch")
    app.bluetooth_manager.devices = lambda: [device]
    app.target_store = TargetStore(tmp_path / "targets.json")
    app.target_store.upsert(
        alias="Watch",
        medium="bluetooth",
        kind="device",
        identifier=device.identifier,
        details={},
    )

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        name = scanner.query_one("#bluetooth-table", DataTable).get_row(
            device.identifier,
        )[0]
        assert name.plain.startswith("⌖ ")
        assert any("red" in str(span.style) for span in name.spans)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_scanner_cycles_sort_column_and_direction():
    app = WifiteApp()
    now = time.time()
    weak = replace(
        _anonymous_apple("11:11:11:11:11:11", rssi=-80),
        name="Weak Sensor",
        advertisement_count=30,
        first_seen=now - 20,
    )
    strong = replace(
        _anonymous_apple("22:22:22:22:22:22", rssi=-40),
        name="Strong Sensor",
        advertisement_count=10,
        first_seen=now - 5,
    )
    app.bluetooth_manager.devices = lambda: [weak, strong]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()

        assert table.columns[ColumnKey("first_seen")].label.plain == "▼ FIRST SEEN"
        assert table.get_row_at(0)[0].plain == "Weak Sensor"

        while table.columns[ColumnKey("rssi")].label.plain == "  POWER":
            scanner.action_cycle_sort()
        assert table.columns[ColumnKey("rssi")].label.plain == "▼ POWER"
        assert table.get_row_at(0)[0].plain == "Strong Sensor"

        scanner.action_toggle_sort_dir()
        assert table.columns[ColumnKey("rssi")].label.plain == "▲ POWER"
        assert table.get_row_at(0)[0].plain == "Weak Sensor"

        while table.columns[ColumnKey("advertisements")].label.plain == "  OBS":
            scanner.action_cycle_sort()
        assert table.columns[ColumnKey("advertisements")].label.plain == "▲ OBS"
        assert table.get_row_at(0)[0].plain == "Strong Sensor"

        scanner.action_toggle_sort_dir()
        assert table.columns[ColumnKey("advertisements")].label.plain == "▼ OBS"
        assert table.get_row_at(0)[0].plain == "Weak Sensor"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_sort_change_shows_toast_and_header_status():
    app = WifiteApp()

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        toasts = []
        scanner.notify = lambda message, **kwargs: toasts.append(
            (kwargs.get("title"), message)
        )
        readout = scanner.query_one(_BluetoothSortReadout)

        assert readout.summary == "Sorted: FIRST SEEN (>)"
        scanner.action_cycle_sort()
        assert readout.summary == "Sorted: LAST SEEN (>)"
        assert toasts[-1] == ("Sort changed", "Sorted by LAST SEEN descending")

        scanner.action_toggle_sort_dir()
        assert readout.summary == "Sorted: LAST SEEN (<)"
        assert toasts[-1] == ("Sort changed", "Sorted by LAST SEEN ascending")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_scanner_filters_by_power_type_and_text():
    app = WifiteApp()
    audio = replace(
        _anonymous_apple("11:11:11:11:11:11", rssi=-45),
        name="Office Headphones",
    )
    sensor = replace(
        _anonymous_apple("22:22:22:22:22:22", rssi=-75),
        name="Temperature Sensor",
        manufacturer_ids=(0x0499,),
    )
    app.bluetooth_manager.devices = lambda: [audio, sensor]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()
        assert table.row_count == 2

        scanner.query_one("#bluetooth-filter-type", Select).value = "Audio"
        await pilot.pause()
        assert table.row_count == 1
        assert table.get_row_at(0)[0].plain == "Office Headphones"

        scanner.query_one("#bluetooth-filter-type", Select).value = "All"
        scanner.query_one("#bluetooth-filter-power", Select).value = -70
        await pilot.pause()
        assert table.row_count == 1

        scanner.query_one("#bluetooth-filter-power", Select).value = -100
        scanner.query_one("#bluetooth-filter-text", Input).value = "temperature"
        await pilot.pause()
        assert table.row_count == 1
        assert table.get_row_at(0)[0].plain == "Temperature Sensor"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_default_sort_keeps_new_devices_at_the_bottom():
    app = WifiteApp()
    now = time.time()
    first = replace(
        _anonymous_apple("11:11:11:11:11:11"), name="First", first_seen=now - 30
    )
    second = replace(
        _anonymous_apple("22:22:22:22:22:22"), name="Second", first_seen=now - 15
    )
    devices = [first, second]
    app.bluetooth_manager.devices = lambda: devices

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["First", "Second"]

        devices.append(replace(_anonymous_apple("33:33:33:33:33:33"), name="Newcomer", first_seen=now))
        scanner.refresh_table()
        assert [table.get_row_at(i)[0].plain for i in range(3)] == [
            "First",
            "Second",
            "Newcomer",
        ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_default_first_seen_order_stays_put_as_labels_tick(monkeypatch):
    app = WifiteApp()
    base = 1_700_000_000.0
    clock = {"now": base}
    monkeypatch.setattr(
        "wifit3.ui.screens.bluetooth_scanner.time.time",
        lambda: clock["now"],
    )
    earlier = replace(
        _anonymous_apple("99:99:99:99:99:99"),
        name="Earlier",
        first_seen=base - 5.2,
        last_seen=base,
    )
    later = replace(
        _anonymous_apple("11:11:11:11:11:11"),
        name="Later",
        first_seen=base - 4.8,
        last_seen=base,
    )
    app.bluetooth_manager.devices = lambda: [later, earlier]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["Earlier", "Later"]

        clock["now"] = base + 0.3
        scanner.refresh_table()
        assert table.get_row_at(0)[5].plain == "5s ago"
        assert table.get_row_at(1)[5].plain == "5s ago"
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["Earlier", "Later"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_first_seen_sort_uses_timestamps_not_formatted_ages():
    app = WifiteApp()
    now = time.time()
    older = replace(
        _anonymous_apple("99:99:99:99:99:99"), name="Older", first_seen=now - 65
    )
    newer = replace(
        _anonymous_apple("11:11:11:11:11:11"), name="Newer", first_seen=now - 25
    )
    app.bluetooth_manager.devices = lambda: [newer, older]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()

        table.update_cell(older.identifier, "first_seen", Text("1 minute ago"))
        table.update_cell(newer.identifier, "first_seen", Text("25 secs ago"))
        scanner._apply_sort()
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["Older", "Newer"]

        scanner.action_toggle_sort_dir()
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["Newer", "Older"]


def test_anonymous_apple_identifiers_form_approximate_group():
    first = _anonymous_apple("11111111-1111-1111-1111-111111111111")
    second = replace(
        first,
        identifier="22222222-2222-2222-2222-222222222222",
        rssi=-45,
        advertisement_count=4,
    )
    named_airpods = replace(first, identifier="stable", name="AirPods")

    grouped = _group_anonymous_apple_devices([first, second, named_airpods])

    assert len(grouped) == 2
    assert grouped[0].identifier == "approximate:apple:004c"
    assert grouped[0].name == "Apple devices (~2 IDs)"
    assert grouped[0].group_size == 2
    assert grouped[0].advertisement_count == 7
    assert grouped[0].rssi == -45
    assert grouped[1] is named_airpods


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_apple_group_can_expand_and_collapse():
    app = WifiteApp()
    devices = [
        _anonymous_apple("11111111-1111-1111-1111-111111111111"),
        _anonymous_apple("22222222-2222-2222-2222-222222222222", rssi=-45),
    ]
    app.bluetooth_manager.devices = lambda: devices

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        scanner.refresh_table()
        assert table.row_count == 1
        assert table.get_row("approximate:apple:004c")[0].plain == "≈ Apple devices (~2 IDs)"

        scanner.action_toggle_apple_group()
        assert table.row_count == 2
        assert table.get_row(devices[0].identifier)[0].plain == "Apple private ID"

        scanner.action_toggle_apple_group()
        assert table.row_count == 1
        assert table.get_row("approximate:apple:004c")[0].plain == "≈ Apple devices (~2 IDs)"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_connect_key_connects_selected_device_and_opens_focus(monkeypatch):
    app = WifiteApp()
    device = replace(
        _anonymous_apple("AA:BB:CC:DD:EE:FF"),
        name="Test Sensor",
        manufacturer_ids=(0x0499,),
    )
    app.bluetooth_manager.devices = lambda: [device]
    app.bluetooth_manager.stop = AsyncMock()
    app.bluetooth_manager.connect = AsyncMock()
    pushed = []

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        monkeypatch.setattr(app, "push_screen", pushed.append)
        assert not any(binding.key == "c" for binding in scanner.BINDINGS)
        enter_binding = next(binding for binding in scanner.BINDINGS if binding.key == "enter")
        assert enter_binding.action == "connect"
        assert enter_binding.show is False

        await pilot.press("enter")
        for _ in range(40):
            await pilot.pause(0)
            if pushed:
                break

        app.bluetooth_manager.connect.assert_awaited_once_with(device)
        assert pushed == ["bluetooth-focus"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_connect_key_opens_read_only_focus_for_classic_device(monkeypatch):
    app = WifiteApp()
    device = replace(
        _anonymous_apple("AA:BB:CC:DD:EE:FF"),
        name="Classic Speaker",
        manufacturer_ids=(),
        radio_types=("BT",),
        discovery_source="usb-hci",
        class_of_device=0x240404,
    )
    app.bluetooth_manager.devices = lambda: [device]
    app.bluetooth_manager._devices[device.identifier] = device
    pushed = []

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        monkeypatch.setattr(app, "push_screen", pushed.append)

        await pilot.press("enter")
        await pilot.pause(0)

        assert app.bluetooth_manager.classic_focus_device is device
        assert pushed == ["bluetooth-classic-focus"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_ble_timeout_falls_back_to_classic_focus(monkeypatch):
    app = WifiteApp()
    device = replace(
        _anonymous_apple("AA:BB:CC:DD:EE:FF"),
        name="Stonmore 2",
        manufacturer_ids=(),
        radio_types=("BLE", "BT"),
        discovery_source="system+usb-hci",
    )
    app.bluetooth_manager.devices = lambda: [device]
    app.bluetooth_manager._devices[device.identifier] = device
    app.bluetooth_manager.stop = AsyncMock()
    app.bluetooth_manager.resume_scan = AsyncMock()

    async def timeout_connect(_device):
        raise BluetoothConnectionError("TimeoutError") from TimeoutError()

    app.bluetooth_manager.connect = AsyncMock(side_effect=timeout_connect)
    pushed = []

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        monkeypatch.setattr(app, "push_screen", pushed.append)

        await pilot.press("enter")
        for _ in range(40):
            await pilot.pause(0)
            if pushed:
                break

        app.bluetooth_manager.resume_scan.assert_awaited_once()
        assert app.bluetooth_manager.classic_focus_device is device
        assert pushed == ["bluetooth-classic-focus"]

