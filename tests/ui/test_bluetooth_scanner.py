import time
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from rich.text import Text
from textual.widgets import Button, Checkbox, DataTable, Input, Select
from textual.widgets.data_table import ColumnKey

from wifit3.models import BluetoothDevice, SignalPosition
from wifit3.bluetooth.connection import BluetoothConnectionError
from wifit3.bluetooth.manager import BluetoothManager, OsBleSourceStatus
from wifit3.bluetooth.usb_hci import UsbBluetoothController
from wifit3.persist.config import Config
from wifit3.persist.targets import TargetStore
from wifit3.ui.app import WifiteApp
from wifit3.ui.bluetooth_detail import _address_kind_label
from wifit3.ui.screens.bluetooth_scanner import (
    _BluetoothSortReadout,
    BluetoothScannerView,
    _connection_error_message,
    _device_has_expired,
    _group_anonymous_apple_devices,
)
from wifit3.ui.screens.confirm_active import ConfirmEndScanModal
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


def test_address_kind_label_distinguishes_stable_and_rotating_addresses():
    assert _address_kind_label("public") == "public/stable (OUI-based, trackable)"
    assert "private rotating" in _address_kind_label("resolvable-private")
    assert "NRPA" in _address_kind_label("non-resolvable-private")
    assert "MAC hidden" in _address_kind_label("platform-opaque")


def test_timeout_error_has_actionable_ble_message():
    try:
        raise BluetoothConnectionError("TimeoutError") from TimeoutError()
    except BluetoothConnectionError as exc:
        assert _connection_error_message(exc) == (
            "BLE GATT connection timed out. The device may currently accept "
            "Bluetooth Classic only."
        )


def test_bluetooth_expiry_uses_shared_scanner_preference(monkeypatch):
    ble_only = _anonymous_apple("AA:BB:CC:DD:EE:01")
    monkeypatch.setattr(Config, "scanner_ap_expiry", 120.0)
    assert _device_has_expired(ble_only, 599.9) is False
    assert _device_has_expired(ble_only, 600.0) is True

    monkeypatch.setattr(Config, "scanner_ap_expiry", -1.0)
    assert _device_has_expired(ble_only, 100_000.0) is False


def test_bluetooth_expiry_extends_named_classic_rows(monkeypatch):
    now = time.time()
    classic = BluetoothDevice(
        identifier="11:22:33:44:55:66",
        name="Vieta Pro Upper 2",
        rssi=-60,
        service_uuids=(),
        service_data_uuids=(),
        manufacturer_ids=(),
        manufacturer_data_bytes=0,
        service_data_bytes=0,
        tx_power=None,
        advertisement_count=1,
        advertisement_interval=None,
        first_seen=now,
        last_seen=now,
        radio_types=("BT",),
    )
    monkeypatch.setattr(Config, "scanner_ap_expiry", 30.0)
    assert _device_has_expired(classic, 60.0) is False
    assert _device_has_expired(classic, 899.9) is False
    assert _device_has_expired(classic, 900.0) is True


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
        assert panel.query_one(".os-ble-state").render().plain == "READY"
        assert not splash.query_one("#bluetooth-btn").disabled

        splash.query_one("#os-ble-enabled", Checkbox).value = False
        await pilot.pause(0)

        assert app.bluetooth_manager.os_ble_enabled is False
        assert Config.os_ble_enabled is False
        assert panel.query_one(".os-ble-state").render().plain == "OFF (Enable)"
        # No radio available (OS BLE off, no USB) -> button stays visible, disabled.
        bluetooth_btn = splash.query_one("#bluetooth-btn")
        assert bluetooth_btn.display is True
        assert bluetooth_btn.disabled is True


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

        assert state.plain == "OFF (Enable)"
        assert any("red" in str(span.style) for span in state.spans)
        bluetooth_btn = app.screen.query_one("#bluetooth-btn")
        assert bluetooth_btn.display is True
        assert bluetooth_btn.disabled is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_primary_buttons_share_a_centered_row():
    # All primary buttons are always mounted (never removed), even with no
    # SDR/background hardware - they just end up disabled. The row layout must
    # account for all of them every time.
    app = WifiteApp()
    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause(0)
        ids = (
            "start-btn", "bluetooth-btn", "spectrum-btn",
            "background-btn", "offline-btn",
        )
        regions = [app.screen.query_one(f"#{i}").region for i in ids]
        y = regions[0].y
        assert all(region.y == y for region in regions)
        for prev, cur in zip(regions, regions[1:]):
            assert cur.x >= prev.right + 2
        assert abs((regions[0].x + regions[-1].right) - 130) <= 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_splash_wifi_and_bluetooth_buttons_have_hotkeys():
    from wifit3.chips.driver import DeviceID

    app = WifiteApp()
    async with app.run_test() as pilot:
        splash = app.screen
        wifi = splash.query_one("#start-btn")
        bluetooth = splash.query_one("#bluetooth-btn")
        offline = splash.query_one("#offline-btn")

        assert wifi.label.plain == "WI-FI"
        assert wifi.disabled is True

        splash.render_devices([DeviceID(0x0BDA, 0x8812, "RTL8812AU", bus=1, address=3)])
        await pilot.pause(0)

        assert wifi.label.plain == "WI-FI"
        assert wifi.disabled is False
        assert bluetooth.label.plain == "BLE"
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
async def test_splash_adaptive_button_shows_bt_ble_with_dual_controller(monkeypatch):
    app = WifiteApp()
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    app.bluetooth_manager.available_usb_controllers = lambda: [controller]
    app.bluetooth_manager.start_parallel = AsyncMock(return_value=[])
    # Restore after the test so the class-level property can't leak into others.
    monkeypatch.setattr(
        type(app.bluetooth_manager), "is_scanning", property(lambda self: True)
    )
    switched = []
    monkeypatch.setattr(app, "switch_screen", switched.append)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        button = splash.query_one("#bluetooth-btn")
        picker = splash.query_one("#bluetooth-picker")
        # One adaptive button: OS BLE (BLE) + the dual dongle running Classic.
        assert button.display
        assert button.label.plain == "BT+BLE"
        assert picker.display
        assert picker.region.height == 3
        assert picker.selected_controllers() == [controller]

        splash.action_start_bluetooth()
        for _ in range(40):
            await pilot.pause(0)
            if switched:
                break

        app.bluetooth_manager.start_parallel.assert_awaited_once()
        assert app.bluetooth_manager.start_parallel.await_args.kwargs["controllers"] == [controller]
        assert switched == ["bluetooth"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecked_bluetooth_adapter_is_not_started(monkeypatch):
    app = WifiteApp()
    first = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    second = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 3,
        supports_le=False,
    )
    app.bluetooth_manager.available_usb_controllers = lambda: [first, second]
    app.bluetooth_manager.start_parallel = AsyncMock(return_value=[])
    # Restore after the test so the class-level property can't leak into others.
    monkeypatch.setattr(
        type(app.bluetooth_manager), "is_scanning", property(lambda self: True)
    )
    monkeypatch.setattr(app, "switch_screen", lambda name: None)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        assert picker.region.height == 4
        from wifit3.ui.screens.bluetooth_picker import BluetoothModeBar

        realtek_bar = picker.query_one("#bt-mode-bar-0", BluetoothModeBar)
        sena_bar = picker.query_one("#bt-mode-bar-1", BluetoothModeBar)
        assert [key for _label, key in realtek_bar.choices] == ["all", "bt", "ble"]
        assert [key for _label, key in sena_bar.choices] == ["bt"]
        assert sena_bar.has_class("-fixed")

        # Uncheck the Realtek: only the Sena should be handed to start_parallel.
        splash.query_one("#bt-chk-0", Checkbox).value = False
        await pilot.pause(0)
        assert splash.query_one("#bluetooth-btn").display
        splash.action_start_bluetooth()
        for _ in range(20):
            await pilot.pause(0)
            if app.bluetooth_manager.start_parallel.await_count:
                break
        assert (
            app.bluetooth_manager.start_parallel.await_args.kwargs["controllers"] == [second]
        )

        # Uncheck the Sena too: neither dongle is started (OS BLE runs alone).
        splash.query_one("#bt-chk-1", Checkbox).value = False
        await pilot.pause(0)
        app.bluetooth_manager.start_parallel.reset_mock()
        splash.action_start_bluetooth()
        for _ in range(20):
            await pilot.pause(0)
            if app.bluetooth_manager.start_parallel.await_count:
                break
        assert app.bluetooth_manager.start_parallel.await_args.kwargs["controllers"] == []


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
async def test_bluetooth_picker_shows_segmented_scan_mode():
    from wifit3.bluetooth import scan_modes
    from wifit3.ui.screens.bluetooth_picker import BluetoothModeBar

    app = WifiteApp()
    realtek = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    sena = UsbBluetoothController(
        0x0A12, 0x0001, "BlueCore4-ROM", "Sena", "Parani-UD100", 1, 3,
        supports_le=False,
    )
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        picker.set_os_ble_active(True)
        picker.set_controllers([realtek, sena])
        await pilot.pause()
        # Segments mirror the Wi-Fi band bar: ALL | BT | BLE for a dual dongle,
        # a single fixed BT for the Classic-only Sena.
        realtek_bar = picker.query_one("#bt-mode-bar-0", BluetoothModeBar)
        assert [label for label, _key in realtek_bar.choices] == ["ALL", "BT", "BLE"]
        # With OS BLE active, the dual dongle defaults to Classic (BLE on the OS).
        assert realtek_bar.value == "bt"
        assert picker.scan_mode_for(realtek) == scan_modes.BT

        # Turning OS BLE off re-pins the untouched dongle to ALL (both radios).
        picker.set_os_ble_active(False)
        await pilot.pause()
        assert realtek_bar.value == "all"
        assert picker.scan_mode_for(realtek) == scan_modes.BT_BLE


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_picker_selects_scan_mode_on_segment_click():
    from wifit3.bluetooth import scan_modes
    from wifit3.ui.screens.bluetooth_picker import BluetoothModeBar

    app = WifiteApp()
    realtek = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        picker.set_os_ble_active(True)
        picker.set_controllers([realtek])
        await pilot.pause()

        # Clicking the BLE segment selects it and makes the choice sticky.
        bar = picker.query_one("#bt-mode-bar-0", BluetoothModeBar)
        ble_opt = picker.query_one("#bt-mode-bar-0 .bt-mode-ble")
        ble_opt.on_click(type("E", (), {"stop": lambda self: None})())
        await pilot.pause()
        assert bar.value == "ble"
        assert picker.scan_mode_for(realtek) == scan_modes.BLE

        # A manual pick is not overridden when OS BLE availability changes.
        picker.set_os_ble_active(False)
        await pilot.pause()
        assert bar.value == "ble"
        assert picker.scan_mode_for(realtek) == scan_modes.BLE


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_bluetooth_picker_shows_reclaim_icon_when_not_claimed():
    app = WifiteApp()
    controller = UsbBluetoothController(
        0x0BDA, 0x8771, "RTL8761BU", "Realtek", "Bluetooth Adapter", 1, 2,
    )
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        picker = splash.query_one("#bluetooth-picker")
        picker.set_controllers([controller], not_claimed={controller.instance_key})
        await pilot.pause()
        reclaim = picker.query_one("#bt-reclaim-0", Button)
        assert reclaim.display is True
        assert "↻" in str(reclaim.render())
        assert reclaim.styles.width.value == 3
        assert reclaim.styles.min_width.value == 3
        assert reclaim.styles.background.a == 0
        picker.set_controllers([controller], not_claimed=set())
        await pilot.pause()
        reclaim = picker.query_one("#bt-reclaim-0", Button)
        assert reclaim.display is False


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
        assert row[1].plain == "·"
        assert row[2].plain == "·"
        assert row[3].plain == "·"
        assert row[4].plain == "BLE Beacon"
        assert row[5].plain == "Apple, Inc."
        assert row[6].plain == "-42 dBm"
        assert row[7].plain == "12"
        assert row[8].plain == "250 ms"
        assert row[9].plain == "now"
        assert row[10].plain == "now"
        assert row[11].plain == "Battery Service"
        assert row[12].plain == "AA:BB:CC:DD:EE:FF"
        assert row[13].plain == "51.50300, -0.14400 ±5m"

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
async def test_bluetooth_scanner_shows_cached_device_model():
    app = WifiteApp()
    now = time.time()
    device = replace(
        _anonymous_apple("AA:BB:CC:DD:EE:FF"),
        name="Apple Watch",
        model_number="Watch7,15",
        firmware_revision="11.0",
        hardware_revision="1.0",
        software_revision="11.0.1",
        serial_number="ABC123",
        first_seen=now,
        last_seen=now,
    )
    app.bluetooth_manager.devices = lambda: [device]

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()
        table = scanner.query_one("#bluetooth-table", DataTable)
        row = table.get_row(device.identifier)
        assert row[0].plain == "Apple Watch"
        assert row[1].plain == "Apple Watch SE 3 (GPS + Cellular)"

        scanner._show_device_details(device)
        log = scanner.query_one("#bluetooth-log")
        rendered = "\n".join(
            line.text if hasattr(line, "text") else str(line) for line in log.lines
        )
        assert "GATT Device Information" in rendered
        assert "Watch7,15" in rendered
        assert "11.0.1" in rendered


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_scanner_logs_learned_model_and_gates_enrichment_by_screen():
    app = WifiteApp()
    base = replace(_anonymous_apple("AA:BB:CC:DD:EE:FF"), name="Apple Watch")
    current = {"device": base}
    app.bluetooth_manager.devices = lambda: [current["device"]]

    resumed: list[bool] = []
    paused: list[bool] = []
    app.bluetooth_manager.resume_device_information_sweep = lambda: resumed.append(True)

    async def _pause():
        paused.append(True)

    app.bluetooth_manager.pause_device_information_sweep = _pause

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        scanner.refresh_table()  # row created (auto-detail clears the log)
        await pilot.pause(0)

        # The scanner resumes passive enrichment on entry.
        assert resumed

        # Enrichment later learns the model; it is logged without clearing.
        current["device"] = replace(
            base, model_number="Watch7,15", firmware_revision="11.0",
        )
        scanner.refresh_table()
        await pilot.pause(0)
        log = scanner.query_one("#bluetooth-log")
        rendered = "\n".join(
            line.text if hasattr(line, "text") else str(line) for line in log.lines
        )
        assert "Model learned" in rendered
        assert "Watch7,15" in rendered

        # Leaving the scanner (entering Focus/Lab) pauses enrichment.
        await scanner.on_screen_suspend()
        assert paused


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
        assert name.plain.startswith("! ")
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

        while table.columns[ColumnKey("advertisements")].label.plain == "  #ADV":
            scanner.action_cycle_sort()
        assert table.columns[ColumnKey("advertisements")].label.plain == "▲ #ADV"
        assert table.get_row_at(0)[0].plain == "Strong Sensor"

        scanner.action_toggle_sort_dir()
        assert table.columns[ColumnKey("advertisements")].label.plain == "▼ #ADV"
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
async def test_touching_bluetooth_header_selects_and_reverses_sort():
    app = WifiteApp()

    async with app.run_test(size=(120, 40)) as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        scanner = app.screen
        table = scanner.query_one("#bluetooth-table", DataTable)
        column_key = ColumnKey("name")
        event = DataTable.HeaderSelected(
            table,
            column_key,
            table.get_column_index(column_key),
            table.columns[column_key].label,
        )

        scanner.sort_from_header(event)
        assert table.columns[column_key].label.plain == "DEVICE ▲"

        scanner.sort_from_header(event)
        assert table.columns[column_key].label.plain == "DEVICE ▼"


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
        table = scanner.query_one("#bluetooth-private-table", DataTable)
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
        table = scanner.query_one("#bluetooth-private-table", DataTable)
        scanner.refresh_table()
        assert [table.get_row_at(i)[0].plain for i in range(2)] == ["Earlier", "Later"]

        clock["now"] = base + 0.3
        scanner.refresh_table()
        assert table.get_row_at(0)[9].plain == "5s ago"
        assert table.get_row_at(1)[9].plain == "5s ago"
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
        table = scanner.query_one("#bluetooth-private-table", DataTable)
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
async def test_anonymous_apple_devices_render_in_private_table_pane():
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
        main = scanner.query_one("#bluetooth-table", DataTable)
        private = scanner.query_one("#bluetooth-private-table", DataTable)
        scanner.refresh_table()
        assert main.row_count == 0
        assert private.row_count == 2
        assert private.display is True
        assert private.get_row(devices[0].identifier) is not None
        assert private.get_row(devices[1].identifier) is not None


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
        assert pushed == ["bluetooth-focus"]


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
        assert pushed == ["bluetooth-focus"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_ble_timeout_without_classic_still_opens_observation_focus(monkeypatch):
    app = WifiteApp()
    device = replace(
        _anonymous_apple("AA:BB:CC:DD:EE:FF"),
        name="BLE-only sensor",
        manufacturer_ids=(),
        radio_types=("BLE",),
    )
    app.bluetooth_manager.devices = lambda: [device]
    app.bluetooth_manager._devices[device.identifier] = device
    app.bluetooth_manager.stop = AsyncMock()
    app.bluetooth_manager.resume_scan = AsyncMock()
    app.bluetooth_manager.connect = AsyncMock(
        side_effect=BluetoothConnectionError("TimeoutError"),
    )
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

        assert app.bluetooth_manager.focus_device is device
        assert "timeout" in app.bluetooth_manager.focus_connection_error.casefold()
        assert pushed == ["bluetooth-focus"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_escape_from_bluetooth_scan_asks_before_leaving():
    app = WifiteApp()
    app.bluetooth_manager.stop = AsyncMock()
    async with app.run_test() as pilot:
        app.switch_screen("bluetooth")
        await pilot.pause(0)
        assert isinstance(app.screen, BluetoothScannerView)

        await pilot.press("escape")
        await pilot.pause(0)
        modal = app.screen
        assert isinstance(modal, ConfirmEndScanModal)
        modal.query_one("#end-scan-cancel", Button).press()
        await pilot.pause(0)
        assert isinstance(app.screen, BluetoothScannerView)

        await pilot.press("escape")
        await pilot.pause(0)
        app.screen.query_one("#end-scan-confirm", Button).press()
        for _ in range(20):
            await pilot.pause(0)
            if isinstance(app.screen, SplashView):
                break
        assert isinstance(app.screen, SplashView)
        app.bluetooth_manager.stop.assert_awaited()

