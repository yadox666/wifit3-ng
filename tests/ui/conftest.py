import pytest
from unittest.mock import patch

from wifit3.persist.config import Config
from wifit3.bluetooth.manager import OsBleSourceStatus
from wifit3.ui.app import WifiteApp


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path, monkeypatch):
    """UI tests build WifiteApp, which loads and persists Config: keep that off the real on-disk
    config file and reset the class-level defaults so a theme edit can't leak between tests."""
    monkeypatch.setattr("wifit3.persist.config._PATH", tmp_path / "config.toml")
    monkeypatch.setattr(
        "wifit3.persist.locations.LOCATION_HISTORY_PATH",
        tmp_path / "location_history.sqlite3",
    )
    monkeypatch.setattr("wifit3.gps.manager.list_ports.comports", lambda: [])

    async def ready_os_ble(manager):
        manager.os_ble_status = OsBleSourceStatus(
            True,
            True,
            "OS-READY",
            "TestBleak",
            "TestOS",
            "Test vendor",
            "Test adapter",
            "Operating-system BLE scanning is available",
        )
        return manager.os_ble_status

    monkeypatch.setattr(
        "wifit3.bluetooth.manager.BluetoothManager.probe_os_ble",
        ready_os_ble,
    )
    Config.theme = "wifit3-green-dark"
    Config.scanner_sort = "signal"
    Config.scanner_sort_reverse = True
    Config.scanner_sort_delay = 2.0
    Config.scanner_ap_expiry = 30.0
    Config.auto_check_updates = False
    Config.confirm_active_actions = True
    Config.auto_wps_pbc = False
    Config.active_action_intensity = "normal"
    Config.gps_port = ""
    Config.gps_movement_threshold_m = 20.0
    Config.gps_max_accuracy_m = 20.0
    Config.os_ble_enabled = True
    Config.silenced_bssids = []
    yield


@pytest.fixture(autouse=True)
def _auto_start_scan_session(monkeypatch):
    """UI tests boot WifiteApp without blocking on the session naming modal."""

    def _prompt(self) -> None:
        self.start_scan_session({"wifi", "bluetooth"}, mode="app")

    monkeypatch.setattr(WifiteApp, "_prompt_scan_session", _prompt)


@pytest.fixture
def no_usb_devices():
    """Bus scan finds zero cards, so booting WifiteApp touches no real backend.

    Opt-in (NOT autouse) by design: the app-boot / UI tests don't want hardware, but the
    libusb-backend-failure tests need the real usb.core.find path intact, so a global stub
    would make those untestable. Tests request it with @pytest.mark.usefixtures("no_usb_devices").
    """
    # usb.core.find covers libusb; present_usb_ids covers the Windows PnP merge in devices().
    with patch('usb.core.find', return_value=[]), \
         patch('wifit3.device.windows_pnp.present_usb_ids', return_value=set()):
        yield
