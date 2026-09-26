from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.bluetooth_focus import BluetoothFocusView
from wifit3.ui.screens.bluetooth_scanner import BluetoothScannerView
from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.splash import SplashView
from wifit3.ui.screens.vault_drawer import VaultDrawer


def test_quit_uses_global_ctrl_q_binding_only():
    assert any(
        binding.key == "ctrl+q" and binding.action == "quit"
        for binding in WifiteApp.BINDINGS
    )
    for screen in (
        SplashView,
        ScannerView,
        FocusViewV2,
        BluetoothScannerView,
        BluetoothFocusView,
        VaultDrawer,
    ):
        assert not any(
            (binding[0] if isinstance(binding, tuple) else binding.key) == "q"
            for binding in screen.BINDINGS
        )
