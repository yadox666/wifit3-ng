from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.splash import SplashView


def test_manual_oui_update_is_only_in_device_selection_footer():
    assert ("u", "update_oui", "Update OUI DB") in SplashView.BINDINGS
    assert not any(binding.key == "u" for binding in ScannerView.BINDINGS)
