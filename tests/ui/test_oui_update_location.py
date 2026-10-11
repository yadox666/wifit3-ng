from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.splash import SplashView


def test_manual_oui_update_is_not_on_the_splash_footer():
    assert not any(binding.action == "update_oui" for binding in SplashView.BINDINGS)
    assert not any(binding.key == "u" for binding in ScannerView.BINDINGS)
    diagnostics = [binding for binding in SplashView.BINDINGS if binding.key == "ctrl+d"]
    assert diagnostics and diagnostics[0].show is False
