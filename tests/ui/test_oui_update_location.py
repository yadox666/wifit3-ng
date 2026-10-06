from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.splash import SplashView


def test_manual_oui_update_is_only_in_device_selection_footer():
    assert any(
        binding.key == "u"
        and binding.action == "update_oui"
        and binding.description == "Update OUI DB"
        for binding in SplashView.BINDINGS
    )
    assert not any(binding.key == "u" for binding in ScannerView.BINDINGS)
