from wifit3.models import AccessPoint, IdKey, IdSource
from wifit3.models.identity_display import scanner_identity_summary


def test_quantenna_topaz_shows_cpe_device_name_and_firmware():
    ap = AccessPoint(bssid="44:3b:14:29:25:77", ssid="MOVISTAR-WIFI6-9398", channel=100)
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "Quantenna Communications")
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MODEL_NAME, "Topaz")
    ap.identity.set(
        IdSource.WSC_BEACON,
        IdKey.DEVICE_NAME,
        "MitraStar Technology Corp. GPT-2742GX4X5V6",
    )
    ap.wps_os_version = 0x01020304  # major 1 minor 2 build 0x0304 -> need check encoding

    summary = scanner_identity_summary(ap)
    assert "GPT-2742GX4X5V6" in summary
    assert "Quantenna" in summary
    assert "Topaz" in summary
    assert "fw " in summary


def test_quantenna_yields_to_branded_oui_in_identity():
    ap = AccessPoint(bssid="44:3b:14:29:25:77", ssid="MOVISTAR-WIFI6", channel=100)
    ap.identity.set(IdSource.OUI, IdKey.MANUFACTURER, "MitraStar Technology Corp. GPT-2742GX4X5V6")
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MANUFACTURER, "Quantenna")
    ap.identity.set(IdSource.WSC_BEACON, IdKey.MODEL_NAME, "Topaz")
    assert ap.identity.manufacturer.startswith("MitraStar")

    summary = scanner_identity_summary(ap)
    assert "MitraStar" in summary
    assert "Quantenna" in summary
    assert "Topaz" in summary
