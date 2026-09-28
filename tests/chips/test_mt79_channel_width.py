import pytest

from wifit3.chips.mt7921au import mcu as mcu21
from wifit3.chips.mt7925au import mcu as mcu25


@pytest.mark.parametrize("mcu", [mcu21, mcu25])
def test_config_sniffer_encodes_20mhz_primary(mcu):
    _command, payload = mcu.config_sniffer(9)

    assert payload[11:17] == bytes([0, 9, 0, 9, 0, 1])


@pytest.mark.parametrize("mcu", [mcu21, mcu25])
@pytest.mark.parametrize(
    ("primary", "offset", "center", "sco"),
    [(5, 1, 7, 1), (9, -1, 7, 3), (44, 1, 46, 1)],
)
def test_config_sniffer_encodes_40mhz_secondary(mcu, primary, offset, center, sco):
    _command, payload = mcu.config_sniffer(
        primary,
        width_mhz=40,
        secondary_offset=offset,
        center_channel=center,
    )

    assert payload[11:17] == bytes([0, primary, sco, center, 0, 1])


@pytest.mark.parametrize("mcu", [mcu21, mcu25])
def test_config_sniffer_rejects_invalid_40mhz_layout(mcu):
    with pytest.raises(ValueError, match="secondary"):
        mcu.config_sniffer(9, width_mhz=40)
    with pytest.raises(ValueError, match="conflicts"):
        mcu.config_sniffer(
            9, width_mhz=40, secondary_offset=-1, center_channel=11,
        )
