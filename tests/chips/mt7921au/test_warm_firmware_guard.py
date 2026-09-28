from unittest.mock import MagicMock

import pytest

from wifit3.chips.mt7921au.driver import MT7921AUDriver
from wifit3.chips.mt7925au.driver import MT7925AUDriver
from wifit3.errors import BringUpError


def _bare(driver_cls):
    return driver_cls.__new__(driver_cls)


@pytest.mark.parametrize("driver_cls", (MT7921AUDriver, MT7925AUDriver))
def test_require_own_firmware_accepts_wifit3_warm_chip(driver_cls):
    drv = _bare(driver_cls)
    drv.firmware = MagicMock()
    drv.firmware.dma_need_reinit.return_value = False
    drv._require_own_firmware()


@pytest.mark.parametrize("driver_cls", (MT7921AUDriver, MT7925AUDriver))
def test_require_own_firmware_rejects_foreign_firmware(driver_cls):
    drv = _bare(driver_cls)
    drv.firmware = MagicMock()
    drv.firmware.dma_need_reinit.return_value = True
    with pytest.raises(BringUpError, match="unplug/replug"):
        drv._require_own_firmware()
