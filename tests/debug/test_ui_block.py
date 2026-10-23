import logging
import time

from wifit3.debug.ui_block import configure, section


def test_section_logs_when_slow(tmp_path, caplog):
    configure(enabled_flag=True, slow_ms=1, stall_ms=5, console=False)
    caplog.set_level(logging.WARNING, logger="wifit3.debug.ui_block")
    with section("test.sleep"):
        time.sleep(0.01)
    assert any("SLOW" in record.message and "test.sleep" in record.message for record in caplog.records)


def test_section_silent_when_fast():
    configure(enabled_flag=True, slow_ms=500, console=False)
    with section("test.fast"):
        pass
