import copy

import pytest

import wifit3.persist.config as cfg
from wifit3.persist.config import Config, ConfigError

_DEFAULTS = {n: getattr(Config, n)
             for n in (
                 "theme", "scanner_sort", "scanner_sort_reverse", "scanner_sort_delay",
                 "scanner_ap_expiry", "silenced_bssids", "log_level", "captures_dir",
                 "save_pcap", "auto_check_updates", "confirm_active_actions", "auto_wps_pbc",
                 "active_action_intensity", "auto_lock_targets",
                 "target_reacquire_timeout", "target_capture_max_mb",
                 "target_capture_max_parts", "gps_port",
                 "gps_movement_threshold_m", "gps_max_accuracy_m")}


@pytest.fixture(autouse=True)
def _restore_defaults():
    for n, v in _DEFAULTS.items():
        setattr(Config, n, copy.deepcopy(v))
    yield
    for n, v in _DEFAULTS.items():
        setattr(Config, n, copy.deepcopy(v))


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setattr(cfg, "_PATH", path)
    return path


def test_load_missing_file_keeps_defaults(config_path):
    before = {n: getattr(Config, n) for n in _DEFAULTS}
    Config.load()
    assert all(getattr(Config, n) == before[n] for n in before)


def test_load_reads_values_and_ignores_unknown_keys(config_path):
    config_path.write_text(
        'theme = "gruvbox"\nscanner_sort = "channel"\nscanner_sort_reverse = false\nfuture = 1\n')
    Config.load()
    assert Config.theme == "gruvbox"
    assert Config.scanner_sort == "channel"
    assert Config.scanner_sort_reverse is False


def test_load_absent_key_keeps_default(config_path):
    config_path.write_text('theme = "nord"\n')
    Config.load()
    assert Config.theme == "nord"
    assert Config.scanner_sort == "signal"


def test_load_corrupt_file_raises(config_path):
    config_path.write_text("this is = = not toml")
    with pytest.raises(ConfigError):
        Config.load()


def test_save_then_load_round_trips(config_path):
    Config.theme, Config.scanner_sort, Config.scanner_sort_reverse = "nord", "channel", False
    Config.save()
    Config.theme, Config.scanner_sort, Config.scanner_sort_reverse = "x", "y", True
    Config.load()
    assert (Config.theme, Config.scanner_sort, Config.scanner_sort_reverse) == ("nord", "channel", False)


def test_save_load_preserves_windows_path_literally(config_path):
    Config.theme = r"C:\Users\Someone\theme"
    Config.save()
    assert r"'C:\Users\Someone\theme'" in config_path.read_text("utf-8")
    Config.theme = "x"
    Config.load()
    assert Config.theme == r"C:\Users\Someone\theme"


def test_save_load_round_trips_captures_dir_with_apostrophe(config_path):
    Config.captures_dir = r"C:\Users\O'Brien\captures"
    Config.save()
    Config.captures_dir = "x"
    Config.load()
    assert Config.captures_dir == r"C:\Users\O'Brien\captures"


def test_save_failure_raises(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    monkeypatch.setattr(cfg, "_PATH", blocker / "config.toml")
    with pytest.raises(ConfigError):
        Config.save()


def test_fmt_scalars():
    assert cfg._fmt(True) == "true"
    assert cfg._fmt(False) == "false"
    assert cfg._fmt(3) == "3"
    assert cfg._fmt("signal") == "'signal'"


def test_fmt_list():
    assert cfg._fmt([]) == "[]"
    assert cfg._fmt(["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]) == \
        "['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']"


def test_silenced_bssids_save_load_roundtrip(config_path):
    Config.silenced_bssids = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    Config.save()
    assert "silenced_bssids = ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']" \
        in config_path.read_text("utf-8")
    Config.silenced_bssids = []
    Config.load()
    assert Config.silenced_bssids == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]


def test_silenced_bssids_load_normalizes_case(config_path):
    config_path.write_text("silenced_bssids = ['AA:BB:CC:DD:EE:FF']\n")
    Config.load()
    assert Config.silenced_bssids == ["aa:bb:cc:dd:ee:ff"]


def test_silenced_bssids_bad_type_keeps_default(config_path):
    Config.silenced_bssids = []
    config_path.write_text('silenced_bssids = "not-a-list"\n')
    Config.load()
    assert Config.silenced_bssids == []


def test_is_silenced_is_case_insensitive():
    Config.silenced_bssids = ["aa:bb:cc:dd:ee:ff"]
    assert Config.is_silenced("AA:BB:CC:DD:EE:FF") is True
    assert Config.is_silenced("aa:bb:cc:dd:ee:ff") is True
    assert Config.is_silenced("11:22:33:44:55:66") is False


def test_scanner_sort_delay_save_load_roundtrip(config_path):
    Config.scanner_sort_delay = 5.0
    Config.save()
    assert "scanner_sort_delay = 5.0" in config_path.read_text("utf-8")
    Config.scanner_sort_delay = 1.0
    Config.load()
    assert Config.scanner_sort_delay == 5.0


def test_scanner_ap_expiry_save_load_roundtrip(config_path):
    Config.scanner_ap_expiry = 120.0
    Config.save()
    assert "scanner_ap_expiry = 120.0" in config_path.read_text("utf-8")
    Config.scanner_ap_expiry = 30.0
    Config.load()
    assert Config.scanner_ap_expiry == 120.0


def test_update_preference_save_load_roundtrip(config_path):
    Config.auto_check_updates = True
    Config.save()
    Config.auto_check_updates = False
    Config.load()
    assert Config.auto_check_updates is True


def test_active_action_preferences_save_load_roundtrip(config_path):
    Config.confirm_active_actions = False
    Config.auto_wps_pbc = True
    Config.active_action_intensity = "low"
    Config.save()
    Config.confirm_active_actions = True
    Config.auto_wps_pbc = False
    Config.active_action_intensity = "normal"
    Config.load()
    assert Config.confirm_active_actions is False
    assert Config.auto_wps_pbc is True
    assert Config.active_action_intensity == "low"


def test_auto_lock_targets_save_load_roundtrip(config_path):
    Config.auto_lock_targets = True
    Config.target_reacquire_timeout = 60
    Config.target_capture_max_mb = 50
    Config.target_capture_max_parts = 3
    Config.save()
    Config.auto_lock_targets = False
    Config.target_reacquire_timeout = 120
    Config.target_capture_max_mb = 100
    Config.target_capture_max_parts = 10
    Config.load()
    assert Config.auto_lock_targets is True
    assert Config.target_reacquire_timeout == 60
    assert Config.target_capture_max_mb == 50
    assert Config.target_capture_max_parts == 3


def test_unlimited_capture_parts_save_load_roundtrip(config_path):
    Config.target_capture_max_parts = 0
    Config.save()
    Config.target_capture_max_parts = 10
    Config.load()
    assert Config.target_capture_max_parts == 0


def test_gps_preferences_save_load_roundtrip(config_path):
    Config.gps_port = "COM7"
    Config.gps_movement_threshold_m = 35.0
    Config.gps_max_accuracy_m = 12.0
    Config.save()
    Config.gps_port = ""
    Config.gps_movement_threshold_m = 20.0
    Config.gps_max_accuracy_m = 20.0

    Config.load()

    assert Config.gps_port == "COM7"
    assert Config.gps_movement_threshold_m == 35.0
    assert Config.gps_max_accuracy_m == 12.0
