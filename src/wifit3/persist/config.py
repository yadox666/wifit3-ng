"""Persistent user preferences: a flat TOML file in the OS config dir."""
from __future__ import annotations

import tomllib
from pathlib import Path

from platformdirs import user_config_dir

_PATH = Path(user_config_dir("wifit3", appauthor=False)) / "config.toml"


class ConfigError(Exception):
    pass


class Config:
    theme: str = "textual-dark"
    captures_dir: str = "captures"
    save_pcap: bool = True
    log_level: str = "info"
    scanner_sort: str = "signal"
    scanner_sort_reverse: bool = True
    scanner_sort_delay: float = 2.0
    scanner_ap_expiry: float = 30.0
    auto_check_updates: bool = False
    confirm_active_actions: bool = True
    auto_wps_pbc: bool = False
    auto_lock_targets: bool = False
    target_reacquire_timeout: float = 120.0
    target_capture_max_mb: int = 100
    target_capture_max_parts: int = 10
    active_action_intensity: str = "normal"
    silenced_bssids: list[str] = []

    @classmethod
    def is_silenced(cls, bssid: str) -> bool:
        return bssid.lower() in cls.silenced_bssids

    @classmethod
    def load(cls) -> None:
        try:
            data = tomllib.loads(_PATH.read_text("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise ConfigError(f"Failed to load config at {_PATH}: {e}") from e
        cls.captures_dir = data.get("captures_dir", cls.captures_dir)
        cls.save_pcap = data.get("save_pcap", cls.save_pcap)
        cls.theme = data.get("theme", cls.theme)
        cls.log_level = data.get("log_level", cls.log_level)
        cls.scanner_sort = data.get("scanner_sort", cls.scanner_sort)
        cls.scanner_sort_reverse = data.get("scanner_sort_reverse", cls.scanner_sort_reverse)
        cls.auto_check_updates = bool(data.get("auto_check_updates", cls.auto_check_updates))
        cls.confirm_active_actions = bool(
            data.get("confirm_active_actions", cls.confirm_active_actions)
        )
        cls.auto_wps_pbc = bool(data.get("auto_wps_pbc", cls.auto_wps_pbc))
        cls.auto_lock_targets = bool(
            data.get("auto_lock_targets", cls.auto_lock_targets)
        )
        try:
            cls.target_reacquire_timeout = max(
                15.0,
                float(data.get(
                    "target_reacquire_timeout", cls.target_reacquire_timeout,
                )),
            )
            cls.target_capture_max_mb = max(
                1,
                int(data.get("target_capture_max_mb", cls.target_capture_max_mb)),
            )
            cls.target_capture_max_parts = max(
                0,
                int(data.get(
                    "target_capture_max_parts", cls.target_capture_max_parts,
                )),
            )
        except (ValueError, TypeError):
            pass
        intensity = data.get("active_action_intensity", cls.active_action_intensity)
        if intensity in {"low", "normal", "high"}:
            cls.active_action_intensity = intensity
        raw_delay = data.get("scanner_sort_delay", cls.scanner_sort_delay)
        try:
            cls.scanner_sort_delay = float(raw_delay)
        except (ValueError, TypeError):
            pass
        raw_expiry = data.get("scanner_ap_expiry", cls.scanner_ap_expiry)
        try:
            cls.scanner_ap_expiry = float(raw_expiry)
        except (ValueError, TypeError):
            pass
        raw = data.get("silenced_bssids", cls.silenced_bssids)
        cls.silenced_bssids = [str(x).lower() for x in raw] if isinstance(raw, list) else cls.silenced_bssids

    @classmethod
    def save(cls) -> None:
        text = (
            f"captures_dir = {_fmt(cls.captures_dir)}\n"
            f"save_pcap = {_fmt(cls.save_pcap)}\n"
            f"theme = {_fmt(cls.theme)}\n"
            f"log_level = {_fmt(cls.log_level)}\n"
            f"scanner_sort = {_fmt(cls.scanner_sort)}\n"
            f"scanner_sort_reverse = {_fmt(cls.scanner_sort_reverse)}\n"
            f"scanner_sort_delay = {_fmt(cls.scanner_sort_delay)}\n"
            f"scanner_ap_expiry = {_fmt(cls.scanner_ap_expiry)}\n"
            f"auto_check_updates = {_fmt(cls.auto_check_updates)}\n"
            f"confirm_active_actions = {_fmt(cls.confirm_active_actions)}\n"
            f"auto_wps_pbc = {_fmt(cls.auto_wps_pbc)}\n"
            f"auto_lock_targets = {_fmt(cls.auto_lock_targets)}\n"
            f"target_reacquire_timeout = {_fmt(cls.target_reacquire_timeout)}\n"
            f"target_capture_max_mb = {_fmt(cls.target_capture_max_mb)}\n"
            f"target_capture_max_parts = {_fmt(cls.target_capture_max_parts)}\n"
            f"active_action_intensity = {_fmt(cls.active_action_intensity)}\n"
            f"silenced_bssids = {_fmt(cls.silenced_bssids)}\n"
        )
        try:
            _PATH.parent.mkdir(parents=True, exist_ok=True)
            _PATH.write_text(text, encoding="utf-8")
        except OSError as e:
            raise ConfigError(f"Failed to save config at {_PATH}: {e}") from e


def _fmt(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_fmt(x) for x in v) + "]"
    s = str(v)
    if "'" not in s and "\n" not in s:
        return "'" + s + "'"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
