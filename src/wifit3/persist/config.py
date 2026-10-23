"""Persistent user preferences: TOML in the OS config dir (one table per cracking tool)."""
from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field, fields, replace
from types import UnionType
from typing import Any, TypeVar, get_args, get_origin, get_type_hints

from wifit3.models.jobs import ToolName

_SSID_MAX_OCTETS = 32
from pathlib import Path

from platformdirs import user_config_dir
from wifit3.persist.private_files import ensure_private_directory, write_private_text

_PATH = Path(user_config_dir("wifit3", appauthor=False)) / "config.toml"


class ConfigError(Exception):
    pass


@dataclass
class CpuCrackSettings:
    wordlists: list[str] = field(default_factory=list)
    default_passwords: bool = True
    ap_ssid_passwords: bool = True
    probed_ssid_passwords: bool = True


@dataclass
class HashcatSettings:
    path: str | None = None
    args: str | None = None
    wordlists: list[str] = field(default_factory=list)


@dataclass
class HashtopolisSettings:
    url: str | None = None
    access_key: str | None = None
    wordlist_id: int | None = None
    wordlist_name: str | None = None
    access_group_id: int | None = None
    access_group_name: str | None = None


SettingsT = TypeVar("SettingsT", CpuCrackSettings, HashcatSettings, HashtopolisSettings)


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
    gps_port: str = ""
    gps_movement_threshold_m: float = 20.0
    gps_max_accuracy_m: float = 20.0
    gps_enabled: bool = True
    os_ble_enabled: bool = True
    silenced_bssids: list[str] = []
    decloaked_ssids: dict[str, str] = {}
    hide_silenced: bool = False
    wps_auto_pbc: bool = True
    # ISO 3166-1 alpha-2; ``""``, ``00``, and ``world`` (any case) all mean cfg80211 world.
    wifi_regulatory_country: str = "00"
    # Last RealAP identity; passphrase is never stored.
    # Shared PortalTwin / RealAP captive page pack (``builtin`` or user-import id).
    auto_crack: ToolName | None = ToolName.CPU_CRACK
    cpu_crack: CpuCrackSettings = CpuCrackSettings()
    hashcat: HashcatSettings = HashcatSettings()
    hashtopolis: HashtopolisSettings = HashtopolisSettings()

    @classmethod
    def is_silenced(cls, bssid: str) -> bool:
        return bssid.lower() in cls.silenced_bssids

    @classmethod
    def decloaked_ssid(cls, bssid: str) -> str | None:
        return cls.decloaked_ssids.get(bssid.lower())

    @classmethod
    def remember_decloak(cls, bssid: str, ssid: str) -> bool:
        if not ssid or len(ssid.encode("utf-8")) > _SSID_MAX_OCTETS:
            return False
        key = bssid.lower()
        if cls.decloaked_ssids.get(key) == ssid:
            return False
        cls.decloaked_ssids[key] = ssid
        return True

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
        cls.wps_auto_pbc = bool(data.get("wps_auto_pbc", cls.wps_auto_pbc))
        if "auto_wps_pbc" in data:
            cls.auto_wps_pbc = bool(data.get("auto_wps_pbc"))
        stored = data.get("decloak")
        if isinstance(stored, dict):
            cls.decloaked_ssids = {str(bssid).lower(): ssid for bssid, ssid in stored.items()
                                   if isinstance(ssid, str) and ssid}
        cls.hide_silenced = bool(data.get("hide_silenced", cls.hide_silenced))
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
        cls.gps_port = str(data.get("gps_port", cls.gps_port)).strip()
        cls.gps_enabled = bool(data.get("gps_enabled", cls.gps_enabled))
        cls.os_ble_enabled = bool(data.get("os_ble_enabled", cls.os_ble_enabled))
        try:
            cls.gps_movement_threshold_m = max(
                20.0,
                float(data.get(
                    "gps_movement_threshold_m", cls.gps_movement_threshold_m,
                )),
            )
        except (ValueError, TypeError):
            pass
        try:
            cls.gps_max_accuracy_m = max(
                1.0,
                float(data.get("gps_max_accuracy_m", cls.gps_max_accuracy_m)),
            )
        except (ValueError, TypeError):
            pass
        raw = data.get("silenced_bssids", cls.silenced_bssids)
        cls.silenced_bssids = [str(x).lower() for x in raw] if isinstance(raw, list) else cls.silenced_bssids
        from wifit3.wlan.regulatory import normalize_country

        cls.wifi_regulatory_country = normalize_country(
            str(data.get("wifi_regulatory_country", cls.wifi_regulatory_country))
        )
        cls.auto_crack = _auto_crack(data, cls.auto_crack)
        legacy_wordlists = _legacy_wordlists(data)
        cls.cpu_crack = _load_table(_table(data, "cpu_crack"), cls.cpu_crack)
        cls.hashcat = _load_table(
            {"path": data.get("hashcat_path"), "args": data.get("hashcat_args"),
             "wordlists": legacy_wordlists, **_table(data, "hashcat")}, cls.hashcat)
        legacy_hashtopolis = {name.removeprefix("hashtopolis_"): value
                              for name, value in data.items() if name.startswith("hashtopolis_")}
        cls.hashtopolis = _load_table({**legacy_hashtopolis, **_table(data, "hashtopolis")},
                                      cls.hashtopolis)

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
            f"wps_auto_pbc = {_fmt(cls.wps_auto_pbc)}\n"
            f"hide_silenced = {_fmt(cls.hide_silenced)}\n"
            f"auto_lock_targets = {_fmt(cls.auto_lock_targets)}\n"
            f"target_reacquire_timeout = {_fmt(cls.target_reacquire_timeout)}\n"
            f"target_capture_max_mb = {_fmt(cls.target_capture_max_mb)}\n"
            f"target_capture_max_parts = {_fmt(cls.target_capture_max_parts)}\n"
            f"active_action_intensity = {_fmt(cls.active_action_intensity)}\n"
            f"gps_port = {_fmt(cls.gps_port)}\n"
            f"gps_movement_threshold_m = {_fmt(cls.gps_movement_threshold_m)}\n"
            f"gps_max_accuracy_m = {_fmt(cls.gps_max_accuracy_m)}\n"
            f"gps_enabled = {_fmt(cls.gps_enabled)}\n"
            f"os_ble_enabled = {_fmt(cls.os_ble_enabled)}\n"
            f"silenced_bssids = {_fmt(cls.silenced_bssids)}\n"
            f"wifi_regulatory_country = {_fmt_regulatory_country(cls.wifi_regulatory_country)}\n"
            f"auto_crack = {_fmt(cls.auto_crack or '')}\n"
        )
        text += _table_text("cpu_crack", cls.cpu_crack)
        text += _table_text("hashcat", cls.hashcat)
        text += _table_text("hashtopolis", cls.hashtopolis)
        if cls.decloaked_ssids:
            text += "\n[decloak]\n"
            for bssid, ssid in sorted(cls.decloaked_ssids.items()):
                text += f"{_fmt(bssid)} = {_fmt(ssid)}\n"
        try:
            ensure_private_directory(_PATH.parent)
            write_private_text(_PATH, text)
        except OSError as e:
            raise ConfigError(f"Failed to save config at {_PATH}: {e}") from e


def _auto_crack(data: dict, current: ToolName | None) -> ToolName | None:
    raw = data["auto_crack_tool"] if "auto_crack_tool" in data else data.get("auto_crack", current)
    if raw is None or isinstance(raw, bool):
        return ToolName.CPU_CRACK if raw else None
    try:
        return ToolName(raw)
    except ValueError:
        return None


def _legacy_wordlists(data: dict) -> object:
    if "wordlist_paths" in data:
        return data["wordlist_paths"]
    return [data["wordlist_path"]] if data.get("wordlist_path") else None


def _table(data: dict, name: str) -> dict:
    table = data.get(name)
    return table if isinstance(table, dict) else {}


def _load_table(raw: dict, current: SettingsT) -> SettingsT:
    hints = get_type_hints(type(current))
    loaded = {f.name: raw[f.name] for f in fields(current)
              if raw.get(f.name) not in (None, "") and _has_type(raw[f.name], hints[f.name])}
    return replace(current, **loaded)


def _has_type(value: Any, hint: Any) -> bool:
    if isinstance(hint, UnionType):
        return any(_has_type(value, arg) for arg in get_args(hint) if arg is not type(None))
    if get_origin(hint) is list:
        return isinstance(value, list) and all(_has_type(v, get_args(hint)[0]) for v in value)
    if hint is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, hint)


def _table_text(name: str, settings: SettingsT) -> str:
    lines = [f"{key} = {_fmt(value)}\n" for key, value in asdict(settings).items()
             if value not in (None, "", [])]
    return f"\n[{name}]\n" + "".join(lines) if lines else ""


def _fmt_regulatory_country(code: str) -> str:
    from wifit3.wlan.regulatory import normalize_country

    if normalize_country(code) == "00":
        return "''"
    return _fmt(code)


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
