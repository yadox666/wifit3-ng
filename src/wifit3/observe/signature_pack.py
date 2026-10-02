"""JSON signature rules in the OS user data directory, beside the compiled catalog."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Mapping

from platformdirs import user_data_dir

from wifit3.observe.remote_id import summarize_remote_id
from wifit3.observe.tracker_state import TrackerState, decode_dult, decode_find_hub
from wifit3.persist.private_files import write_private_text


SCHEMA = 1
_MAX_RULES = 400
_MAX_BYTES = 256 * 1024
_TIMEOUT_S = 20
_STOCK_HOST = "raw.githubusercontent.com"
_STOCK_PREFIX = "/yadox666/wifit3-ng/"
_STOCK_URL = (
    "https://raw.githubusercontent.com/yadox666/wifit3-ng/"
    "yadox-enhanced/src/wifit3/observe/stock_signatures.json"
)
_DECODERS = frozenset({"dult", "find_hub", "remote_id"})
_MATCH_KEYS = frozenset({
    "service_data_uuid",
    "service_uuid",
    "service_data_prefix",
    "company_id",
    "manufacturer_prefix",
    "ssid_contains",
    "name_contains",
    "vendor_oui",
})
_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

_lock = threading.RLock()
_rules: tuple["Rule", ...] = ()
_loaded = False


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    category: str
    label: str
    watch: bool
    decode: str
    match: dict[str, str | int]
    user: bool


@dataclass(frozen=True, slots=True)
class PackStatus:
    ok: bool
    message: str
    count: int = 0


@dataclass(frozen=True, slots=True)
class BluetoothNotes:
    category: str = ""
    protocol_type: str = ""
    source: str = ""
    confidence: str = ""
    detail: str = ""
    prefer: bool = False
    alert: bool = False


@dataclass(frozen=True, slots=True)
class WifiNotes:
    label: str = ""
    alert: bool = False


def stock_path() -> Path:
    """On-disk stock pack, under the OS user data directory."""
    return Path(user_data_dir("wifit3", appauthor=False)) / "signatures-stock.json"


def user_path() -> Path:
    """On-disk user pack, under the OS user data directory."""
    return Path(user_data_dir("wifit3", appauthor=False)) / "signatures-user.json"


def ensure_stock() -> PackStatus:
    """Copy the bundled stock pack into the user data directory when it is missing."""
    path = stock_path()
    if not path.is_file():
        try:
            write_private_text(path, _bundled_text())
        except (OSError, ValueError) as exc:
            _install(())
            return PackStatus(False, f"Could not seed signature pack: {exc.__class__.__name__}")
    return reload_rules()


def reload_rules() -> PackStatus:
    """Read the stock and user packs into the in-memory rule list."""
    stock, stock_error = _read_file(stock_path(), user=False)
    user, user_error = _read_file(user_path(), user=True)
    _install((*user, *stock))
    if stock_error and user_error:
        return PackStatus(False, stock_error, len(user) + len(stock))
    if stock_error:
        return PackStatus(True, stock_error, len(_rules))
    if user_error:
        return PackStatus(True, user_error, len(_rules))
    return PackStatus(True, f"{len(_rules)} signature rules", len(_rules))


def refresh_stock(*, fetch=None) -> PackStatus:
    """Replace the stock pack from the pinned GitHub URL. User rules stay put."""
    fetch = _download if fetch is None else fetch
    try:
        raw = fetch(_STOCK_URL)
        text = _decode_download(raw)
        rules = parse_pack(text, user=False)
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return PackStatus(False, f"Signature refresh failed ({exc.__class__.__name__})")
    try:
        write_private_text(stock_path(), text)
    except OSError as exc:
        return PackStatus(False, f"Could not store signature pack: {exc.__class__.__name__}")
    status = reload_rules()
    return PackStatus(status.ok, f"stock catalog updated, {len(rules)} rules", status.count)


def import_user_pack(path: Path) -> PackStatus:
    """Replace the user pack from a JSON file the operator chose."""
    try:
        text = Path(path).read_text(encoding="utf-8")
        if len(text.encode("utf-8")) > _MAX_BYTES:
            raise ValueError("file is too large")
        rules = parse_pack(text, user=True)
        write_private_text(user_path(), text)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return PackStatus(False, f"Could not import signatures: {exc}")
    status = reload_rules()
    return PackStatus(True, f"imported {len(rules)} user rules", status.count)


def export_user_pack(directory: Path) -> PackStatus:
    """Write the user pack into ``directory``. An empty pack is a valid export."""
    source = user_path()
    try:
        text = source.read_text(encoding="utf-8") if source.is_file() else _empty_pack()
        parse_pack(text, user=True)
        destination = Path(directory) / "signatures-user.json"
        write_private_text(destination, text if text.endswith("\n") else text + "\n")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return PackStatus(False, f"Could not export signatures: {exc}")
    return PackStatus(True, str(destination))


def describe_bluetooth(
    manufacturer_data: Mapping[int, bytes] | None,
    service_data: Mapping[str, bytes] | None,
    service_uuids: tuple[str, ...] | list[str] = (),
    *,
    name: str = "",
) -> BluetoothNotes:
    """Family, state, and watch flag for one BLE advertisement."""
    manufacturers = manufacturer_data or {}
    services = service_data or {}
    matched = [
        rule for rule in _current_rules()
        if _rule_matches_bluetooth(rule, manufacturers, services, service_uuids, name)
    ]
    decoded = _decode_bluetooth(services)
    if decoded is None:
        for rule in matched:
            decoded = _decode_named(rule, services)
            if decoded is not None:
                break
    matched_rule = matched[0] if matched else None
    if decoded is not None:
        return BluetoothNotes(
            category=decoded.category,
            protocol_type=decoded.protocol_type,
            source=decoded.source,
            confidence=decoded.confidence,
            detail=decoded.detail,
            prefer=True,
            alert=decoded.alert,
        )
    if matched_rule is None or not matched_rule.label:
        return BluetoothNotes()
    return BluetoothNotes(
        category=matched_rule.category or "Other",
        protocol_type=matched_rule.label,
        source="User signature" if matched_rule.user else "Signature pack",
        confidence="medium",
        detail="",
        prefer=False,
        alert=matched_rule.watch,
    )


def describe_wifi(ssid: str | None, vendor_ouis: set[str] | frozenset[str]) -> WifiNotes:
    """Label and watch flag for one access point from SSID and vendor OUIs."""
    matched = [
        rule for rule in _current_rules()
        if _rule_matches_wifi(rule, ssid or "", vendor_ouis)
    ]
    if not matched:
        return WifiNotes()
    rule = matched[0]
    return WifiNotes(label=rule.label, alert=rule.watch)


def parse_pack(text: str, *, user: bool) -> tuple[Rule, ...]:
    """Parse one signature document. Unknown match keys drop that rule only."""
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("signature pack is too large")
    document = json.loads(text)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError("unsupported signature schema")
    raw_rules = document.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("signature rules must be a list")
    if len(raw_rules) > _MAX_RULES:
        raise ValueError("too many signature rules")
    rules: list[Rule] = []
    for raw in raw_rules:
        rule = _parse_rule(raw, user=user)
        if rule is not None:
            rules.append(rule)
    return tuple(rules)


def _decode_named(rule: Rule, service_data: Mapping[str, bytes]) -> TrackerState | None:
    uuid = rule.match.get("service_data_uuid")
    if not isinstance(uuid, str) or not rule.decode:
        return None
    payload = _service_payload(service_data, _compact_uuid(uuid))
    if payload is None:
        return None
    if rule.decode == "dult":
        return decode_dult(payload)
    if rule.decode == "find_hub":
        return decode_find_hub(payload)
    report = summarize_remote_id(payload)
    if report is None:
        return None
    return TrackerState(
        category="Drone",
        protocol_type=report.protocol_type,
        detail=report.summary,
        alert=report.alert,
        source="Remote ID advertisement",
    )


def _decode_bluetooth(service_data: Mapping[str, bytes]) -> TrackerState | None:
    dult = decode_dult(_service_payload(service_data, "fcb2") or b"")
    if dult is not None:
        return dult
    find_hub = decode_find_hub(_service_payload(service_data, "feaa") or b"")
    if find_hub is not None:
        return find_hub
    remote = summarize_remote_id(_service_payload(service_data, "fffa") or b"")
    if remote is None:
        return None
    return TrackerState(
        category="Drone",
        protocol_type=remote.protocol_type,
        detail=remote.summary,
        alert=remote.alert,
        source="Remote ID advertisement",
    )


def _rule_matches_bluetooth(
    rule: Rule,
    manufacturer_data: Mapping[int, bytes],
    service_data: Mapping[str, bytes],
    service_uuids,
    name: str,
) -> bool:
    match = rule.match
    if not match or "ssid_contains" in match or "vendor_oui" in match:
        return False
    if not any(key in match for key in (
        "service_data_uuid", "service_uuid", "company_id", "name_contains",
    )):
        return False
    service_uuid = match.get("service_data_uuid")
    if isinstance(service_uuid, str):
        payload = _service_payload(service_data, _compact_uuid(service_uuid))
        if payload is None:
            return False
        prefix = match.get("service_data_prefix")
        if isinstance(prefix, str) and not payload.startswith(bytes.fromhex(prefix)):
            return False
    advertised = match.get("service_uuid")
    if isinstance(advertised, str):
        wanted = _compact_uuid(advertised)
        if wanted not in {_compact_uuid(item) for item in service_uuids}:
            return False
    company_id = match.get("company_id")
    if isinstance(company_id, int):
        payload = manufacturer_data.get(company_id)
        if payload is None:
            return False
        prefix = match.get("manufacturer_prefix")
        if isinstance(prefix, str) and not payload.startswith(bytes.fromhex(prefix)):
            return False
    elif "manufacturer_prefix" in match:
        return False
    contained = match.get("name_contains")
    if isinstance(contained, str) and contained.casefold() not in name.casefold():
        return False
    return True


def _rule_matches_wifi(rule: Rule, ssid: str, vendor_ouis: set[str] | frozenset[str]) -> bool:
    match = rule.match
    if not match:
        return False
    contained = match.get("ssid_contains")
    oui = match.get("vendor_oui")
    if not isinstance(contained, str) and not isinstance(oui, str):
        return False
    if isinstance(contained, str) and contained.casefold() not in ssid.casefold():
        return False
    if isinstance(oui, str) and oui.upper() not in {item.upper() for item in vendor_ouis}:
        return False
    return True


def _parse_rule(raw: object, *, user: bool) -> Rule | None:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id")
    label = raw.get("label")
    match = raw.get("match")
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 64:
        return None
    if not isinstance(label, str) or not label.strip() or len(label) > 80:
        return None
    if not isinstance(match, dict) or any(key not in _MATCH_KEYS for key in match):
        return None
    decode = raw.get("decode", "")
    if not isinstance(decode, str) or (decode and decode not in _DECODERS):
        decode = ""
    category = raw.get("class", "Other")
    if not isinstance(category, str) or len(category) > 32:
        category = "Other"
    cleaned = _clean_match(match)
    if cleaned is None:
        return None
    return Rule(
        id=identifier.strip(),
        category=category.strip() or "Other",
        label=label.strip(),
        watch=raw.get("watch") is True,
        decode=decode,
        match=cleaned,
        user=user,
    )


def _clean_match(match: dict) -> dict[str, str | int] | None:
    cleaned: dict[str, str | int] = {}
    for key, value in match.items():
        if key in {"company_id"}:
            if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
                return None
            cleaned[key] = value
            continue
        if not isinstance(value, str) or not value.strip() or len(value) > 64:
            return None
        text = value.strip()
        if key in {"service_data_prefix", "manufacturer_prefix"}:
            try:
                bytes.fromhex(text)
            except ValueError:
                return None
            if len(text) % 2:
                return None
        if key in {"service_data_uuid", "service_uuid"}:
            text = _compact_uuid(text)
        if key == "vendor_oui":
            text = text.upper()
        cleaned[key] = text
    return cleaned or None


def _service_payload(service_data: Mapping[str, bytes], uuid16: str) -> bytes | None:
    for key, value in service_data.items():
        if _compact_uuid(key) == uuid16 and isinstance(value, (bytes, bytearray)):
            return bytes(value)
    return None


def _compact_uuid(service_uuid: str) -> str:
    lowered = service_uuid.strip().casefold()
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(_UUID_SUFFIX):
        return lowered[4:8]
    return lowered


def _current_rules() -> tuple[Rule, ...]:
    global _loaded
    with _lock:
        if not _loaded:
            _loaded = True
            stock, _stock_error = _read_file(stock_path(), user=False)
            user, _user_error = _read_file(user_path(), user=True)
            _install((*user, *stock))
        return _rules


def _install(rules: tuple[Rule, ...]) -> None:
    global _rules, _loaded
    with _lock:
        _rules = rules
        _loaded = True


def _read_file(path: Path, *, user: bool) -> tuple[tuple[Rule, ...], str]:
    if not path.is_file():
        return (), ""
    try:
        return parse_pack(path.read_text(encoding="utf-8"), user=user), ""
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return (), f"Ignored unreadable signature file {path.name}"


def _bundled_text() -> str:
    path = Path(__file__).with_name("stock_signatures.json")
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return files("wifit3.observe").joinpath("stock_signatures.json").read_text(encoding="utf-8")


def _empty_pack() -> str:
    return json.dumps({"schema": SCHEMA, "rules": []}, indent=2) + "\n"


def _decode_download(data: bytes) -> str:
    if len(data) > _MAX_BYTES:
        raise ValueError("signature download exceeded size limit")
    return data.decode("utf-8")


class _HostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlparse(newurl)
        if parts.scheme != "https" or parts.hostname != _STOCK_HOST:
            raise urllib.error.URLError("redirect left the signature host")
        if not parts.path.startswith(_STOCK_PREFIX) or not parts.path.endswith(
            "stock_signatures.json",
        ):
            raise urllib.error.URLError("redirect left the signature pack")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": "wifit3",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(_HostRedirect())
    chunks: list[bytes] = []
    total = 0
    with opener.open(request, timeout=_TIMEOUT_S) as response:
        while True:
            block = response.read(64 * 1024)
            if not block:
                break
            total += len(block)
            if total > _MAX_BYTES:
                raise ValueError("signature download exceeded size limit")
            chunks.append(block)
    return b"".join(chunks)
