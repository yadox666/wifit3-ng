"""In-memory index over captures/ plus the single write path for capture
artifacts. Loaded once at startup and refreshed on each save, so reads never
re-scan the directory. Wraps persist.save + persist.capture_history."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist import save
from wifit3.persist.capture_history import load_capture_index, summarize
from wifit3.persist.common import LEGACY_CAPTURE_RE, bssid_to_dashed, parse_hc22000, safe_ssid
from wifit3.persist.config import Config
from wifit3.persist.private_files import ensure_private_directory, harden_private_file
from wifit3.persist.save import SaveResult
from wifit3.vault.manager import JobManager

if TYPE_CHECKING:
    from wifit3.models import AccessPoint

logger = logging.getLogger(__name__)


def _open_in_file_manager(path: Path) -> None:
    if sys.platform.startswith("win"):
        import os
        os.startfile(path)                                        # noqa: S606 (Windows only)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class Vault:
    """Caches the on-disk capture index (from Config.captures_dir) and is the
    backend interface for querying/deleting capture files.
    """

    # Capture-kind -> human label, in display order. The one place these map.
    _KIND_LABELS = {
        CaptureType.HS: "Handshake",
        CaptureType.PMKID: "PMKID",
        CaptureType.WEP: "WEP Key",
        CaptureType.WPS_PIN: "WPS PIN",
        CaptureType.WPS_PBC: "WPS PBC",
        CaptureType.WPA_PSK: "WPA PSK",
        CaptureType.ENTERPRISE: "Enterprise report",
    }

    _PSK_TYPES = (CaptureType.WPS_PIN, CaptureType.WPS_PBC, CaptureType.WPA_PSK)

    def __init__(self) -> None:
        self._index: Dict[str, List[PersistedCapture]] = {}
        self.errors: list[str] = []                       # surfaced as toasts by the app on mount
        try:
            self.refresh()
        except Exception as exc:
            logger.exception("Vault: failed to load the capture index")
            self._index = {}
            self.errors.append(f"Failed to load captures: {exc}")
        self.manager = JobManager(self)
        try:
            self.manager.reconcile_on_startup()
        except Exception as exc:
            logger.exception("Vault: job reconciliation failed on startup")
            self.errors.append(f"Failed to reconcile jobs: {exc}")

    def refresh(self) -> None:
        """Re-scan Config.captures_dir into the cache."""
        self._index = load_capture_index()

    # ----- reads -----

    def persisted(self, bssid: str) -> List[PersistedCapture]:
        """This AP's saved captures, newest-first (empty if none)."""
        return self._index.get(bssid, [])

    def all_captures(self) -> List[PersistedCapture]:
        """Every saved capture across all APs, unordered (callers sort as needed)."""
        return [c for caps in self._index.values() for c in caps]

    def capture_payload(self, capture: PersistedCapture) -> str:
        """Copyable text for a capture: its stored value (WEP/WPS), else the file's
        own contents (HS/PMKID hashlines). Empty string if unreadable."""
        if capture.value is not None:
            return capture.value
        try:
            return Path(capture.path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""

    def summary(self) -> Optional[str]:
        """One-line count of every saved capture, e.g. '3 handshakes, 1 WEP key',
        or None when nothing is saved."""
        hs, pmkid, wep, psk = summarize(self._index)
        parts = []
        if hs:
            parts.append(f"{hs} handshake{'s' * (hs != 1)}")
        if pmkid:
            parts.append(f"{pmkid} PMKID{'s' * (pmkid != 1)}")
        if wep:
            parts.append(f"{wep} WEP key{'s' * (wep != 1)}")
        if psk:
            parts.append(f"{psk} PSK{'s' * (psk != 1)}")
        return ", ".join(parts) or None

    def detailed_summary(self, ap: "AccessPoint") -> dict[str, tuple[PersistedCapture, int]]:
        """Per-kind rollup for the Focus 'Existing captures' panel:
        ``{human label: (newest_capture, count)}``, absent kinds omitted, kind order."""
        caps = self.persisted(ap.bssid)
        result: dict[str, tuple[PersistedCapture, int]] = {}
        for kind, label in self._KIND_LABELS.items():
            matching = [c for c in caps if c.type == kind]
            if matching:
                result[label] = (max(matching, key=lambda c: c.timestamp), len(matching))
        return result

    def known_psk(self, ap: "AccessPoint") -> Optional[str]:
        """Return a usable credential for an AP.

        Session and exact-BSSID credentials take precedence. If neither exists,
        reuse one unambiguous persisted credential from the exact same SSID.
        SSIDs are case-sensitive octet strings; hidden/unknown SSIDs never
        inherit credentials. Conflicting credentials for one SSID are
        deliberately rejected rather than guessed.
        """
        session_psk = ap.wps_pbc_psk or ap.wps_pin_psk
        if session_psk:
            return session_psk
        direct = next((
            capture.value
            for capture in self.persisted(ap.bssid)
            if capture.type in self._PSK_TYPES and capture.value
        ), None)
        if direct:
            return direct
        if not ap.ssid:
            return None
        ssid_credentials = {
            capture.value
            for captures in self._index.values()
            for capture in captures
            if (
                capture.type in self._PSK_TYPES
                and capture.value
                and capture.ssid == ap.ssid
            )
        }
        if len(ssid_credentials) == 1:
            return next(iter(ssid_credentials))
        return None

    def has_psk(self, ap: "AccessPoint") -> bool:
        """True once we hold this AP's passphrase (see known_psk)."""
        return self.known_psk(ap) is not None

    def has_handshake(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.HS)

    def has_pmkid(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.PMKID)

    def has_wep_key(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.WEP)

    def has_wps_psk(self, ap: "AccessPoint") -> bool:
        return any(c.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC)
                   for c in self.persisted(ap.bssid))

    def wps_capture(self, ap: "AccessPoint") -> Optional[PersistedCapture]:
        """Newest saved WPS credential for this AP (PIN- or PBC-derived), or None."""
        return next((c for c in self.persisted(ap.bssid)
                     if c.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC) and c.value), None)

    def _has(self, bssid: str, kind: CaptureType) -> bool:
        return any(c.type == kind for c in self.persisted(bssid))

    # ----- writes (persist to disk, then fold into the cache) -----

    def save_handshake(self, ap: "AccessPoint", client_mac: str) -> Optional[SaveResult]:
        result = save.save_handshake(ap, client_mac)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.HS, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid))
        return result

    def save_pmkid(self, ap: "AccessPoint", client_mac: str) -> Optional[SaveResult]:
        result = save.save_pmkid(ap, client_mac)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.PMKID, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid))
        return result

    def save_wep_key(self, ap: "AccessPoint", key: bytes) -> Optional[SaveResult]:
        result = save.save_wep_key(ap, key)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WEP, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, value=key.hex(), ssid=ap.ssid))
        return result

    def save_wps_pin(self, ap: "AccessPoint", pin: str, psk: str) -> Optional[SaveResult]:
        result = save.save_wps_pin(ap, pin, psk)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WPS_PIN, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, value=psk, pin=pin, ssid=ap.ssid))
        return result

    def save_wps_pbc(self, ap: "AccessPoint", psk: str) -> Optional[SaveResult]:
        result = save.save_wps_pbc(ap, psk)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WPS_PBC, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, value=psk, ssid=ap.ssid))
        return result

    def save_wpa_psk(self, ap: "AccessPoint", psk: str) -> Optional[SaveResult]:
        result = save.save_wpa_psk(ap, psk)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WPA_PSK, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, value=psk, ssid=ap.ssid))
        return result

    def save_mschapv2(
        self,
        ap: "AccessPoint",
        capture,
        *,
        lab_bssid: str | None = None,
    ) -> Optional[save.EapLabSaveResult]:
        result = save.save_mschapv2(ap, capture, lab_bssid=lab_bssid)
        if result is None:
            return None
        bssid = lab_bssid or ap.bssid
        ts = int(time.time())
        if result.mschapv2.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0,
                PersistedCapture(
                    type=CaptureType.MSCHAPV2,
                    timestamp=ts,
                    path=str(result.mschapv2.path),
                    bssid=bssid,
                    ssid=ap.ssid,
                    value=capture.username,
                ),
            )
        if result.netntlmv2.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0,
                PersistedCapture(
                    type=CaptureType.NETNTLMV2,
                    timestamp=ts,
                    path=str(result.netntlmv2.path),
                    bssid=bssid,
                    ssid=ap.ssid,
                    value=capture.username,
                ),
            )
        return result

    def save_enterprise_report(self, ap: "AccessPoint") -> Optional[SaveResult]:
        result = save.save_enterprise_report(ap)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(
                    type=CaptureType.ENTERPRISE,
                    timestamp=int(time.time()),
                    path=str(result.path),
                    bssid=ap.bssid,
                    ssid=ap.ssid,
                ),
            )
        return result

    def save_eap_lab_report(
        self,
        ap: "AccessPoint",
        *,
        lab_bssid: str,
        launch,
        clients,
        campaign_result: str,
    ) -> Optional[SaveResult]:
        result = save.save_eap_lab_report(
            ap,
            lab_bssid=lab_bssid,
            launch=launch,
            clients=clients,
            campaign_result=campaign_result,
        )
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0,
                PersistedCapture(
                    type=CaptureType.ENTERPRISE,
                    timestamp=int(time.time()),
                    path=str(result.path),
                    bssid=ap.bssid,
                    ssid=ap.ssid,
                    value="EAP lab client assessment",
                ),
            )
        return result

    def validate_capture(self, capture: PersistedCapture) -> tuple[bool, str]:
        """Validate a saved artifact's local structure without transmitting or exposing secrets."""
        path = Path(capture.path)
        try:
            if path.suffix.lower() == ".hc22000":
                entries = [
                    parse_hc22000(line)
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                ]
                valid = [entry for entry in entries if entry is not None]
                return (
                    (True, f"{len(valid)} valid Hashcat record{'s' if len(valid) != 1 else ''}")
                    if valid else (False, "No valid Hashcat 22000 records")
                )
            if path.suffix.lower() == ".pcap":
                with path.open("rb") as stream:
                    header = stream.read(4)
                magics = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
                return (
                    (True, "Valid PCAP header")
                    if header in magics else (False, "Invalid or truncated PCAP header")
                )
            if capture.type == CaptureType.MSCHAPV2:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
                valid = text.startswith("$MSCHAPv2$") or ":$MSCHAPv2$" in text
                return (
                    (True, "Valid Hashcat MS-CHAPv2 line")
                    if valid else (False, "Invalid MS-CHAPv2 hash line")
                )
            if capture.type == CaptureType.NETNTLMV2:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
                valid = text.count(":") >= 4 and "::" in text
                return (
                    (True, "Valid Hashcat NetNTLMv2-SSP line")
                    if valid else (False, "Invalid NetNTLMv2 hash line")
                )
            if capture.type == CaptureType.ENTERPRISE:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or payload.get("schema_version") != 1:
                    return False, "Unsupported Enterprise report schema"
                if not isinstance(payload.get("enterprise"), dict):
                    return False, "Enterprise report has no profile"
                return True, "Valid sanitized Enterprise report"
            if capture.type == CaptureType.WEP:
                value = capture.value or ""
                return (
                    (True, f"Valid {len(value) * 4}-bit WEP key")
                    if len(value) in {10, 26, 32, 58} and all(char in "0123456789abcdefABCDEF" for char in value)
                    else (False, "Invalid WEP key encoding")
                )
            if capture.type in self._PSK_TYPES:
                value = capture.value or ""
                valid = 8 <= len(value) <= 63 or (
                    len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)
                )
                return (True, "Credential structure is valid") if valid else (False, "Invalid WPA credential length")
        except (OSError, ValueError) as exc:
            return False, str(exc)
        return False, "Unsupported capture format"

    # ----- filesystem ops (the screen goes through these, never touches disk) -----

    def delete_capture(self, capture: PersistedCapture) -> None:
        """Delete a capture's file and drop every cache entry backed by it (an
        aggregate .hc22000 backs both an HS and a PMKID entry)."""
        Path(capture.path).unlink(missing_ok=True)
        for bssid in list(self._index):
            remaining = [c for c in self._index[bssid] if c.path != capture.path]
            if remaining:
                self._index[bssid] = remaining
            else:
                del self._index[bssid]

    def zip_captures(self, captures: List[PersistedCapture],
                     save_as: Optional[Path] = None) -> Optional[Path]:
        """Zip the given captures' files (deduped) into ``save_as``, defaulting to a
        timestamped archive beside captures/. None if none of the files exist."""
        paths: List[Path] = []
        seen: set[str] = set()
        for c in captures:
            p = Path(c.path)
            if p.is_file() and str(p) not in seen:
                seen.add(str(p))
                paths.append(p)
        if not paths:
            return None
        if save_as is None:
            save_as = Path(Config.captures_dir).parent / f"wifit3_captures_{int(time.time())}.zip"
        if not save_as.parent.exists():
            ensure_private_directory(save_as.parent)
        with zipfile.ZipFile(save_as, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                zf.write(p, arcname=p.name)
        harden_private_file(save_as)
        return save_as

    def open_directory(self) -> None:
        """Reveal captures/ in the OS file manager."""
        _open_in_file_manager(Path(Config.captures_dir))

    # ----- legacy .hc22000 consolidation (temporary: pre-aggregate installs) ---

    def _legacy_hc_files(self) -> List[Path]:
        """Pre-aggregate per-capture .hc22000 files still on disk (one file per
        capture, vs today's one aggregate file per AP)."""
        root = Path(Config.captures_dir)
        if not root.is_dir():
            return []
        return [p for p in root.iterdir()
                if p.is_file() and (m := LEGACY_CAPTURE_RE.match(p.name))
                and m.group("ext") == "hc22000"]

    def legacy_hc_file_count(self) -> int:
        """Number of legacy per-capture .hc22000 files that could be consolidated."""
        return len(self._legacy_hc_files())

    def legacy_hc_unique_count(self) -> int:
        """Distinct SSID+BSSID the legacy files would collapse into (one file each)."""
        return len({f"{safe_ssid(m.group('ssid'))}_{bssid_to_dashed(m.group('bssid'))}"
                    for p in self._legacy_hc_files()
                    if (m := LEGACY_CAPTURE_RE.match(p.name))})

    def consolidate_legacy_hc_files(self) -> tuple[int, int]:
        """Merge legacy per-capture .hc22000 files into one per AP, then refresh the
        cache. Returns (migrated_ap_count, deleted_file_count)."""
        migrated, deleted = save.consolidate_hc_files(Path(Config.captures_dir))
        self.refresh()
        return migrated, deleted
