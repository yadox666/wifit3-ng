#!/usr/bin/env python3
"""Copy reviewed private changes onto wifit3-ng-public with boundary exclusions."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

# Paths relative to repo root — never overwrite from private (regdom-change).
REGDOM_KEEP_PUBLIC = frozenset(
    {
        "src/wifit3/wlan/regulatory.py",
        "src/wifit3/wlan/regdb_db.txt",
        "src/wifit3/persist/config.py",
        "src/wifit3/ui/pref.py",
        "src/wifit3/wlan/interface.py",
        "tests/wlan/test_regulatory.py",
        "tests/test_config.py",
        "tests/ui/test_pref.py",
    }
)

REGDOM_CHIP_PREFIXES = (
    "src/wifit3/chips/ar9271_v2/",
    "src/wifit3/chips/driver.py",
    "src/wifit3/chips/mt76x2u/",
    "src/wifit3/chips/mt7921au/",
    "src/wifit3/chips/mt7925au/",
    "src/wifit3/chips/rtl8821cu_dkms/",
    "src/wifit3/chips/rtw88_8814au/",
)

# PortalTwin stack is entangled; keep public versions.
PORTAL_KEEP_PUBLIC = frozenset(
    {
        "src/wifit3/ui/screens/focus_v2/screen.py",
        "src/wifit3/ui/screens/focus_v2/campaign_controls.py",
        "src/wifit3/dot11/portal_server.py",
        "src/wifit3/dot11/connectivity.py",
        "src/wifit3/dot11/dhcp.py",
    }
)

SKIP_SUBSTRINGS = (
    "bluetooth/lab/",
    "bluetooth_usb_lab",
    "/portal_twin",
    "portal_twin_modal",
    "captive_portal",
    "/portal_",
    "eviltwin/templates/",
    "PortalTwin",
    "rf_lab",
    "rf_lab_profiles",
    "ap_jam",
    "hackrf_endpoint",
    "lab_tx",
    "rf_lab_preview",
    "hackrf_lab_tx",
    "portal_tls/",
    "__pycache__",
    ".DS_Store",
)

SKIP_TEST_RE = re.compile(
    r"(^tests/.*/test_(lab_|usb_lab|rf_lab|portal)|test_lab_tx|test_captive_portal|test_portal_)"
)


def should_skip(rel: str) -> bool:
    if rel in REGDOM_KEEP_PUBLIC or rel in PORTAL_KEEP_PUBLIC:
        return True
    for prefix in REGDOM_CHIP_PREFIXES:
        if rel.startswith(prefix):
            return True
    for part in SKIP_SUBSTRINGS:
        if part in rel:
            return True
    if SKIP_TEST_RE.search(rel):
        return True
    if rel.startswith("tests/bluetooth/test_bias_"):
        return True
    if rel in (
        "tests/bluetooth/test_narrative.py",
        "tests/bluetooth/test_speaker_posture.py",
        "tests/bluetooth/test_lmp_features.py",
    ):
        return True
    if rel.startswith("assets/PortalTwin"):
        return True
    return False


def git_diff_names(private_root: Path, public_ref: str) -> list[str]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", public_ref, "HEAD"],
        cwd=private_root,
        text=True,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def copy_tree(private_root: Path, public_root: Path, rel: str) -> None:
    src = private_root / rel
    dest = public_root / rel
    if src.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def main() -> int:
    private_root = Path(__file__).resolve().parent.parent
    public_root = Path(
        sys.argv[1] if len(sys.argv) > 1 else "/Users/yhansen/Downloads/To_Test/wifit3-ng-public"
    )
    public_ref = sys.argv[2] if len(sys.argv) > 2 else "public/yadox-enhanced"

    if not (public_root / ".git").is_dir():
        print(f"missing public repo: {public_root}", file=sys.stderr)
        return 1

    names = git_diff_names(private_root, public_ref)
    copied: list[str] = []
    skipped: list[str] = []
    for rel in names:
        if should_skip(rel):
            skipped.append(rel)
            continue
        src = private_root / rel
        if not src.exists():
            skipped.append(rel)
            continue
        if not (
            rel.startswith("src/")
            or rel.startswith("tests/")
            or rel in ("pyproject.toml", "README.md", "CHANGELOG.md", "start.sh")
            or rel.startswith("scripts/")
        ):
            skipped.append(rel)
            continue
        copy_tree(private_root, public_root, rel)
        copied.append(rel)

    # Bluetooth identifier JSON bundle (may match public ref already).
    data_dir = private_root / "src/wifit3/bluetooth/data"
    if data_dir.is_dir():
        dest = public_root / "src/wifit3/bluetooth/data"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(data_dir, dest)
        copied.append("src/wifit3/bluetooth/data/")

    # gatt_att / usb_claim may not appear in diff vs ref but should be present.
    for extra in (
        "src/wifit3/bluetooth/gatt_att.py",
        "src/wifit3/bluetooth/usb_claim.py",
        "src/wifit3/bluetooth/usb_capabilities.py",
        "src/wifit3/bluetooth/routing.py",
        "src/wifit3/bluetooth/roles.py",
        "src/wifit3/bluetooth/sources.py",
        "src/wifit3/bluetooth/scan_modes.py",
        "src/wifit3/persist/bluetooth_bonds.py",
        "src/wifit3/ui/screens/bluetooth_picker.py",
        "src/wifit3/ui/bluetooth_detail.py",
        "src/wifit3/ui/screens/focus_v2/client_focus_screen.py",
        "tests/bluetooth/test_routing.py",
        "tests/bluetooth/test_roles.py",
        "tests/bluetooth/test_scan_modes.py",
        "tests/ui/test_bluetooth_detail.py",
        "src/wifit3/ui/screens/background_monitor_modal.py",
        "src/wifit3/observe/__init__.py",
        "src/wifit3/observe/remote_id.py",
        "src/wifit3/observe/signature_pack.py",
        "src/wifit3/observe/stock_signatures.json",
        "src/wifit3/observe/tracker_state.py",
        "src/wifit3/gps/manager.py",
    ):
        if should_skip(extra):
            continue
        src = private_root / extra
        if src.is_file():
            copy_tree(private_root, public_root, extra)
            if extra not in copied:
                copied.append(extra)

    scripts_dir = private_root / "scripts"
    for name in ("strip_bt_lab_for_public.py", "strip_regdom_for_public.py"):
        src = scripts_dir / name
        if src.is_file():
            shutil.copy2(src, public_root / "scripts" / name)

    strip_bt = scripts_dir / "strip_bt_lab_for_public.py"
    strip_regdom = scripts_dir / "strip_regdom_for_public.py"
    subprocess.run([sys.executable, str(strip_bt), str(public_root)], check=True)
    subprocess.run([sys.executable, str(strip_regdom), str(public_root)], check=True)
    strip_rf = scripts_dir / "strip_rf_lab_for_public.py"
    subprocess.run([sys.executable, str(strip_rf), str(public_root)], check=True)
    strip_tests = scripts_dir / "strip_public_tests.py"
    if strip_tests.is_file():
        subprocess.run([sys.executable, str(strip_tests), str(public_root)], check=True)

    for rel in REGDOM_KEEP_PUBLIC:
        src = public_root / ".git"
        if not src.is_dir():
            continue
        subprocess.run(
            ["git", "-C", str(public_root), "checkout", "HEAD", "--", rel],
            check=False,
        )

    patch_focus_leave = public_root / "src/wifit3/ui/screens/focus_v2/screen.py"
    if patch_focus_leave.is_file():
        text = patch_focus_leave.read_text()
        for block in (
            "        if self._network_analyzer is not None:\n"
            '            add("Passive network metadata")\n',
        ):
            text = text.replace(block, "")
        patch_focus_leave.write_text(text)

    client_focus = public_root / "src/wifit3/ui/screens/focus_v2/client_focus_screen.py"
    if client_focus.is_file():
        text = client_focus.read_text()
        block = (
            "        if self._network_analyzer is not None:\n"
            '            actions.append("Passive network metadata")\n'
        )
        text = text.replace(block, "")
        client_focus.write_text(text)

    print(f"Copied {len(copied)} paths; skipped {len(skipped)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
