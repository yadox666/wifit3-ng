#!/usr/bin/env python3
"""Remove USB Bluetooth lab surface from files copied to the public tree."""
from __future__ import annotations

import re
import sys
from pathlib import Path

MANAGER_DROP_METHODS = frozenset({
    "_os_ble_lab_gatt",
    "run_usb_lab_suite",
    "run_usb_pairing_analysis",
    "_classic_to_le_pairing_fallback",
    "_pairing_os_ble_gatt_fallback",
    "_log_gatt_inventory",
    "run_usb_classic_hello",
    "fuzz_usb_classic_l2cap",
    "run_usb_speaker_lab",
    "_patch_usb_lab_bias_narrative_check",
})

MANAGER_DROP_PROPS = frozenset({
    "usb_lab_classic_summary",
    "usb_lab_ble_summary",
    "usb_lab_inspection",
    "usb_lab_checks",
    "usb_lab_pairing_summary",
    "usb_lab_pairing_checks",
    "usb_lab_echo_result",
    "usb_lab_speaker_result",
    "usb_lab_speaker_checks",
    "usb_lab_bias_summary",
    "usb_lab_last_debug_dir",
    "usb_lab_last_run_log",
})


def _drop_class_members(text: str, names: frozenset[str]) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^    (async )?def (\w+)\(", line)
        if m and m.group(2) in names:
            i += 1
            while i < len(lines) and not (
                lines[i].startswith("    def ")
                or lines[i].startswith("    async def ")
                or lines[i].startswith("class ")
            ):
                i += 1
            continue
        m2 = re.match(r"^    @property\n", line)
        if m2 and i + 1 < len(lines):
            m3 = re.match(r"^    def (\w+)\(", lines[i + 1])
            if m3 and m3.group(1) in names:
                i += 2
                while i < len(lines) and not (
                    lines[i].startswith("    def ")
                    or lines[i].startswith("    async def ")
                    or lines[i].startswith("    @")
                    or lines[i].startswith("class ")
                ):
                    i += 1
                continue
        out.append(line)
        i += 1
    return "".join(out)


def strip_manager(path: Path) -> None:
    text = path.read_text()
    text = text.replace("from wifit3.bluetooth.lab.run_log import OnRunLogLine\n", "")
    text = _drop_class_members(text, MANAGER_DROP_METHODS)
    text = _drop_class_members(text, MANAGER_DROP_PROPS)
    text = re.sub(
        r"    def usb_lab_available\(self\) -> bool:\n(?:        .*\n)+?(?=    def |    @|class |\Z)",
        "    def usb_lab_available(self) -> bool:\n        return False\n\n",
        text,
        count=1,
    )
    # Drop lab instance fields in __init__
    text = re.sub(
        r"\n        self\._usb_lab_[^\n]+\n",
        "\n",
        text,
    )
    path.write_text(text)


def strip_scanner_ui(path: Path) -> None:
    text = path.read_text()
    text = re.sub(r"from wifit3\.ui\.screens\.bluetooth_usb_lab import[^\n]+\n", "", text)
    text = re.sub(
        r"\n        Binding\(\"(?:shift\+l|L|ctrl\+shift\+l)\", \"open_usb_lab\"[^\n]*\n",
        "\n",
        text,
    )
    text = re.sub(
        r"\n    def action_open_usb_lab\(self\) -> None:.*?(?=\n    def |\nclass |\Z)",
        "\n",
        text,
        flags=re.DOTALL,
    )
    path.write_text(text)


def strip_manager_tests(path: Path) -> None:
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(("async def test_", "def test_")):
            block = [line]
            i += 1
            while i < len(lines) and not (
                lines[i].startswith("async def test_")
                or lines[i].startswith("def test_")
                or (lines[i].startswith("def ") and not lines[i].startswith("def test_"))
                or lines[i].startswith("class ")
            ):
                block.append(lines[i])
                i += 1
            body = "".join(block)
            if any(
                needle in body
                for needle in (
                    "bluetooth.lab",
                    "run_usb_lab",
                    "_classic_to_le_pairing_fallback",
                    "_pairing_os_ble_gatt_fallback",
                )
            ):
                continue
            out.extend(block)
            continue
        out.append(line)
        i += 1
    path.write_text("".join(out))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: strip_bt_lab_for_public.py <public-repo-root>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    strip_manager(root / "src/wifit3/bluetooth/manager.py")
    test_manager = root / "tests/bluetooth/test_manager.py"
    if test_manager.is_file():
        strip_manager_tests(test_manager)
    for rel in (
        "src/wifit3/ui/screens/bluetooth_scanner.py",
        "src/wifit3/ui/screens/bluetooth_focus.py",
        "src/wifit3/ui/screens/bluetooth_classic_focus.py",
    ):
        p = root / rel
        if p.is_file():
            strip_scanner_ui(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
