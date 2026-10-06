#!/usr/bin/env python3
"""Sanitize tests copied to the public tree (no RF lab, BT lab, or regdom UI)."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def _drop_test_functions(text: str, needles: tuple[str, ...]) -> str:
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
            if any(n in body for n in needles):
                continue
            out.extend(block)
            continue
        out.append(line)
        i += 1
    return "".join(out)


def strip_file(path: Path) -> None:
    text = path.read_text()
    text = re.sub(
        r"from wifit3\.ui\.screens\.bluetooth_usb_lab import[^\n]+\n", "", text
    )
    for needle in ("rf-lab", "start_rf_lab", "lab_btn", "BluetoothUsbLabView", "usb_lab"):
        if needle in ("usb_lab",) and path.name != "test_manager.py":
            pass
    if path.name not in ("test_bluetooth_detail.py", "test_manager.py"):
        lines = [
            ln
            for ln in text.splitlines(keepends=True)
            if "rf-lab" not in ln and "start_rf_lab" not in ln and "lab_btn" not in ln
        ]
        text = "".join(lines)
    if path.name == "test_bluetooth_scanner.py":
        text = _drop_test_functions(text, ("usb_lab", "BluetoothUsbLabView", "shift_l"))
    if path.name == "test_bluetooth_detail.py":
        text = _drop_test_functions(text, ("usb_lab", "BluetoothUsbLabView"))
    if path.name == "test_manager.py":
        text = _drop_test_functions(text, ("test_usb_lab_available_tracks",))
    path.write_text(text)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: strip_public_tests.py <public-repo-root>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    for rel in (
        "tests/ui/test_splash_bringup.py",
        "tests/ui/test_bluetooth_scanner.py",
        "tests/ui/test_bluetooth_detail.py",
        "tests/bluetooth/test_manager.py",
    ):
        p = root / rel
        if p.is_file():
            strip_file(p)
    picker = root / "tests/ui/test_device_picker.py"
    if picker.is_file():
        picker.write_text(
            picker.read_text().replace(
                '        assert picker.border_subtitle.endswith("(reg)")\n', ""
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
