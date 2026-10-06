#!/usr/bin/env python3
"""Remove user-selectable regdom UI from a public tree (world-only regulatory.py)."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def strip_device_picker(path: Path) -> None:
    text = path.read_text()
    text = re.sub(
        r"\nfrom wifit3\.wlan\.regulatory import splash_regulatory_subtitle\n",
        "\n",
        text,
        count=1,
    )
    text = re.sub(
        r"\n    def refresh_regulatory_from_array\(self, members\) -> None:.*?"
        r"\n    def _refresh_regulatory_subtitle\(self\) -> None:.*?"
        r"\n        self\.border_subtitle = splash_regulatory_subtitle\(attached\)\n\n",
        "\n",
        text,
        flags=re.DOTALL,
    )
    text = text.replace("        self._attached_for_regulatory = None\n", "")
    text = text.replace("        self._refresh_regulatory_subtitle()\n", "")
    path.write_text(text)


def strip_splash(path: Path) -> None:
    text = path.read_text()
    text = re.sub(
        r"\n        if array is not None and array\.members:\n"
        r"            self\._picker\(\)\.refresh_regulatory_from_array\(array\.members\)\n",
        "\n",
        text,
    )
    text = re.sub(
        r"\n            self\._picker\(\)\.refresh_regulatory_from_array\(array\.members\)\n",
        "\n",
        text,
    )
    text = re.sub(
        r"\n    def refresh_regulatory_subtitle\(self\) -> None:.*?"
        r"\n            picker\._refresh_regulatory_subtitle\(\)\n",
        "\n",
        text,
        flags=re.DOTALL,
    )
    text = re.sub(
        r"\n        array = getattr\(self\.app, \"array\", None\)\n"
        r"        if array is not None and array\.members:\n"
        r"            picker\.refresh_regulatory_from_array\(array\.members\)\n",
        "\n",
        text,
    )
    text = re.sub(
        r"\n            picker\.refresh_regulatory_from_array\(array\.members\)\n",
        "\n",
        text,
    )
    path.write_text(text)


def strip_app(path: Path) -> None:
    text = path.read_text()
    text = re.sub(
        r"\n    def _on_preferences_closed\(self, _result\) -> None:\n"
        r"        from wifit3\.ui\.screens\.splash import SplashView\n\n"
        r"        if isinstance\(self\.screen, SplashView\):\n"
        r"(?:            self\.screen\.refresh_regulatory_subtitle\(\)\n)?",
        "\n    def _on_preferences_closed(self, _result) -> None:\n        return\n",
        text,
    )
    path.write_text(text)


def merge_gps_enabled_config(public_config: Path, private_config: Path) -> None:
    """Add ``gps_enabled`` from private without ``wifi_regulatory_country``."""
    if not private_config.is_file():
        return
    priv = private_config.read_text()
    if "gps_enabled: bool" not in priv:
        return
    text = public_config.read_text()
    if "gps_enabled" in text:
        return
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    inserted_field = False
    inserted_load = False
    inserted_save = False
    for line in lines:
        out.append(line)
        if not inserted_field and line.strip().startswith("gps_port:"):
            out.append("    gps_enabled: bool = True\n")
            inserted_field = True
    text = "".join(out)
    if "cls.gps_enabled" not in text and "gps_enabled = bool" in priv:
        text = text.replace(
            "        cls.gps_port = str(data.get(\"gps_port\", cls.gps_port))\n",
            "        cls.gps_port = str(data.get(\"gps_port\", cls.gps_port))\n"
            "        cls.gps_enabled = bool(data.get(\"gps_enabled\", cls.gps_enabled))\n",
        )
        inserted_load = True
    if 'f"gps_enabled' not in text:
        text = text.replace(
            '            f"gps_port = {_fmt(cls.gps_port)}\\n"\n',
            '            f"gps_port = {_fmt(cls.gps_port)}\\n"\n'
            '            f"gps_enabled = {_fmt(cls.gps_enabled)}\\n"\n',
        )
        inserted_save = True
    if inserted_field or inserted_load or inserted_save:
        public_config.write_text(text)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: strip_regdom_for_public.py <public-repo-root>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    private = Path(__file__).resolve().parent.parent
    for rel in (
        "src/wifit3/ui/screens/device_picker.py",
        "src/wifit3/ui/screens/splash.py",
        "src/wifit3/ui/app.py",
    ):
        p = root / rel
        if p.is_file():
            if rel.endswith("device_picker.py"):
                strip_device_picker(p)
            elif rel.endswith("splash.py"):
                strip_splash(p)
            else:
                strip_app(p)
    merge_gps_enabled_config(
        root / "src/wifit3/persist/config.py",
        private / "src/wifit3/persist/config.py",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
