#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -d .venv ]]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

INSTALL_STAMP=".venv/.wifit3-install-stamp"
needs_install=0
if ! .venv/bin/python -c '
import pathlib
import wifit3

expected = pathlib.Path.cwd() / "src" / "wifit3"
installed = pathlib.Path(wifit3.__file__).resolve().parent
raise SystemExit(installed != expected.resolve())
' 2>/dev/null; then
  needs_install=1
elif [[ ! -f "$INSTALL_STAMP" ]] || [[ pyproject.toml -nt "$INSTALL_STAMP" ]]; then
  needs_install=1
fi
if [[ "$needs_install" -eq 1 ]]; then
  echo "Installing wifit3..."
  .venv/bin/python -m pip install -U pip
  .venv/bin/python -m pip install -e .
  touch "$INSTALL_STAMP"
fi

exec .venv/bin/python -m wifit3 "$@"
