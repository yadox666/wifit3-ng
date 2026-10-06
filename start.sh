#!/usr/bin/env bash
# Usage: ./start.sh [--case] [--background] [--all] …
#   --case  prompt for scan session name and notes (default: auto-generated name)
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -d .venv ]]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

if ! .venv/bin/python -c '
import pathlib
import wifit3

expected = pathlib.Path.cwd() / "src" / "wifit3"
installed = pathlib.Path(wifit3.__file__).resolve().parent
raise SystemExit(installed != expected.resolve())
' 2>/dev/null; then
  echo "Installing wifit3..."
  .venv/bin/python -m pip install -U pip
  .venv/bin/python -m pip install -e .
fi

exec .venv/bin/python -m wifit3 "$@"
