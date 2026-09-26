#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -d .venv ]]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

if [[ ! -x .venv/bin/wifit3 ]]; then
  echo "Installing wifit3..."
  python -m pip install -U pip
  python -m pip install -e .
fi

exec wifit3 "$@"
