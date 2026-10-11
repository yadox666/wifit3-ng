#!/usr/bin/env bash
# Usage: ./start.sh [--case] [--background] [--all] …
#   --case  prompt for scan session name and notes (default: auto-generated name)
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(uname -s)" == Linux && "$(id -u)" -eq 0 ]]; then
  echo "Warning: do not run ./start.sh with sudo. USB adapters are used in userspace." >&2
fi

linux_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
  elif command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v yum >/dev/null 2>&1; then
    echo yum
  elif command -v pacman >/dev/null 2>&1; then
    echo pacman
  elif command -v zypper >/dev/null 2>&1; then
    echo zypper
  fi
}

linux_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  elif command -v pkexec >/dev/null 2>&1; then
    pkexec "$@"
  else
    echo "Need root to install: $*" >&2
    return 1
  fi
}

install_linux_packages() {
  local pkgs=("$@") mgr
  [[ ${#pkgs[@]} -eq 0 ]] && return 0
  mgr="$(linux_pkg_manager)"
  echo "Installing Linux packages: ${pkgs[*]}"
  case "$mgr" in
    apt)
      if ! linux_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"; then
        linux_root apt-get update -y
        linux_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
      fi
      ;;
    dnf) linux_root dnf install -y "${pkgs[@]}" ;;
    yum) linux_root yum install -y "${pkgs[@]}" ;;
    pacman) linux_root pacman -Sy --needed --noconfirm "${pkgs[@]}" ;;
    zypper) linux_root zypper --non-interactive install -y "${pkgs[@]}" ;;
    *)
      echo "Install these packages and rerun: ${pkgs[*]}" >&2
      return 1
      ;;
  esac
}

ensure_linux_python_packages() {
  [[ "$(uname -s)" == Linux ]] || return 0
  local missing=() mgr
  mgr="$(linux_pkg_manager)"
  if ! command -v python3 >/dev/null 2>&1; then
    case "$mgr" in
      apt|dnf|yum|zypper) missing+=(python3) ;;
      pacman) missing+=(python) ;;
    esac
  fi
  if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
    case "$mgr" in
      apt|zypper) missing+=(python3-venv python3-pip) ;;
      dnf|yum) missing+=(python3-pip) ;;
      pacman) missing+=(python-pip) ;;
    esac
  fi
  if command -v python3 >/dev/null 2>&1 && ! python3 -c '
import sysconfig
from pathlib import Path
raise SystemExit(not Path(sysconfig.get_path("include")).joinpath("Python.h").exists())
' >/dev/null 2>&1; then
    case "$mgr" in
      apt) missing+=(python3-dev) ;;
      dnf|yum) missing+=(python3-devel) ;;
      zypper) missing+=(python3-devel) ;;
    esac
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    install_linux_packages "${missing[@]}"
  fi
}

if [[ "$(uname -s)" == Linux ]]; then
  ensure_linux_python_packages
  if [[ -d .venv ]] && ! .venv/bin/python -c 'import sys' >/dev/null 2>&1; then
    echo "Recreating Linux virtual environment..."
    rm -rf .venv
  fi
fi

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
