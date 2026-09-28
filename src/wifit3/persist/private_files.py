from __future__ import annotations

import os
from pathlib import Path
from typing import IO


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_private_text(path: Path, text: str) -> None:
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)
    harden_private_file(path)


def open_private_text_append(path: Path) -> IO[str]:
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    harden_private_file(path)
    return os.fdopen(descriptor, "a", encoding="utf-8")


def open_private_text_write(path: Path, *, newline: str | None = None) -> IO[str]:
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    harden_private_file(path)
    return os.fdopen(descriptor, "w", encoding="utf-8", newline=newline)


def open_private_binary(path: Path) -> IO[bytes]:
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    harden_private_file(path)
    return os.fdopen(descriptor, "wb")


def harden_private_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
