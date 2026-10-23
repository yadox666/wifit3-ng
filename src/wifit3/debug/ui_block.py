"""Detect UI/event-loop stalls and log slow synchronous work.

Enabled by ``./start.sh --debug`` (sets ``WIFIT3_UI_DEBUG=1``) or manually::

    export WIFIT3_UI_DEBUG=1
    python -m wifit3

Logs:
- ``SLOW ...ms <label>`` - a traced section or SQLite call exceeded ``slow_ms``
- ``UI STALL ...ms`` - the asyncio loop did not heartbeat in time (main thread blocked)
- Stack dumps on stall (all threads) written to stderr and ``wifit3.log``
"""
from __future__ import annotations

import asyncio
import functools
import logging
import os
import sys
import threading
import time
import traceback
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Callable, Iterator, TypeVar

logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., Any])

_enabled = False
_slow_s = 0.05
_stall_s = 0.20
_stall_dump_cooldown_s = 1.0
_last_stall_dump = 0.0
_ap_history_patched = False
_monitor: StallMonitor | None = None


def enabled() -> bool:
    return _enabled or os.environ.get("WIFIT3_UI_DEBUG", "").strip() in {
        "1",
        "true",
        "yes",
        "on",
    }


def configure(
    *,
    enabled_flag: bool | None = None,
    slow_ms: float = 50.0,
    stall_ms: float = 200.0,
    console: bool = True,
) -> None:
    """Turn on UI blocking diagnostics."""
    global _enabled, _slow_s, _stall_s
    if enabled_flag is None:
        _enabled = enabled()
    else:
        _enabled = enabled_flag
    _slow_s = max(0.001, slow_ms / 1000.0)
    _stall_s = max(0.05, stall_ms / 1000.0)
    if not _enabled:
        return
    root = logging.getLogger()
    if console and not any(
        isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stderr
        for h in logger.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-5s [ui-block] %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        if root.level > logging.INFO:
            root.setLevel(logging.INFO)
    logger.info(
        "UI block debug on (slow>=%dms stall>=%dms); see wifit3.log + stderr",
        int(_slow_s * 1000),
        int(_stall_s * 1000),
    )


def _log_slow(label: str, elapsed_s: float, extra: str = "") -> None:
    if elapsed_s < _slow_s:
        return
    suffix = f" {extra}" if extra else ""
    logger.warning("SLOW %.0fms %s%s", elapsed_s * 1000, label, suffix)


@asynccontextmanager
async def async_section(label: str) -> AsyncIterator[None]:
    """Time an ``async with`` block."""
    if not _enabled:
        yield
        return
    start = time.monotonic()
    try:
        yield
    finally:
        _log_slow(label, time.monotonic() - start)


@contextmanager
def section(label: str) -> Iterator[None]:
    """Time a block; log when it exceeds ``slow_ms``."""
    if not _enabled:
        yield
        return
    start = time.monotonic()
    try:
        yield
    finally:
        _log_slow(label, time.monotonic() - start)


def run_named(label: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    start = time.monotonic()
    try:
        return func(*args, **kwargs)
    finally:
        _log_slow(label, time.monotonic() - start)


def trace_sync(label: str) -> Callable[[_F], _F]:
    """Decorator for hot synchronous callables."""

    def decorator(func: _F) -> _F:
        if not _enabled:
            return func

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with section(label):
                return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def dump_all_stacks(reason: str) -> None:
    global _last_stall_dump
    now = time.monotonic()
    if now - _last_stall_dump < _stall_dump_cooldown_s:
        return
    _last_stall_dump = now
    lines = [f"=== stack dump ({reason}) ==="]
    frames = sys._current_frames()
    for thread_id, frame in sorted(frames.items()):
        name = "unknown"
        for thread in threading.enumerate():
            if thread.ident == thread_id:
                name = thread.name
                break
        lines.append(f"--- Thread {name} ({thread_id}) ---")
        lines.extend(traceback.format_stack(frame))
    text = "\n".join(lines)
    logger.warning("%s", reason)
    logger.debug("%s", text)


class StallMonitor:
    """Watchdog: asyncio heartbeats vs wall clock."""

    def __init__(self, loop: asyncio.AbstractEventLoop, stall_s: float) -> None:
        self._loop = loop
        self._stall_s = stall_s
        self._stop = threading.Event()
        self._last_ping = time.monotonic()
        self._ping_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def ping(self) -> None:
        with self._ping_lock:
            self._last_ping = time.monotonic()

    def _schedule_ping(self) -> None:
        if self._stop.is_set():
            return
        self.ping()
        self._loop.call_later(0.05, self._schedule_ping)

    def _watch(self) -> None:
        while not self._stop.wait(0.05):
            with self._ping_lock:
                age = time.monotonic() - self._last_ping
            if age >= self._stall_s:
                dump_all_stacks(
                    f"UI STALL {age * 1000:.0f}ms (event loop heartbeat missing)",
                )

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._watch,
            name="wifit3-ui-stall-watch",
            daemon=True,
        )
        self._thread.start()
        self._loop.call_soon(self._schedule_ping)

    def stop(self) -> None:
        self._stop.set()


def install_on_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Heartbeat + asyncio slow-callback warnings."""
    global _monitor
    if not _enabled:
        return
    loop.set_debug(True)
    loop.slow_callback_duration = _slow_s
    _monitor = StallMonitor(loop, _stall_s)
    _monitor.start()
    logger.info("Stall monitor installed on asyncio loop")


def patch_ap_history() -> None:
    """Wrap ``ApHistoryStore`` locked SQLite methods with slow-call logging."""
    global _ap_history_patched
    if not _enabled or _ap_history_patched:
        return
    from wifit3.persist import ap_history as mod

    original_locked = mod._locked

    def _locked_timed(method):  # noqa: ANN001
        wrapped = original_locked(method)

        @functools.wraps(wrapped)
        def outer(self, *args, **kwargs):
            if not _enabled:
                return wrapped(self, *args, **kwargs)
            label = f"ap_history.{method.__name__}"
            start = time.monotonic()
            try:
                return wrapped(self, *args, **kwargs)
            finally:
                _log_slow(label, time.monotonic() - start)

        return outer

    mod._locked = _locked_timed  # type: ignore[assignment]
    _ap_history_patched = True
    logger.info("ApHistoryStore lock timing enabled")
