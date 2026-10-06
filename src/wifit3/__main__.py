"""Entry point for ``python -m wifit3`` and the ``wifit3`` console script."""


async def _smoke() -> None:
    """Headless self-test: prove the PyInstaller bundle is intact, then exit. Used by CI to
    catch bundling breaks the unit-test import-smoke can't.

    Three checks:
      1. The bundled libusb shared lib is where ``libusb_package.get_library_path()`` looks
         (``libusb_package/libusb-1.0.*``) and actually loads. A onefile build can misplace it,
         which breaks USB enumeration with "No backend available". We deliberately do NOT
         ``libusb_init``/enumerate here: CI runners have no USB subsystem (no ``/dev/bus/usb``),
         so init legitimately fails there. That's a runtime-env concern, not a packaging break.
      2. ``App.run_test()`` mounts every screen headless (no TTY), pulling the widget .tcss and
         logo assets that a broken ``collect_all`` would silently drop.
      3. ``supported_ids()`` is non-empty: the pkgutil chip-discovery walk only enumerates
         drivers PyInstaller actually collected, so an empty map means the bundle shipped with
         no drivers and the app would launch but show zero interfaces.
      4. The bundled TLS CA store loads and contains trusted certificate authorities.
    """
    import ctypes
    import os

    from libusb_package import get_library_path

    lib = get_library_path()
    if not (lib and os.path.isfile(str(lib))):
        raise RuntimeError(f"bundled libusb not found via libusb_package: {lib!r}")
    ctypes.CDLL(str(lib))  # must load from the bundle (deps resolved), not just exist on disk

    from wifit3.ui.app import WifiteApp

    app = WifiteApp(cli_log_level="unset")
    async with app.run_test() as pilot:
        await pilot.pause()

    # Chip discovery actually finds drivers. supported_ids() walks wifit3.chips via pkgutil; if
    # PyInstaller didn't collect the dynamically-imported chip packages the map is empty and the
    # app launches fine but shows zero interfaces. That is the break this check exists to catch.
    from wifit3.device.manager import supported_ids

    if not supported_ids():
        raise RuntimeError("chip discovery found no driver packages (PyInstaller bundling break)")

    from wifit3.updates import _tls_context

    if _tls_context().cert_store_stats().get("x509_ca", 0) < 1:
        raise RuntimeError("bundled TLS CA store contains no trusted certificate authorities")


def build_parser():
    """CLI for ``python -m wifit3`` and ``./start.sh``."""
    import argparse

    from wifit3 import __version__

    parser = argparse.ArgumentParser(prog="wifit3", description="USB Wireless Auditor")
    parser.add_argument("--version", action="version", version=f"wifit3 {__version__}")
    parser.add_argument("--smoke", action="store_true", help="TEST ONLY: Run headless, render, exit 0")
    parser.add_argument("--quiet", action="store_true", help="Do not emit any logs")
    parser.add_argument("--debug", action="store_true", help="Emit verbose debug logs")
    parser.add_argument("--trace", action="store_true", help="Emit very verbose trace logs")
    parser.add_argument(
        "--background",
        action="store_true",
        help="Stay on the startup screen and record enabled Wi-Fi, BLE, and Bluetooth radios",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="With --background, monitor Wi-Fi, Bluetooth Classic, and BLE",
    )
    parser.add_argument(
        "--case",
        action="store_true",
        help="Prompt for scan session name and notes at startup (default: auto-generated name)",
    )
    return parser


def check_cli(parser, args) -> None:
    """Reject flag combinations that do not name a mode."""
    if args.all and not args.background:
        parser.error("--all requires --background")


def main() -> None:
    """Parse CLI args, then run the headless smoke test or launch the TUI."""
    parser = build_parser()
    args = parser.parse_args()
    check_cli(parser, args)

    if args.smoke:
        import asyncio

        # 60s ceiling so a hung mount fails CI instead of stalling the runner.
        asyncio.run(asyncio.wait_for(_smoke(), timeout=60))
        return

    # Lazy import for WEP cracker ProcessPoolExecutor case
    from wifit3.ui.app import WifiteApp

    cli_log_level = None
    if args.debug:
        cli_log_level = "debug"
    if args.trace:
        cli_log_level = "trace"
    if args.quiet:
        cli_log_level = "quiet"

    import asyncio
    import os

    # Own the event loop instead of letting app.run() call asyncio.run(). On exit,
    # asyncio.run() drains the default thread-pool executor (and the interpreter's
    # concurrent.futures atexit hook joins it again) - if a background worker is
    # blocked in a syscall (a serial-GPS or USB read), that join hangs for minutes
    # and Ctrl+C just stacks more KeyboardInterrupts. Passing our own loop takes
    # Textual's run_until_complete() path (no executor drain); the TUI has already
    # restored the terminal by the time run() returns, so we exit immediately and
    # skip the thread-join entirely.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = WifiteApp(
        cli_log_level=cli_log_level,
        background=args.background,
        background_all=args.all,
        case_prompt=args.case,
    )
    try:
        app.run(loop=loop)
    except KeyboardInterrupt:
        pass
    finally:
        os._exit(app.return_code or 0)


if __name__ == "__main__":
    # Frozen (PyInstaller) builds use the `spawn` start method, so each
    # ProcessPoolExecutor worker (the WEP cracker) re-execs this exe. freeze_support()
    # makes that re-exec run the worker bootstrap and exit, instead of launching a
    # second TUI. It is a no-op for normal `python -m wifit3` / console-script runs.
    import multiprocessing

    multiprocessing.freeze_support()
    main()
