"""Runtime diagnostics (UI stall monitor, slow-call tracing)."""

from wifit3.debug.ui_block import (
    async_section,
    configure,
    enabled,
    install_on_loop,
    patch_ap_history,
    section,
)

__all__ = [
    "async_section",
    "configure",
    "enabled",
    "install_on_loop",
    "patch_ap_history",
    "section",
]
