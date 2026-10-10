"""Fingerprint summaries for offline history tables."""
from __future__ import annotations

from typing import Any

from rich.text import Text

_FINGERPRINT_GREEN_COMPLETENESS = 50

SHORT_SIGNATURE_LEN = 8


def short_signature(signature: str | None) -> str:
    sig = (signature or "").strip()
    if not sig:
        return "-"
    if len(sig) > SHORT_SIGNATURE_LEN:
        return f"{sig[:SHORT_SIGNATURE_LEN]}\u2026"
    return sig


def _wifi_fingerprint_parts(
    record: dict[str, Any],
    kind: str,
) -> tuple[str, int, dict[str, Any]]:
    if kind == "hw":
        return (
            str(record.get("fingerprint_id") or "").strip(),
            int(record.get("fingerprint_completeness") or record.get("completeness") or 0),
            record.get("fingerprint") if isinstance(record.get("fingerprint"), dict) else {},
        )
    return (
        str(record.get("radio_fingerprint_id") or "").strip(),
        int(record.get("radio_fingerprint_completeness") or 0),
        record.get("radio_fingerprint")
        if isinstance(record.get("radio_fingerprint"), dict)
        else {},
    )


def offline_wifi_fingerprint_cell(
    record: dict[str, Any],
    kind: str,
) -> Text:
    fp_id, completeness, document = _wifi_fingerprint_parts(record, kind)
    sufficient = document.get("is_sufficient")
    if not fp_id:
        if sufficient is False or not document:
            return Text("...", style="dim yellow")
        if sufficient is True and document.get("signature_id"):
            fp_id = str(document["signature_id"])
    if not fp_id:
        return Text("...", style="dim yellow")
    summary = fp_id[:8]
    if completeness >= _FINGERPRINT_GREEN_COMPLETENESS:
        style = "green"
    elif sufficient is False:
        style = "dim yellow"
    else:
        style = "dim"
    return Text(summary, style=style)


def offline_wifi_fingerprint_sort_value(
    record: dict[str, Any],
    kind: str,
) -> str:
    fp_id, _completeness, document = _wifi_fingerprint_parts(record, kind)
    if fp_id:
        return fp_id.casefold()
    signature = document.get("signature_id")
    return str(signature or "").casefold()


def offline_wifi_meaningful_fingerprint_keys(
    record: dict[str, Any],
) -> frozenset[str]:
    """Fingerprint ids strong enough to link or keep a client in the main table."""
    keys: set[str] = set()
    for kind in ("hw", "rf"):
        fp_id, completeness, document = _wifi_fingerprint_parts(record, kind)
        sufficient = document.get("is_sufficient")
        if fp_id and completeness >= _FINGERPRINT_GREEN_COMPLETENESS:
            keys.add(fp_id.casefold())
            continue
        if sufficient is True:
            signature = document.get("signature_id")
            if signature:
                keys.add(str(signature).casefold())
    return frozenset(keys)
