"""Probe-request SSIDs for offline Wi-Fi client rows."""
from __future__ import annotations

from typing import Any, Iterable

from rich.text import Text

_MAX_CELL_SSIDS = 6
_CLIP_SSID = 20


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def offline_client_probed_ssids(record: dict[str, Any]) -> tuple[str, ...]:
    """Distinct probe SSIDs stored on an offline client record."""
    direct = record.get("probed_ssids")
    if direct:
        return tuple(sorted({str(item).strip() for item in direct if str(item).strip()}))
    radio = record.get("radio_fingerprint") or {}
    if isinstance(radio, dict):
        payload = radio.get("payload") or radio
        if isinstance(payload, dict):
            behavior = payload.get("behavior") or {}
            stored = behavior.get("probed_ssids")
            if stored:
                return tuple(
                    sorted({str(item).strip() for item in stored if str(item).strip()}),
                )
    return ()


def enrich_offline_wifi_client_probes(
    record: dict[str, Any],
    *,
    hidden_probe_ssids: Iterable[str] | None = None,
) -> None:
    """Attach merged ``probed_ssids`` for table, filter, and detail use."""
    merged = set(offline_client_probed_ssids(record))
    if hidden_probe_ssids is not None:
        merged.update(
            str(ssid).strip()
            for ssid in hidden_probe_ssids
            if str(ssid).strip()
        )
    record["probed_ssids"] = sorted(merged)


def offline_client_probes_cell(record: dict[str, Any]) -> Text:
    ssids = offline_client_probed_ssids(record)
    probes = Text(no_wrap=True)
    if not ssids:
        probes.append("·", style="dim")
        return probes
    shown = ssids[:_MAX_CELL_SSIDS]
    for index, ssid in enumerate(shown):
        if index:
            probes.append("  ·  ", style="dim")
        probes.append(_clip(ssid, _CLIP_SSID))
    extra = len(ssids) - len(shown)
    if extra > 0:
        probes.append(f"  +{extra}", style="dim")
    return probes


def offline_client_probes_sort_value(record: dict[str, Any]) -> str:
    return " ".join(offline_client_probed_ssids(record)).casefold()
