"""Shared EAP lab honeypot poll for Focus and Scanner logs."""
from __future__ import annotations

import logging

from rich.markup import escape

from wifit3.campaigns import treelog
from wifit3.crack.mschapv2 import is_complete_mschapv2_capture

logger = logging.getLogger(__name__)

_RESULT = {
    "captured": "[bold green]MS-CHAPv2 CAPTURED[/bold green] · saved to Vault",
    "misconfigured": "[bold yellow]CLIENT MISCONFIGURATION[/bold yellow] · see Vault report",
    "timeout": "[dim]TIMEOUT[/dim] · no MS-CHAPv2 response",
    "stopped": "[dim]STOPPED[/dim]",
    "no-interface": "[red]FAILED[/red] · no compatible interface",
}


def attach_eap_lab_campaign(app, campaign) -> None:
    app.eap_lab_campaign = campaign
    app.eap_lab_event_indexes = {}
    app.eap_lab_event_index = 0
    app.eap_lab_finished = False


def poll_eap_lab_campaign(app, log, *, listener: str = "default") -> None:
    campaign = getattr(app, "eap_lab_campaign", None)
    if campaign is None:
        return
    indexes = getattr(app, "eap_lab_event_indexes", None)
    if not isinstance(indexes, dict):
        indexes = {}
        app.eap_lab_event_indexes = indexes
    index = int(indexes.get(listener, 0) or 0)
    events = campaign.stats.events
    for message in events[index:]:
        log(treelog.branch(escape(message)))
    indexes[listener] = len(events)
    app.eap_lab_event_index = indexes[listener]

    ap = getattr(campaign, "target_ap", None) or getattr(campaign, "ap", None)
    _commit_pending_saves(app, campaign, ap, log, indexes, listener)
    if not campaign.done or getattr(app, "eap_lab_finished", False):
        return
    app.eap_lab_finished = True
    finish = _RESULT.get(campaign.result, escape(str(campaign.result)))
    campaign.stats.events.append(f"EAP lab finished · {campaign.result}")
    indexes[listener] = len(campaign.stats.events)
    log(treelog.leaf(finish))
    if ap is not None and campaign.client_assessments:
        try:
            saved = app.vault.save_eap_lab_report(
                ap,
                lab_bssid=campaign.bssid_text,
                launch=campaign.launch,
                clients=campaign.client_assessments,
                campaign_result=campaign.result,
                pcap_path=getattr(campaign, "pcap_path", None),
            )
        except Exception as exc:
            logger.exception("Could not save EAP lab assessment report")
            app.notify(str(exc), title="Vault save failed", severity="error")
            saved = None
        if saved is not None:
            notice = f"EAP lab assessment saved to Vault · {escape(saved.path.name)}"
            campaign.stats.events.append(notice)
            log(treelog.branch(notice))
    app.notify(
        "MS-CHAPv2 hash saved to Vault"
        if campaign.result == "captured"
        else f"EAP lab finished: {campaign.result}",
        title="EAP lab",
        severity=(
            "warning"
            if campaign.result in ("misconfigured", "timeout", "stopped")
            else "information"
        ),
        persist=campaign.result == "captured",
    )


def _commit_pending_saves(app, campaign, ap, log, indexes, listener) -> None:
    if ap is None:
        return
    lab_ssid = getattr(campaign, "ssid", None) or ap.ssid
    pending_credentials = getattr(campaign, "pending_credentials", None) or []
    while pending_credentials:
        username, password = pending_credentials.pop(0)
        try:
            saved = app.vault.save_captive_password(
                ap,
                password,
                username=username,
                portal_name=lab_ssid,
                source="eap_lab_inner_pap",
                lab_bssid=getattr(campaign, "bssid_text", None),
                allow_empty_password=True,
            )
        except Exception as exc:
            logger.exception("Could not save EAP lab credential")
            app.notify(str(exc), title="Vault save failed", severity="error")
            break
        if saved is None:
            continue
        notice = (
            f"EAP lab credential saved to Vault · {escape(username)} · "
            f"{escape(saved.path.name)}"
        )
        campaign.stats.events.append(notice)
        log(treelog.branch(notice))
        indexes[listener] = len(campaign.stats.events)
    if not campaign.pending_captures:
        return
    while campaign.pending_captures:
        capture = campaign.pending_captures.pop(0)
        if not is_complete_mschapv2_capture(capture):
            continue
        try:
            saved = app.vault.save_mschapv2(
                ap,
                capture,
                lab_bssid=campaign.bssid_text,
            )
        except Exception as exc:
            logger.exception("Could not save MS-CHAPv2 capture")
            app.notify(str(exc), title="Vault save failed", severity="error")
            break
        if saved is None:
            continue
        notice = (
            f"MS-CHAPv2 saved to Vault · {escape(capture.username)} · "
            f"{escape(saved.mschapv2.path.name)} + "
            f"{escape(saved.netntlmv2.path.name)} (Hashcat 5500/5600)"
        )
        campaign.stats.events.append(notice)
        log(treelog.branch(notice))
        indexes[listener] = len(campaign.stats.events)
