"""View-model for the Focus screen."""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from rich.markup import escape
from wifit3.wlan.array import WlanArray

from .encryption_format import format_encryption_markup
from ..campaigns.campaign import Campaign
from ..campaigns.pmkid import PmkidHarvestAttack
from ..campaigns.wep import WepCampaign
from wifit3.crack.wep import CRACK_READY_THRESHOLD
from wifit3.crack.handshake import pmkid_crackable
from wifit3.models import IdKey, IdSource
from wifit3.persist.config import Config
from wifit3.dot11.enterprise import EAP_TYPE_NAMES
from wifit3.wlan.enterprise_risk import enterprise_findings, tls_cipher_name
from ..campaigns.pin import WpsCampaign
from ..campaigns.deauth import DeauthCampaign
from ..campaigns.eviltwin import EvilTwinCampaign
from ..campaigns.fake_connect import FakeConnectCampaign

if TYPE_CHECKING:
    from wifit3.models.access_point import AccessPoint

# Attack-button campaigns in button-row order.
BUTTON_CAMPAIGNS = [
    WepCampaign, DeauthCampaign, PmkidHarvestAttack, FakeConnectCampaign,
    WpsCampaign, EvilTwinCampaign,
]


CAMPAIGN_BY_KEY = {cls.key: cls for cls in BUTTON_CAMPAIGNS}


def campaign_blocked(cls, ap, vault=None) -> Optional[str]:
    """Why cls's attack button is disabled right now, or None if it can start:
    the AP is silenced, another campaign owns the radio, or the campaign's own
    ineligible_reason (hidden SSID, WPS locked, unconfirmed encryption, …)."""
    if Config.is_silenced(ap.bssid):
        return "AP silenced"
    active = Campaign.active
    if active is not None and active.key != cls.key:
        return f"Blocked ({active.key} is active)"
    if cls is FakeConnectCampaign and vault is not None:
        return cls.ineligible_reason(ap, vault)
    return cls.ineligible_reason(ap)


def other_long_running_tx(exclude: str = "") -> bool:
    """True if a campaign OTHER than ``exclude`` owns the radio."""
    active = Campaign.active
    return active is not None and active.key != exclude


def is_wep(ap) -> bool:
    return (ap.encryption or "").upper() == "WEP"


@dataclass
class DashboardRow:
    """One row of the packet dashboard."""
    key: str                       # beacon / data / wep_iv / eapol / inject / deauth
    label: str                     # <= 6-char gutter label
    color: str                     # Rich colour name
    peak: int                      # nominal scale (drives the fake generator)
    as_rate: bool = True           # True -> "N/s", False -> a recent count


# Dashboard rows by family: WEP shows the wep-iv row, WPA/WPA2/WPA3 the eapol row.
_DASHBOARD_BEACON = DashboardRow("beacon", "beacon", "cyan", 10)
_DASHBOARD_DATA = DashboardRow("data", "data", "blue", 240)
_DASHBOARD_WEP_IV = DashboardRow("wep_iv", "wep iv", "green", 120)
_DASHBOARD_EAPOL = DashboardRow("eapol", "eapol", "green", 4, as_rate=False)
_DASHBOARD_INJECT = DashboardRow("inject", "inject", "orange1", 30)
_DASHBOARD_DEAUTH = DashboardRow("deauth", "deauth", "red", 12)


def dashboard_rows(ap) -> list[DashboardRow]:
    """The 5 dashboard rows for this target's family."""
    enc = (ap.encryption or "").upper()
    rows = [_DASHBOARD_BEACON, _DASHBOARD_DATA]
    if enc == "WEP":
        rows.append(_DASHBOARD_WEP_IV)
    elif enc not in ("OPEN", ""):
        rows.append(_DASHBOARD_EAPOL)
    rows += [_DASHBOARD_INJECT, _DASHBOARD_DEAUTH]
    return rows


def truncate_ssid(ssid: str, maxlen: int = 24) -> str:
    """Ellipsize an SSID that overflows the endpoint width '  …'."""
    if len(ssid) <= maxlen:
        return ssid
    return ssid[:maxlen - 1].rstrip() + "…"


def best_named_sibling_ssid(ap, array) -> Optional[str]:
    """Strongest confirmed SSID among same-radio siblings of a hidden AP."""
    if array is None or not ap.siblings:
        return None
    best_ssid: Optional[str] = None
    best_beacons = -1
    for sibling_bssid in ap.siblings:
        sibling = array.access_points.get(sibling_bssid)
        if sibling and sibling.ssid and sibling.beacons > best_beacons:
            best_ssid = sibling.ssid
            best_beacons = sibling.beacons
    return best_ssid


def display_ssid(ap, array) -> tuple[Optional[str], Optional[str]]:
    """SSID plus evidence source: confirmed, history, sibling guess, or absent."""
    if ap.ssid:
        return ap.ssid, "history" if ap.decloak_method == "history" else "confirmed"
    sibling = best_named_sibling_ssid(ap, array)
    return (sibling, "sibling") if sibling else (None, None)


def _band_of(channel: int) -> str:
    return "2.4 GHz" if channel and channel <= 14 else "5 GHz"


def _bssid_bit_diff(a: str, b: str) -> int:
    """Hamming distance between two ``aa:bb:..``-formatted BSSIDs (matches WlanSink)."""
    pa, pb = a.lower().split(":"), b.lower().split(":")
    if len(pa) != 6 or len(pb) != 6:
        return 48
    try:
        return sum(bin(int(x, 16) ^ int(y, 16)).count("1") for x, y in zip(pa, pb))
    except ValueError:
        return 48


def band_twins(ap, array) -> list:
    """Same-network APs on a DIFFERENT band than ``ap`` -- its other-band radio.

    Dual-band routers publish one SSID on both 2.4 and 5 GHz under near-identical BSSIDs, and a
    band-steered client keeps one link in power-save (Null keepalives only) while moving data to
    the other band. Same-band virtual APs are already linked as ``siblings`` (same channel); this
    finds the cross-band counterpart, matched either by SSID or by the same same-radio BSSID
    heuristic siblings use (same OUI + small Hamming delta). Sorted by channel."""
    if ap is None or array is None or not ap.channel:
        return []
    target_band = _band_of(ap.channel)
    twins = []
    for other in array.access_points.values():
        if other.bssid.casefold() == ap.bssid.casefold() or not other.channel:
            continue
        if _band_of(other.channel) == target_band:
            continue
        same_ssid = bool(
            ap.ssid and ap.ssid != "<hidden>"
            and other.ssid and other.ssid.casefold() == ap.ssid.casefold()
        )
        same_oui = ap.bssid[:8].lower() == other.bssid[:8].lower()
        same_radio = same_oui and 0 < _bssid_bit_diff(ap.bssid, other.bssid) <= 8
        if same_ssid or same_radio:
            twins.append(other)
    return sorted(twins, key=lambda item: item.channel)


def beacon_rate(ap, samples: deque, now: float, window_s: float = 5.0):
    """Windowed beacons/s + cumulative count."""
    samples.append((now, ap.beacons))
    while len(samples) > 1 and now - samples[0][0] > window_s:
        samples.popleft()
    oldest_t, oldest_n = samples[0]
    span = now - oldest_t
    rate = (ap.beacons - oldest_n) / span if span >= 1.0 else None
    return rate, ap.beacons

def count_handshakes(ap):
    """``(complete, partial, msg_counts)`` across this AP's handshakes."""
    n_complete = sum(hs.complete_instances for hs in ap.handshakes.values())
    n_partial = sum(
        1 for hs in ap.handshakes.values()
        if not hs.is_complete and hs.total_messages > 0
    )
    msg_counts: Counter = Counter()
    for hs in ap.handshakes.values():
        for f in hs.messages:
            if f.msg_num:
                msg_counts[f.msg_num] += 1
    return n_complete, n_partial, msg_counts


def fakeauth_value_markup(campaign, now: float, compact: bool = False) -> str:
    """Just the fake-auth status value (no 'Fake-Auth:' label)."""
    if campaign is None:
        return "[dim]Off[/dim]"
    fa = campaign.fake_auth
    if fa.state == "associated":
        countdown = ""
        if fa.next_reauth_at and not compact:
            secs = max(0, int(fa.next_reauth_at - now))
            countdown = f" [dim](re-auth in {secs}s)[/dim]"
        return f"[green]✓ Associated[/green]{countdown}"
    if fa.state == "authenticating":
        return "[yellow]Associating…[/yellow]"
    if fa.state == "failed":
        return f"[red]Failed: {escape(fa.fail_reason or 'unknown')}[/red]"
    return "[dim]Idle[/dim]"


def wep_status_lines(ap, array, campaign, now: float) -> list[str]:
    """The WEP status footer (v2)."""
    samples = array.wep_store.crack_sample_count(ap.bssid) if array else 0
    n = f"[cyan]{samples:,}[/cyan]" if samples else "[red]0[/red]"
    # /10k tags the crack threshold (distinct from the gross "wep iv" rate above)
    ivs = (n if samples >= CRACK_READY_THRESHOLD
           else f"{n}[dim]/{CRACK_READY_THRESHOLD // 1000}k[/dim]")
    lines = []
    if campaign is not None:
        lines.append(
            f"[dim]Fake-Auth:[/dim] {fakeauth_value_markup(campaign, now, compact=True)}")
    lines.append(f"[dim]Usable IVs:[/dim] {ivs}")
    return lines


def encryption_chip(ap) -> str:
    """The encryption family for the 'Target acquired' log."""
    return format_encryption_markup(ap, detailed=False)


def pmf_status_markup(ap) -> str:
    """PMF status for the Focus footer.
    Disabled (dim) → Optional (orange) → Required (red)."""
    if ap.pmf_required:
        return "[red]Required[/red]"
    if ap.pmf_capable:
        return "[dark_orange]Optional[/dark_orange]"
    return "[dim]Disabled[/dim]"


def _router_identity_rows(ap: AccessPoint) -> list[str]:
    ident = ap.identity
    if ident is None or not ident.summary:
        return []
    rows = [f"[bold]{escape(ident.summary)}[/bold]"]
    mfr_src: IdSource | None = None
    if ident.model:
        model_src = getattr(ident, "model_source", None) or ident.get(IdKey.MODEL_NAME)[1] or ident.get(IdKey.MODEL_NUMBER)[1]
        src_label = model_src.label if model_src else ""
        rows.append(f"[dim]Model:[/dim] {escape(ident.model)} [dim]({src_label})[/dim]")
    if ident.manufacturer:
        mfr_src = getattr(ident, "manufacturer_source", None) or ident.get(IdKey.MANUFACTURER)[1]
        src_label = mfr_src.label if mfr_src else ""
        rows.append(f"[dim]Manufacturer:[/dim] {escape(ident.manufacturer)} [dim]({src_label})[/dim]")
    if ident.device_name and ident.device_name != ident.model:
        dev_src = ident.get(IdKey.DEVICE_NAME)[1]
        src_label = dev_src.label if dev_src else ""
        rows.append(f"[dim]Device Name:[/dim] {escape(ident.device_name)} [dim]({src_label})[/dim]")
    if ident.serial_number:
        sn_src = ident.get(IdKey.SERIAL_NUMBER)[1]
        src_label = sn_src.label if sn_src else ""
        rows.append(f"[dim]Serial:[/dim] {escape(ident.serial_number)} [dim]({src_label})[/dim]")
    if ident.device_type:
        dt_src = ident.get(IdKey.DEVICE_TYPE)[1]
        src_label = dt_src.label if dt_src else ""
        rows.append(f"[dim]Device Type:[/dim] {escape(ident.device_type)} [dim]({src_label})[/dim]")

    wsc_mfr = ident.get_source_value(IdKey.MANUFACTURER, IdSource.WSC_M1) or ident.get_source_value(IdKey.MANUFACTURER, IdSource.WSC_BEACON)
    if wsc_mfr and wsc_mfr != ident.manufacturer:
        rows.append(f"[dim]Chipset:[/dim] {escape(wsc_mfr)} [dim](WSC)[/dim]")

    oui_vendor = ident.get_source_value(IdKey.MANUFACTURER, IdSource.OUI)
    if oui_vendor and (oui_vendor != ident.manufacturer or mfr_src != IdSource.OUI):
        rows.append(f"[dim]IEEE OUI:[/dim] {escape(oui_vendor)}")
    return rows


def router_identity_details(ap: AccessPoint) -> str | None:
    rows = _router_identity_rows(ap)
    return "\n".join(rows) if rows else None


def has_stored_wps_identity(ap: AccessPoint) -> bool:
    """True when WPS router identity is already on the AP (DB or passive WSC)."""
    if not getattr(ap, "wps", False):
        return False
    ident = getattr(ap, "identity", None)
    if ident is None:
        return False
    if not (
        ident.has_source(IdSource.WSC_M1)
        or ident.has_source(IdSource.WSC_BEACON)
    ):
        return False
    return bool(ident.summary or router_identity_details(ap))


def router_advertised_details(ap: AccessPoint) -> str:
    rows = _router_identity_rows(ap)
    if not rows:
        rows = [f"[bold]{escape(ap.ssid or ap.bssid)}[/bold]"]
    caps = ap.capabilities
    operation = channel_technical_summary(ap)
    rows.append(f"[dim]Operating Channel:[/dim] {escape(operation)}")
    if caps.channel_conflict:
        rows.append(
            "[yellow]Channel evidence conflicted; using the channel on which "
            "the frame was actually received.[/yellow]"
        )
    radio = _radio_summary(caps)
    if radio:
        rows.append(f"[dim]Supported Radio:[/dim] {escape(radio)}")
    if caps.supported_rates_mbps:
        rates = ", ".join(_rate_label(rate) for rate in sorted(caps.supported_rates_mbps))
        rows.append(f"[dim]Legacy Rates:[/dim] {rates} Mbps")
    timing = []
    if caps.beacon_interval_tu is not None:
        timing.append(f"beacon {caps.beacon_interval_tu} TU")
    if caps.dtim_period is not None:
        timing.append(f"DTIM {caps.dtim_period}")
    if timing:
        rows.append(f"[dim]Timing:[/dim] {' · '.join(timing)}")
    load = []
    if caps.station_count is not None:
        load.append(f"{caps.station_count} stations")
    if caps.channel_utilization is not None:
        load.append(f"{round(caps.channel_utilization * 100 / 255)}% channel use")
    if caps.admission_capacity is not None:
        load.append(f"capacity {caps.admission_capacity}")
    if load:
        rows.append(f"[dim]BSS Load:[/dim] {' · '.join(load)}")
    if ap.country_code:
        country = ap.country_code
        if caps.country_environment:
            country += f" ({caps.country_environment})"
        if caps.country_channels:
            ranges = ", ".join(
                f"CH {start}-{start + count - 1} ≤{power} dBm"
                for start, count, power in caps.country_channels
            )
            country += f" · {ranges}"
        rows.append(f"[dim]Country:[/dim] {escape(country)}")
    power = []
    if caps.power_constraint_db is not None:
        power.append(f"constraint {caps.power_constraint_db} dB")
    if caps.power_min_dbm is not None and caps.power_max_dbm is not None:
        power.append(f"{caps.power_min_dbm}..{caps.power_max_dbm} dBm")
    if power:
        rows.append(f"[dim]Power:[/dim] {' · '.join(power)}")
    security = []
    if ap.group_cipher:
        security.append(f"group {ap.group_cipher}")
    if ap.pairwise_ciphers:
        security.append(f"pairwise {'+'.join(ap.pairwise_ciphers)}")
    if ap.akms:
        security.append(f"AKM {'+'.join(ap.akms)}")
    security.append(f"PMF {_plain_pmf(ap)}")
    if any(suite in (0x18, 0x19) for suite in ap.akm_suites):
        security.append("SAE H2E")
    rows.append(f"[dim]Security:[/dim] {' · '.join(security)}")
    features = _feature_labels(caps)
    if ap.beacon_protection:
        features.append("Beacon Protection")
    if features:
        rows.append(f"[dim]Features:[/dim] {' · '.join(features)}")
    if caps.vendor_ouis:
        rows.append(f"[dim]Vendor IEs:[/dim] {', '.join(sorted(caps.vendor_ouis))}")
    if caps.capability_flags:
        rows.append(f"[dim]Capability Flags:[/dim] {', '.join(sorted(caps.capability_flags))}")
    rows.extend(_enterprise_profile_rows(ap.enterprise, ap))

    return "\n".join(rows)


def _enterprise_profile_rows(profile, ap=None) -> list[str]:
    if profile is None:
        return []
    methods = profile.server_eap_types | profile.client_eap_types
    if not methods and not profile.tls_versions and not profile.certificates:
        return []
    rows = ["[bold cyan]Observed Enterprise authentication[/bold cyan]"]
    if profile.server_eap_types:
        rows.append(
            "[dim]Server requests:[/dim] "
            + ", ".join(
                EAP_TYPE_NAMES.get(method, f"EAP type {method}")
                for method in sorted(profile.server_eap_types)
            )
        )
    if profile.client_eap_types:
        rows.append(
            "[dim]Client responses:[/dim] "
            + ", ".join(
                EAP_TYPE_NAMES.get(method, f"EAP type {method}")
                for method in sorted(profile.client_eap_types)
            )
        )
    if profile.tls_versions:
        rows.append(
            f"[dim]Outer TLS:[/dim] {', '.join(sorted(profile.tls_versions))}",
        )
    if profile.tls_cipher_suites:
        rows.append(
            "[dim]TLS ciphers:[/dim] "
            + ", ".join(
                tls_cipher_name(cipher)
                for cipher in sorted(profile.tls_cipher_suites)
            )
        )
    for certificate in profile.certificates.values():
        validity = ""
        if certificate.not_after is not None:
            validity = datetime.fromtimestamp(certificate.not_after).strftime("%Y-%m-%d")
        key = " ".join(
            str(value) for value in (
                certificate.public_key_algorithm,
                certificate.public_key_bits,
            ) if value is not None
        )
        rows.append(
            f"[dim]RADIUS certificate:[/dim] "
            f"{certificate.fingerprint[:12]}"
            f"{f' · expires {validity}' if validity else ''}"
            f"{f' · {escape(certificate.signature_algorithm)}' if certificate.signature_algorithm else ''}"
            f"{f' · {escape(key)} bits' if key else ''}"
        )
    if ap is not None:
        findings = enterprise_findings(ap)
        if findings:
            colors = {0: "cyan", 1: "yellow", 2: "orange1", 3: "red", 4: "bold red"}
            for finding in findings:
                rows.append(
                    f"[{colors[finding.severity]}]Risk:[/] {escape(finding.label)} "
                    f"[dim]· {escape(finding.evidence)} · confidence {finding.confidence}[/dim]"
                )
        else:
            rows.append("[green]Risk:[/] no passive weakness observed")
    rows.append(
        "[dim]Passive evidence only; tunneled inner methods and client certificate "
        "validation are not visible.[/dim]",
    )
    return rows


def client_advertised_details(client) -> str:
    from wifit3.models import AdvertisedCapabilities
    rows = [f"[bold]{escape(client.mac)}[/bold]"]
    from wifit3.id import vendor_for_mac
    vendor = vendor_for_mac(client.mac)
    if vendor:
        rows.append(f"[dim]Manufacturer:[/dim] {escape(vendor)}")
    try:
        local = bool(int(client.mac.split(":", 1)[0], 16) & 0x02)
    except (ValueError, IndexError):
        local = False
    rows.append(f"[dim]MAC Type:[/dim] {'locally administered / possibly randomized' if local else 'globally administered'}")
    bssid = getattr(client, "bssid", None)
    if bssid:
        rows.append(f"[dim]Associated AP:[/dim] {escape(bssid)}")
    caps = getattr(client, "capabilities", AdvertisedCapabilities())
    radio = _radio_summary(caps)
    if radio:
        rows.append(f"[dim]Radio:[/dim] {escape(radio)}")
    if caps.supported_rates_mbps:
        rates = ", ".join(_rate_label(rate) for rate in sorted(caps.supported_rates_mbps))
        rows.append(f"[dim]Legacy Rates:[/dim] {rates} Mbps")
    akm_selected = getattr(client, "akm_selected", None)
    if akm_selected is not None:
        rows.append(f"[dim]Selected AKM:[/dim] {escape(_akm_label(akm_selected))}")
    if caps.listen_interval is not None:
        rows.append(f"[dim]Listen Interval:[/dim] {caps.listen_interval} beacons")
    pmf = "required" if caps.pmf_required else "capable" if caps.pmf_capable else None
    if pmf:
        rows.append(f"[dim]PMF:[/dim] {pmf}")
    power = []
    if caps.power_min_dbm is not None and caps.power_max_dbm is not None:
        power.append(f"{caps.power_min_dbm}..{caps.power_max_dbm} dBm")
    if caps.supported_channel_ranges:
        channels = ", ".join(
            f"{start}-{start + count - 1}" for start, count in caps.supported_channel_ranges
        )
        power.append(f"channels {channels}")
    if power:
        rows.append(f"[dim]Radio Limits:[/dim] {' · '.join(power)}")
    features = _feature_labels(caps)
    if features:
        rows.append(f"[dim]Features:[/dim] {' · '.join(features)}")
    wps = [caps.wps_manufacturer, caps.wps_model, caps.wps_device_name, caps.wps_device_type]
    if any(wps):
        rows.append(f"[dim]WPS Identity:[/dim] {escape(' · '.join(value for value in wps if value))}")
    if caps.vendor_ouis:
        rows.append(f"[dim]Vendor IEs:[/dim] {', '.join(sorted(caps.vendor_ouis))}")
    if caps.capability_flags:
        rows.append(f"[dim]Capability Flags:[/dim] {', '.join(sorted(caps.capability_flags))}")
    rows.extend(_enterprise_profile_rows(getattr(client, "enterprise", None)))
    probed_ssids = getattr(client, "probed_ssids", set())
    if probed_ssids:
        rows.append(
            f"[dim]Probed SSIDs:[/dim] {', '.join(escape(ssid) for ssid in sorted(probed_ssids))}"
        )
    return "\n".join(rows)


def _radio_summary(caps) -> str:
    parts = []
    if caps.phy_modes:
        parts.append("/".join(sorted(caps.phy_modes)))
    if caps.channel_widths_mhz:
        parts.append("/".join(str(width) for width in sorted(caps.channel_widths_mhz)) + " MHz")
    if caps.max_spatial_streams:
        parts.append(f"{caps.max_spatial_streams} spatial stream"
                     + ("s" if caps.max_spatial_streams != 1 else ""))
    return " · ".join(parts)


def channel_plain_summary(ap: AccessPoint) -> str:
    """Short, jargon-free operating-channel label for the router endpoint."""
    width = ap.capabilities.operating_width_mhz
    return (
        f"channel {ap.channel} · {width} MHz"
        if width is not None
        else f"channel {ap.channel}"
    )


def channel_technical_summary(ap: AccessPoint) -> str:
    """Primary/width/secondary/center details decoded from Operation IEs."""
    caps = ap.capabilities
    parts = [f"primary CH {ap.channel}"]
    width = caps.operating_width_mhz
    if width is not None:
        parts.append(f"{width} MHz")
    if width == 40 and caps.secondary_channel_offset in (-1, 1):
        direction = "above" if caps.secondary_channel_offset == 1 else "below"
        parts.append(f"secondary {direction}")
    centers = [
        center for center in (caps.center_channel_0, caps.center_channel_1)
        if center is not None
    ]
    if centers:
        label = "center CH" if len(centers) == 1 else "center segments"
        parts.append(f"{label} {'/'.join(str(center) for center in centers)}")
    elif width is None:
        parts.append("width not advertised")
    return " · ".join(parts)


def _feature_labels(caps) -> list[str]:
    labels = []
    for enabled, label in (
        (caps.radio_measurement, "802.11k"),
        (caps.fast_transition, "802.11r"),
        (caps.bss_transition, "802.11v"),
        (caps.wmm, "WMM/QoS"),
        (caps.multi_bssid, "Multi-BSSID"),
        (caps.reduced_neighbor_report, "RNR/6 GHz discovery"),
        (caps.multi_link, "MLO"),
    ):
        if enabled:
            labels.append(label)
    return labels


def _rate_label(rate: float) -> str:
    return str(int(rate)) if rate.is_integer() else str(rate)


def _plain_pmf(ap) -> str:
    if ap.pmf_required:
        return "required"
    if ap.pmf_capable:
        return "optional"
    return "disabled"


def _akm_label(suite: int) -> str:
    return {
        0x01: "EAP", 0x02: "PSK", 0x03: "FT-EAP", 0x04: "FT-PSK",
        0x05: "EAP-SHA256", 0x06: "PSK-SHA256", 0x08: "SAE", 0x09: "FT-SAE",
        0x12: "OWE", 0x18: "SAE-EXT-KEY", 0x19: "FT-SAE-EXT-KEY",
    }.get(suite, f"00-0F-AC:{suite}")



def status_under_dash(ap, array, now: float) -> list[str]:
    """The dashboard footer lines for this target."""
    active = Campaign.active
    if active:
        dash = active.status_under_dash(array, now)
        if dash is not None:
            return dash

    if is_wep(ap):
        return wep_status_lines(ap, array, None, now)
    lines = [f"[dim]Encryption:[/dim] {format_encryption_markup(ap, detailed=True)}"]
    parts = []
    if ap.akms or ap.wpa3:              # RSN (WPA2/3): PMF is meaningful
        parts.append(f"[dim]PMF:[/dim] {pmf_status_markup(ap)}")
    if getattr(ap, "wps", None):
        lock = "[red]🔒[/red]" if ap.wps_locked else "[green]🔓[/green]"
        ver = f"{ap.wps_version} " if ap.wps_version else ""
        parts.append(f"[dim]WPS:[/dim] {ver}{lock}")
    if parts:
        lines.append("  ·  ".join(parts))
    return lines


def deauth_blocked(ap) -> bool:
    """Deauth bursts are dead when a campaign owns the radio OR the AP requires PMF."""
    return other_long_running_tx() or ap.pmf_required


def status_under_card() -> str:
    """What the card is doing right now, shown under the card art (reads the active campaign)."""
    active = Campaign.active
    if active:
        status = active.status_under_card()
        if status is not None:
            return status
    return ""


def status_headlines(ap, array, vault) -> list[str]:
    """The Campaign headline: up to 3 markup lines of current activity (reads the active campaign)."""
    active = Campaign.active
    if active:
        headlines = active.status_headlines(vault)
        if headlines is not None:
            return headlines

    # Passive capture state (no active campaign on this AP)
    enc = (ap.encryption or "").upper()
    wep = enc == "WEP"

    # 4. Recovered credentials, when idle: WEP key / PSK (WPS- or handshake-derived).
    if ap.wep_key is not None or vault.has_wep_key(ap):
        return ["[black bold on green] ✓ WEP key recovered [/black bold on green]",
                "[dim]see the event log for the key[/dim]"]
    if vault.known_psk(ap):
        return ["[black bold on green] ✓ PSK recovered [/black bold on green]",
                "[dim]see the event log for the passphrase[/dim]"]

    if Config.is_silenced(ap.bssid):
        return ["[dim]● Silenced[/dim]",
                "[dim]campaigns off, handshakes ignored · press s to resume[/dim]"]

    # 4-5. Passive capture state: captured / partial / listening.
    if wep:
        n_ivs = ap.wep.unique_ivs if ap.wep else 0
        if n_ivs:
            return ["[green]● Listening for WEP IVs[/green]",
                    f"[dim]{n_ivs:,} captured · press Replay to generate more[/dim]"]
        return ["[green]● Listening for WEP IVs[/green]"]

    n_complete, n_partial, msg_counts = count_handshakes(ap)
    n_pmkid = sum(1 for hs in ap.handshakes.values() if hs.pmkid and pmkid_crackable(hs))
    if n_complete or n_pmkid:
        bits = []
        if n_complete:
            bits.append(f"handshake ×{n_complete}")
        if n_pmkid:
            bits.append(f"PMKID ×{n_pmkid}")
        return ["[black bold on green] ✓ Captured [/black bold on green] " + " · ".join(bits),
                f"[dim]saved to {Config.captures_dir}[/dim]"]
    if n_partial:
        breakdown = " · ".join(f"M{m}×{msg_counts[m]}" for m in sorted(msg_counts))
        return ["[yellow]◌ Capturing handshake[/yellow]",
                f"[dim]{breakdown}: deauth a client to force a re-handshake[/dim]"]

    if ap.wpa3 and not ap.transition_mode:
        return ["[dim]● WPA3/SAE: passive capture not applicable[/dim]"]

    if enc in ("OPEN", ""):
        return ["[dim]● Open network: no handshake to capture[/dim]"]
    return ["[green]● Listening for handshake + PMKID[/green]",
            "[dim]passive: deauth a client to force a handshake[/dim]"]


def client_dashboard_rows(client, ap) -> list[DashboardRow]:
    """Sparkline rows for Client Focus (AP family when associated, else station-centric)."""
    if ap is not None:
        return dashboard_rows(ap)
    return [
        DashboardRow("data", "data", "blue", 120),
        DashboardRow("deauth", "deauth", "red", 12),
    ]


def client_status_headlines(client, ap, *, honeypot_active: bool = False) -> list[str]:
    from wifit3.id import vendor_for_mac

    vendor = vendor_for_mac(client.mac) or "Unknown station"
    if honeypot_active:
        return [
            "[yellow]● Probe honeypot active[/yellow]",
            f"[dim]{escape(client.mac)} · {escape(vendor)}[/dim]",
        ]
    if ap is not None:
        ssid = truncate_ssid(ap.ssid) if ap.ssid else "‹hidden›"
        return [
            f"[bold cyan]{escape(client.mac)}[/bold cyan]",
            f"[dim]on [bold]{escape(ssid)}[/bold] · {escape(ap.bssid)}[/dim]",
        ]
    return [
        f"[bold cyan]{escape(client.mac)}[/bold cyan]",
        f"[dim]{escape(vendor)} · unassociated[/dim]",
    ]


def client_dashboard_bssid(client, ap, honeypot_campaign=None) -> str | None:
    if honeypot_campaign is not None and honeypot_campaign.endpoints:
        return honeypot_campaign.endpoints[0].bssid_text
    if ap is not None:
        return ap.bssid
    return None


def card_identity(array: WlanArray) -> tuple[str, str | None]:
    """``(chipset/label, own_bssid_or_None)`` for the card endpoint."""
    if array is None:
        return "no card", None
    if array.members is None or len(array.members) == 0:
        return "no card", None
    if len(array.members) > 1:
        return f"{len(array.members)} cards", None
    iface = array.preferred or array.members[0]
    label = iface.chipset
    if not label:
        # legacy fallback: strip the "(Make Model)" suffix off a description/name
        label = str(iface.description or iface.name or "card").split("(")[0].strip()
    label = label or "card"
    mac = iface.driver.mac_address
    if isinstance(mac, (bytes, bytearray)) and len(mac) == 6:
        mac = ":".join(f"{b:02x}" for b in mac)
    return str(label), (str(mac) if mac else None)

