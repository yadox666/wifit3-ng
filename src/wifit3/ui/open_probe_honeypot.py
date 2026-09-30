"""Shared probe-honeypot helpers for Scanner and Client Focus."""
from __future__ import annotations

from typing import TYPE_CHECKING

from wifit3.campaigns.open_probe_ap import OpenProbeApCampaign
from wifit3.dot11.ie import beacon_rsn_ie, compatible_wpa2_profile_ies, force_psk_akm
from wifit3.models import Client
from wifit3.persist.rsn_profiles import load_scan_rsn_profiles

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp


def honeypot_rsn_profile(app: WifiteApp, ssid: str, channel: int) -> tuple[bytes | None, str, bytes]:
    def same_band(candidate: int) -> bool:
        return (candidate <= 14) == (channel <= 14)

    array = app.array
    if array is not None:
        live = sorted(
            (
                ap for ap in array.access_points.values()
                if ap.ssid == ssid
                and not ap.is_own_fake
                and 2 in ap.akm_suites
                and beacon_rsn_ie(ap.last_beacon_frame) is not None
            ),
            key=lambda ap: (same_band(ap.channel), ap.last_seen),
            reverse=True,
        )
        for ap in live:
            rsn_ie = beacon_rsn_ie(ap.last_beacon_frame)
            compatible = force_psk_akm(
                rsn_ie or b"",
                pmf_capable=ap.pmf_capable,
            )
            if compatible is not None:
                source_ies = (
                    ap.last_beacon_frame[36:]
                    if ap.last_beacon_frame is not None
                    else b""
                )
                return (
                    compatible,
                    f"live AP {ap.bssid} · compatible security/capability clone",
                    compatible_wpa2_profile_ies(source_ies, channel),
                )

    profile_store = getattr(app, "wifi_profile_store", None)
    if profile_store is not None:
        stored = sorted(
            (
                profile for profile in profile_store.profiles_for_ssid(ssid)
                if 2 in profile.akm_suites
            ),
            key=lambda profile: (
                same_band(profile.channel),
                profile.last_seen,
            ),
            reverse=True,
        )
        for profile in stored:
            compatible = force_psk_akm(
                profile.rsn_ie,
                pmf_capable=profile.pmf_capable,
            )
            if compatible is not None:
                return (
                    compatible,
                    f"saved AP profile {profile.bssid} · "
                    "compatible security/capability clone",
                    compatible_wpa2_profile_ies(profile.ies, channel),
                )

    history = sorted(
        (
            profile for profile in load_scan_rsn_profiles(ssid)
            if 2 in profile.akm_suites
        ),
        key=lambda profile: same_band(profile.channel),
        reverse=True,
    )
    for profile in history:
        compatible = force_psk_akm(
            profile.rsn_ie,
            pmf_capable=profile.pmf_capable,
        )
        if compatible is not None:
            return (
                compatible,
                f"scan history {profile.source_file} · "
                f"{profile.bssid} · PSK-compatible RSN clone",
                b"",
            )
    return None, "generic WPA2-PSK/CCMP fallback", b""


def start_open_probe_test(
    app: WifiteApp,
    client: Client,
    ssid: str,
    timeout: int,
    encryption: str,
) -> OpenProbeApCampaign | None:
    array = app.array
    observation = client.probe_observations.get(ssid)
    if array is None or observation is None:
        return None
    rsn_ie, rsn_source, profile_ies = (
        honeypot_rsn_profile(app, ssid, observation.channel)
        if encryption in ("WPA2", "BOTH")
        else (None, "OPEN", b"")
    )
    campaign = OpenProbeApCampaign(
        array,
        client,
        ssid,
        observation.channel,
        timeout=timeout,
        encryption=encryption,
        rsn_ie=rsn_ie,
        rsn_source=rsn_source,
        profile_ies=profile_ies,
    )
    if campaign.iface is None:
        return None
    if not campaign.run():
        return None
    return campaign
