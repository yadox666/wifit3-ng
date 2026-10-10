"""Launch options for the Enterprise EAP lab honeypot and probe identities."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.eap import EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TLS_TYPES
from wifit3.wlan.array import fake_mac_rank

_DEFAULT_EAP_LAB_ENV = Path.home() / "Downloads/To_Test/eap-lab/lab.env"
_FALLBACK_LAB_USER = "labuser"


def parse_lab_identities(text: str) -> tuple[str, ...]:
    """Comma-separated identities only. Drops empties and anything that looks like a secret."""
    seen: list[str] = []
    for raw in text.replace(";", ",").split(","):
        item = raw.strip()
        if not item:
            continue
        lowered = item.casefold()
        if "=" in item or lowered.startswith("pass") or lowered.startswith("secret"):
            continue
        if item not in seen:
            seen.append(item)
    return tuple(seen)


def read_eap_lab_user(env_path: Path | None = None) -> str | None:
    """LAB_USER from eap-lab/lab.env. Never reads LAB_PASS or other secrets."""
    path = env_path or _DEFAULT_EAP_LAB_ENV
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() != "LAB_USER":
            continue
        user = value.strip().strip('"').strip("'")
        return user or None
    return None


def resolve_lab_identities(text: str | None = None) -> tuple[str, ...]:
    parsed = parse_lab_identities(text or "")
    if parsed:
        return parsed
    user = read_eap_lab_user()
    return (user,) if user else (_FALLBACK_LAB_USER,)


def lab_identities_field_value() -> str:
    return ", ".join(resolve_lab_identities())


def distinct_lab_ssid(ssid: str | None) -> str:
    """SSID phones can list separately from the real Enterprise AP."""
    base = (ssid or "").strip() or "EAP"
    if base.endswith("-LAB"):
        return base[:32]
    return f"{base}-LAB"[:32]


def advertised_lab_ssid(target_ssid: str | None, launch: EapLabLaunchConfig) -> str:
    custom = (launch.lab_ssid or "").strip()
    if custom:
        return custom[:32]
    if launch.distinct_ssid:
        return distinct_lab_ssid(target_ssid)
    return (target_ssid or "").strip() or "EAP-LAB"


@dataclass(frozen=True, slots=True)
class EapLabLaunchConfig:
    timeout: int
    eviction: bool = False
    punt_period_sec: float = 30.0
    eap_methods: tuple[int, ...] = (EAP_TYPE_PEAP, EAP_TYPE_TTLS, 13)
    request_client_cert: bool = False
    security_assessment: bool = True
    weak_outer_first: bool = True
    probe_inner_pap: bool = True
    probe_empty_mschap: bool = True
    lab_dhcp: bool = True
    lab_identities: tuple[str, ...] = ()
    distinct_ssid: bool = True
    lab_ssid: str = ""
    record_pcap: bool = True
    iface_name: str = ""
    lab_channel: int | None = None


@dataclass(frozen=True, slots=True)
class EnterpriseProbeConfig:
    lab_identities: tuple[str, ...] = ()
    iface_name: str = ""
    lab_channel: int | None = None
    record_pcap: bool = True


def methods_for_ap(ap) -> tuple[int, ...]:
    """Prefer methods observed on the target, else PEAP → TTLS → EAP-TLS."""
    observed = getattr(ap, "enterprise", None)
    server = set(getattr(observed, "server_eap_types", ()) or ())
    preferred = tuple(
        method for method in (EAP_TYPE_PEAP, EAP_TYPE_TTLS, 13) if method in server
    )
    if preferred:
        return preferred
    return (EAP_TYPE_PEAP, EAP_TYPE_TTLS, 13)


def tunneled_methods(methods: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(method for method in methods if method in EAP_TLS_TYPES)


def lab_host_ifaces(members) -> tuple:
    """Spoofable cards that can host the lab twin."""
    hosts = [
        member
        for member in members
        if getattr(getattr(member, "driver", None), "FAKE_MAC", None)
        is FakeMacSupport.SPOOFABLE
    ]
    return tuple(sorted(hosts, key=fake_mac_rank))


def channels_for_lab_iface(iface, target_channel: int) -> tuple[int, ...]:
    raw = getattr(iface, "supported_channels", None) if iface is not None else None
    channels = tuple(int(channel) for channel in (raw or ()) if int(channel) > 0)
    if channels:
        return channels
    return (target_channel,) if target_channel else ()


def default_lab_channel(iface, target_channel: int) -> int:
    channels = channels_for_lab_iface(iface, target_channel)
    if target_channel in channels:
        return target_channel
    return channels[0] if channels else target_channel


def resolve_lab_radio(
    members,
    *,
    iface_name: str = "",
    lab_channel: int | None = None,
    target_channel: int,
):
    """Pick the lab card and a channel that card actually supports."""
    hosts = lab_host_ifaces(members)
    picked = None
    if iface_name:
        picked = next((member for member in hosts if member.name == iface_name), None)
    if picked is None:
        wanted = lab_channel if lab_channel is not None else target_channel
        capable = [
            member
            for member in hosts
            if wanted in (getattr(member, "supported_channels", None) or ())
        ]
        pool = capable or list(hosts)
        picked = min(pool, key=fake_mac_rank, default=None)
    supported = channels_for_lab_iface(picked, target_channel)
    if lab_channel is not None and lab_channel in supported:
        channel = lab_channel
    else:
        channel = default_lab_channel(picked, target_channel)
    return picked, channel
