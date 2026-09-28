"""Launch options for the Enterprise EAP lab honeypot."""
from __future__ import annotations

from dataclasses import dataclass

from wifit3.dot11.eap import EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TLS_TYPES


@dataclass(frozen=True, slots=True)
class EapLabLaunchConfig:
    timeout: int
    eviction: bool = True
    punt_period_sec: float = 30.0
    eap_methods: tuple[int, ...] = (EAP_TYPE_PEAP, EAP_TYPE_TTLS, 13)
    request_client_cert: bool = True
    security_assessment: bool = True
    weak_outer_first: bool = True
    probe_inner_pap: bool = True
    probe_empty_mschap: bool = True
    lab_dhcp: bool = True


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
