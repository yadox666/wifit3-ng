"""Client misconfiguration outcomes for the Enterprise EAP lab."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ClientOutcome(str, Enum):
    UNKNOWN = "unknown"
    REJECTED_LAB = "rejected_lab"
    INNER_PAP = "inner_pap_accepted"
    EMPTY_MSCHAP = "empty_mschap_accepted"
    INNER_CAPTURED = "inner_captured"
    EAP_SUCCESS = "eap_success"
    DHCP_ON_LAB = "dhcp_on_lab"


@dataclass(slots=True)
class EapLabClientRecord:
    client_mac: str
    outcome: ClientOutcome = ClientOutcome.UNKNOWN
    findings: list[str] = field(default_factory=list)
    outer_eap_method: int | None = None
    username: str | None = None
    client_cert_sha256: str | None = None
    dhcp_offered_ip: str | None = None
    last_detail: str = ""

    def add_finding(self, code: str, *, detail: str = "") -> None:
        if code not in self.findings:
            self.findings.append(code)
        if detail:
            self.last_detail = detail

    def set_outcome(self, outcome: ClientOutcome) -> None:
        if self.outcome == ClientOutcome.UNKNOWN or outcome != ClientOutcome.UNKNOWN:
            self.outcome = outcome

    def to_report_dict(self, *, lab_bssid: str) -> dict[str, Any]:
        return {
            "client_id": client_pseudonym(lab_bssid, self.client_mac),
            "outcome": self.outcome.value,
            "findings": list(self.findings),
            "outer_eap_method": self.outer_eap_method,
            "username": self.username,
            "client_cert_sha256": self.client_cert_sha256,
            "dhcp_offered_ip": self.dhcp_offered_ip,
            "detail": self.last_detail,
        }


def client_pseudonym(lab_bssid: str, client_mac: str) -> str:
    digest = hashlib.sha256(
        f"{lab_bssid.casefold()}|{client_mac.casefold()}".encode("ascii"),
    ).hexdigest()
    return digest[:16]


def order_eap_methods(methods: tuple[int, ...], *, weak_outer_first: bool) -> tuple[int, ...]:
    if not weak_outer_first or len(methods) < 2:
        return methods
    return tuple(reversed(methods))


def is_empty_nt_response(nt_response: bytes) -> bool:
    return len(nt_response) == 24 and nt_response == bytes(24)
