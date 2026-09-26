from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import IntEnum

from wifit3.models import BluetoothCharacteristic, BluetoothInspection, BluetoothService

_BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

_SENSITIVE_SERVICES = {
    "fe59": "firmware update",
    "00001530-1212-efde-1523-785feabcd123": "legacy firmware update",
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "serial bridge",
    "1812": "keyboard/mouse input",
}

_WRITE_PROPERTIES = frozenset({"write", "write-without-response"})


class ExposureSeverity(IntEnum):
    """Ordered so that higher values are more serious."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class ExposureFinding:
    """One characteristic reachable over a connection that never paired."""

    handle: int
    service: str
    characteristic: str
    severity: ExposureSeverity
    reason: str


def assess_exposure(inspection: BluetoothInspection) -> list[ExposureFinding]:
    """Findings for characteristics exposed without pairing, most serious first."""
    findings = [
        finding
        for service in inspection.services
        for characteristic in service.characteristics
        if (finding := _assess_characteristic(service, characteristic)) is not None
    ]
    return sorted(findings, key=lambda finding: (-finding.severity, finding.handle))


def severity_counts(findings: list[ExposureFinding]) -> dict[ExposureSeverity, int]:
    """Number of findings at each severity, including severities with none."""
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts[severity] for severity in ExposureSeverity}


def _assess_characteristic(
    service: BluetoothService, characteristic: BluetoothCharacteristic
) -> ExposureFinding | None:
    sensitive_purpose = _SENSITIVE_SERVICES.get(_compact_uuid(service.uuid))
    if _WRITE_PROPERTIES.intersection(characteristic.properties):
        if sensitive_purpose is not None:
            severity = ExposureSeverity.HIGH
            reason = f"Advertises writes on a {sensitive_purpose} service without pairing"
        else:
            severity = ExposureSeverity.MEDIUM
            reason = "Advertises writes without pairing"
    elif characteristic.value:
        severity = ExposureSeverity.LOW
        reason = "Value obtained without pairing"
    else:
        return None
    return ExposureFinding(
        handle=characteristic.handle,
        service=service.name,
        characteristic=characteristic.name,
        severity=severity,
        reason=reason,
    )


def _compact_uuid(uuid: str) -> str:
    lowered = uuid.lower()
    if len(lowered) == 36 and lowered.startswith("0000") and lowered.endswith(_BASE_UUID_SUFFIX):
        return lowered[4:8]
    return lowered
