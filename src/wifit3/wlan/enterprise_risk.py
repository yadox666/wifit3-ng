from __future__ import annotations

import time
from dataclasses import dataclass

from wifit3.dot11.enterprise import EAP_TYPE_NAMES


TLS_CIPHER_NAMES = {
    0x0004: "RSA-RC4-MD5",
    0x0005: "RSA-RC4-SHA",
    0x000A: "RSA-3DES-SHA",
    0x0013: "DHE-DSS-3DES-SHA",
    0x0016: "DHE-RSA-3DES-SHA",
    0x002F: "RSA-AES128-SHA",
    0x0035: "RSA-AES256-SHA",
    0x009C: "RSA-AES128-GCM-SHA256",
    0x009D: "RSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0x1301: "TLS-AES-128-GCM-SHA256",
    0x1302: "TLS-AES-256-GCM-SHA384",
    0x1303: "TLS-CHACHA20-POLY1305-SHA256",
}
WEAK_TLS_CIPHERS = {0x0004, 0x0005, 0x000A, 0x0013, 0x0016}


@dataclass(frozen=True, slots=True)
class EnterpriseFinding:
    severity: int
    label: str
    evidence: str
    confidence: str


def is_enterprise_ap(ap) -> bool:
    return any("EAP" in akm or "SUITE-B" in akm for akm in getattr(ap, "akms", ()))


def enterprise_findings(ap) -> list[EnterpriseFinding]:
    findings = []
    encryption = (ap.encryption or "").upper()
    enterprise = is_enterprise_ap(ap)
    if encryption == "WEP":
        findings.append(EnterpriseFinding(
            4, "WEP is cryptographically broken", "Advertised privacy suite", "high",
        ))
    if "WPA" in encryption and "WPA2" not in encryption and "WPA3" not in encryption:
        findings.append(EnterpriseFinding(
            3, "Legacy WPA mode", "Advertised security mode", "high",
        ))
    if "TKIP" in encryption or ap.group_cipher == "TKIP" or "TKIP" in ap.pairwise_ciphers:
        findings.append(EnterpriseFinding(
            3, "TKIP is deprecated", "Advertised cipher suite", "high",
        ))
    if enterprise and not ap.pmf_capable:
        findings.append(EnterpriseFinding(
            2, "Management-frame protection unavailable", "RSN capabilities", "high",
        ))
    elif enterprise and not ap.pmf_required:
        findings.append(EnterpriseFinding(
            1, "Management-frame protection optional", "RSN capabilities", "high",
        ))

    methods = ap.enterprise.server_eap_types | ap.enterprise.client_eap_types
    method_findings = {
        4: (3, "EAP-MD5 lacks mutual authentication"),
        17: (4, "LEAP is vulnerable to password recovery"),
        26: (3, "Direct EAP-MSCHAPv2 is vulnerable to offline password attacks"),
    }
    for method, (severity, label) in method_findings.items():
        if method in methods:
            findings.append(EnterpriseFinding(
                severity,
                label,
                f"Observed {EAP_TYPE_NAMES[method]} exchange",
                "high",
            ))
    for method in sorted(methods & {21, 25, 43}):
        findings.append(EnterpriseFinding(
            0,
            f"{EAP_TYPE_NAMES[method]} security depends on client certificate validation",
            "Observed outer EAP method; inner method remains encrypted",
            "medium",
        ))
    for version in sorted(ap.enterprise.tls_versions & {"TLS 1.0", "TLS 1.1"}):
        findings.append(EnterpriseFinding(
            3, f"{version} is obsolete", "Observed outer EAP TLS handshake", "high",
        ))
    for cipher in sorted(ap.enterprise.tls_cipher_suites & WEAK_TLS_CIPHERS):
        findings.append(EnterpriseFinding(
            3,
            f"Weak TLS cipher {tls_cipher_name(cipher)}",
            "Observed ServerHello",
            "high",
        ))
    now = time.time()
    certificates = list(ap.enterprise.certificates.values())
    for certificate in certificates:
        name = certificate.fingerprint[:12]
        if certificate.not_after is not None and certificate.not_after < now:
            findings.append(EnterpriseFinding(
                3, f"Expired RADIUS certificate: {name}", "Observed certificate", "high",
            ))
        if certificate.not_before is not None and certificate.not_before > now:
            findings.append(EnterpriseFinding(
                3, f"RADIUS certificate is not yet valid: {name}",
                "Observed certificate", "high",
            ))
        if certificate.signature_algorithm in {"RSA-MD5", "RSA-SHA1"}:
            findings.append(EnterpriseFinding(
                3,
                f"Weak certificate signature {certificate.signature_algorithm}",
                f"Observed certificate: {name}",
                "high",
            ))
        if (
            certificate.public_key_algorithm == "RSA"
            and certificate.public_key_bits is not None
            and certificate.public_key_bits < 2048
        ):
            findings.append(EnterpriseFinding(
                2,
                f"Short RSA certificate key ({certificate.public_key_bits} bits)",
                f"Observed certificate: {name}",
                "high",
            ))
        if (
            certificate.public_key_algorithm == "EC"
            and certificate.public_key_bits is not None
            and certificate.public_key_bits < 256
        ):
            findings.append(EnterpriseFinding(
                2,
                f"Short EC certificate key ({certificate.public_key_bits} bits)",
                f"Observed certificate: {name}",
                "high",
            ))
    if certificates:
        leaf = certificates[0]
        leaf_name = leaf.fingerprint[:12]
        if leaf.extended_key_usage and "serverAuth" not in leaf.extended_key_usage:
            findings.append(EnterpriseFinding(
                3,
                "RADIUS leaf certificate lacks serverAuth EKU",
                f"Observed leaf certificate: {leaf_name}",
                "high",
            ))
        if leaf.is_ca:
            findings.append(EnterpriseFinding(
                2,
                "RADIUS leaf certificate is marked as a CA",
                f"Observed leaf certificate: {leaf_name}",
                "high",
            ))
        if leaf.subject and not leaf.san_dns:
            findings.append(EnterpriseFinding(
                1,
                "RADIUS leaf certificate has no DNS SAN",
                f"Observed leaf certificate: {leaf_name}",
                "medium",
            ))
        subjects = {
            certificate.subject
            for certificate in certificates
            if certificate.subject
        }
        if (
            leaf.issuer
            and leaf.issuer != leaf.subject
            and leaf.issuer not in subjects
        ):
            findings.append(EnterpriseFinding(
                1,
                "RADIUS certificate chain appears incomplete",
                f"Leaf issuer not present in observed chain: {leaf.issuer}",
                "medium",
            ))
        for child, parent in zip(certificates, certificates[1:]):
            if child.issuer and parent.subject and child.issuer != parent.subject:
                findings.append(EnterpriseFinding(
                    2,
                    "RADIUS certificate chain issuer mismatch",
                    f"{child.fingerprint[:12]} issuer does not match {parent.fingerprint[:12]}",
                    "high",
                ))
    return sorted(findings, key=lambda finding: (-finding.severity, finding.label))


def tls_cipher_name(cipher: int) -> str:
    return TLS_CIPHER_NAMES.get(cipher, f"0x{cipher:04X}")
