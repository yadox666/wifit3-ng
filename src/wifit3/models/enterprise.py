from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class EnterpriseCertificate:
    fingerprint: str
    not_before: float | None = None
    not_after: float | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None


@dataclass(slots=True)
class EnterpriseProfile:
    server_eap_types: set[int] = field(default_factory=set)
    client_eap_types: set[int] = field(default_factory=set)
    tls_versions: set[str] = field(default_factory=set)
    tls_cipher_suites: set[int] = field(default_factory=set)
    certificates: dict[str, EnterpriseCertificate] = field(default_factory=dict)
    eap_packets: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
