from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class EnterpriseCertificate:
    fingerprint: str
    not_before: float | None = None
    not_after: float | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
    subject: str | None = None
    issuer: str | None = None
    san_dns: tuple[str, ...] = ()
    extended_key_usage: tuple[str, ...] = ()
    is_ca: bool | None = None


@dataclass(slots=True)
class EnterpriseSession:
    client_id: str
    first_seen: float
    last_seen: float
    source: str = "passive"
    eap_packets: int = 0
    server_eap_types: set[int] = field(default_factory=set)
    client_eap_types: set[int] = field(default_factory=set)
    nak_eap_types: set[int] = field(default_factory=set)
    tls_versions: set[str] = field(default_factory=set)
    tls_client_versions: set[str] = field(default_factory=set)
    tls_cipher_suites: set[int] = field(default_factory=set)
    tls_client_cipher_suites: set[int] = field(default_factory=set)
    certificate_fingerprints: set[str] = field(default_factory=set)
    outcome: str = "in_progress"


@dataclass(frozen=True, slots=True)
class EnterpriseProbeEvent:
    timestamp: float
    phase: str
    detail: str
    direction: str | None = None
    eap_identifier: int | None = None
    eap_type: int | None = None


@dataclass(slots=True)
class EnterpriseProbeRun:
    started_at: float
    ended_at: float
    status: str
    detail: str
    association_ok: bool = False
    eap_method: int | None = None
    events: list[EnterpriseProbeEvent] = field(default_factory=list)


@dataclass(slots=True)
class EnterpriseProfile:
    server_eap_types: set[int] = field(default_factory=set)
    client_eap_types: set[int] = field(default_factory=set)
    nak_eap_types: set[int] = field(default_factory=set)
    tls_versions: set[str] = field(default_factory=set)
    tls_client_versions: set[str] = field(default_factory=set)
    tls_cipher_suites: set[int] = field(default_factory=set)
    tls_client_cipher_suites: set[int] = field(default_factory=set)
    tls_server_names: set[str] = field(default_factory=set)
    tls_supported_groups: set[int] = field(default_factory=set)
    tls_signature_algorithms: set[int] = field(default_factory=set)
    certificates: dict[str, EnterpriseCertificate] = field(default_factory=dict)
    sessions: list[EnterpriseSession] = field(default_factory=list)
    eap_packets: int = 0
    eap_requests: int = 0
    eap_responses: int = 0
    eap_successes: int = 0
    eap_failures: int = 0
    probe_attempts: int = 0
    probe_last_status: str | None = None
    probe_last_detail: str | None = None
    probe_last_seen: float | None = None
    probe_history: list[EnterpriseProbeRun] = field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
