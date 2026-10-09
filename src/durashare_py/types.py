"""Share, manifest, and recovery records."""

from dataclasses import dataclass, field


@dataclass
class DigitalProfile:
    """One Full or Compact envelope attached to a share."""

    payload: bytes
    audit_hash: bytes
    audit_payload: bytes
    transport_hash: bytes | None = None


@dataclass
class ShareDigital:
    full: DigitalProfile
    compact: DigitalProfile


@dataclass
class Share:
    """One arithmetic share, plus optional MAT tags and hex envelopes."""

    share_number: int
    word_shares: list[int]
    checksum_shares: list[int] = field(default_factory=list)
    column_checksum_shares: list[int] = field(default_factory=list)
    global_integrity_check_share: int | None = None
    mat_mode: str = "none"
    mat_tags: list[list[int]] = field(default_factory=list)
    digital: ShareDigital | None = None


@dataclass
class MatColumn:
    column: int
    weights: list[int]
    row_pads: list[int]


@dataclass
class MatShareKeys:
    share_number: int
    columns: list[MatColumn] = field(default_factory=list)


@dataclass
class Manifest:
    kind: str
    mat_mode: str
    mat_custody: str
    share_keys: list[MatShareKeys]


@dataclass
class SessionProfile:
    batch_id: bytes
    rbt: bytes
    manifest_header_payload: bytes


@dataclass
class DigitalSession:
    protocol_version: int
    language_input: int
    word_count: int
    threshold: int
    wallet_profile_code: int
    full: SessionProfile
    compact: SessionProfile
    rva_note: str | None = None


@dataclass
class SharingArtifacts:
    shares: list[Share]
    manifests: list[Manifest]
    session: DigitalSession | None = None
    rva_note: str | None = None


@dataclass
class StatusSummary:
    status: str
    passed: int = 0
    failed: int = 0


@dataclass
class RbtOutcome:
    profile: str
    sources: list[str]
    source_label: str
    status: str


@dataclass
class RbtValidation:
    status: str = "not-checked"
    checked_profiles: list[str] = field(default_factory=list)
    outcomes: list[RbtOutcome] = field(default_factory=list)
    has_conflict: bool = False


@dataclass
class EvidenceState:
    state: str
    label: str
    copy: str
    coverage: int = 0
    coverage_total: int = 0


@dataclass
class RecoveryErrors:
    bip39: bool = False
    generic: str | None = None


@dataclass
class RecoveryReport:
    """Candidate mnemonic is separate from the convenience success flag.

    `recovered_mnemonic` is set when interpolation yields indices in 1..2048.
    `success` is true only when supplied checksums, BIP39, and every supplied
    RBT all agree. `mnemonic` exposes the phrase only in that case.
    """

    recovered_mnemonic: str | None = None
    recovered_indices: list[int] | None = None
    errors: RecoveryErrors = field(default_factory=RecoveryErrors)
    bip39: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    rbt: RbtValidation = field(default_factory=RbtValidation)
    checksums: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    manifest_audit: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    mat: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    payload_integrity: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    manifest_header: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    rbt_artifacts: StatusSummary = field(default_factory=lambda: StatusSummary("not-checked"))
    confidence: EvidenceState = field(
        default_factory=lambda: EvidenceState("low-confidence", "LOW CONFIDENCE", "")
    )
    kit_health: EvidenceState = field(
        default_factory=lambda: EvidenceState("not-assessed", "NOT ASSESSED", "")
    )
    success: bool = False

    @property
    def mnemonic(self) -> str | None:
        if not self.success:
            return None
        return self.recovered_mnemonic
