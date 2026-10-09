"""Recovery report.

Interpolation is separate from kit health. The convenience `mnemonic` property
is populated only when supplied checksums, BIP39, and every supplied RBT agree.
"""

import re
from collections.abc import Sequence

from .checksums import WORDS_PER_ROW, audit_optional_checksums, compute_row_total, is_supplied_field
from .envelope import (
    PROFILE_COMPACT,
    PROFILE_FULL,
    DecodedManifestHeader,
    DecodedSharePayload,
    audit_evidence_agrees,
    build_canonical_secret_material,
    bytes_to_hex,
    decode_manifest_audit_evidence_hex,
    derive_rbt,
    hex_to_bytes,
    session_header_agrees,
    validate_recovery_payload_set,
)
from .errors import CryptoHardStopError
from .field import FIELD_PRIME, is_int, mod, mod_add, mod_mul
from .lagrange import compute_lagrange_multipliers, lagrange_interpolate_at_zero
from .mat import audit_mat_column
from .security import clear_sensitive_array, constant_time_string_equal
from .seed import validate_bip39_mnemonic
from .types import (
    EvidenceState,
    MatShareKeys,
    RbtOutcome,
    RecoveryErrors,
    RecoveryReport,
    Share,
    StatusSummary,
)

_HEX_FULL_BATCH = re.compile(r"^[0-9A-F]{16}$")
_HEX_COMPACT_BATCH = re.compile(r"^[0-9A-F]{8}$")
_HEX_FULL_RBT = re.compile(r"^[0-9A-F]{24}$")
_HEX_COMPACT_RBT = re.compile(r"^[0-9A-F]{12}$")


def _summary(status: str, passed: int = 0, failed: int = 0) -> StatusSummary:
    return StatusSummary(status, passed, failed)


def _rbt_confidence_counts(report: RecoveryReport) -> tuple[int, int]:
    passed = sum(1 for outcome in report.rbt.outcomes if outcome.status == "pass")
    failed = sum(1 for outcome in report.rbt.outcomes if outcome.status == "fail")
    return passed, failed


def _derive_confidence(report: RecoveryReport) -> EvidenceState:
    passed, failed = _rbt_confidence_counts(report)
    bip39_status = report.bip39.status
    if passed > 0 and bip39_status == "pass":
        if report.rbt.has_conflict:
            copy = (
                "At least one RBT confirms this candidate, but another RBT source disagrees. "
                "Review Backup Kit Health before preserving the artifacts."
            )
        else:
            copy = (
                "The candidate is bound to the sharing session by RBT "
                "and is a well-formed BIP39 mnemonic."
            )
        return EvidenceState("confirmed", "CONFIRMED", copy)
    if passed > 0:
        return EvidenceState(
            "anomaly",
            "ANOMALY",
            "RBT identifies the shared protocol input, but the candidate fails BIP39 validation. "
            "Stop and investigate the mismatch.",
        )
    if failed > 0:
        return EvidenceState(
            "mismatch",
            "MISMATCH",
            "Available RBT evidence does not bind this candidate to the sharing session, "
            "even if the words form a valid BIP39 mnemonic.",
        )
    if bip39_status == "pass":
        return EvidenceState(
            "plausible",
            "PLAUSIBLE — NOT SESSION-BOUND",
            "The candidate is valid BIP39, but no RBT evidence was available to identify it "
            "as the phrase originally shared.",
        )
    return EvidenceState(
        "low-confidence",
        "LOW CONFIDENCE",
        "No RBT evidence identified the candidate, and it is not a valid BIP39 mnemonic.",
    )


def _derive_kit_health(families: list[StatusSummary]) -> EvidenceState:
    coverage = sum(1 for family in families if family.passed + family.failed > 0)
    has_problem = any(family.failed > 0 for family in families)
    has_evidence = any(family.passed > 0 for family in families)
    total = len(families)
    if has_problem:
        return EvidenceState(
            "problems",
            "PROBLEMS DETECTED",
            (
                "At least one supplied artifact check disagreed. "
                f"Evidence coverage: {coverage} of {total} check families."
            ),
            coverage,
            total,
        )
    if has_evidence:
        return EvidenceState(
            "consistent",
            "CONSISTENT",
            (
                "No supplied artifact check disagreed. "
                f"Evidence coverage: {coverage} of {total} check families."
            ),
            coverage,
            total,
        )
    return EvidenceState(
        "not-assessed",
        "NOT ASSESSED",
        (
            "No backup-artifact cross-check was completed. "
            f"Evidence coverage: 0 of {total} check families."
        ),
        0,
        total,
    )


def _checksum_family(shares: list[Share], word_count: int) -> StatusSummary:
    row_count = word_count // WORDS_PER_ROW
    row_total = compute_row_total(row_count)
    failed = 0
    passed = 0
    for share in shares:
        checksums: list[int | None] = list(share.checksum_shares)
        columns: list[int | None] = list(share.column_checksum_shares)
        audit = audit_optional_checksums(
            share.share_number,
            share.word_shares,
            checksums,
            columns,
            share.global_integrity_check_share,
            row_count,
            row_total,
        )
        problems = (
            len(audit["row_fails"]) + len(audit["col_fails"]) + (1 if audit["gic_fail"] else 0)
        )
        supplied = sum(1 for value in checksums if is_supplied_field(value))
        supplied += sum(1 for value in columns if is_supplied_field(value))
        if is_supplied_field(share.global_integrity_check_share):
            supplied += 1
        if problems:
            failed += problems
        elif supplied:
            passed += 1
    if failed:
        return _summary("fail", passed, failed)
    if passed:
        return _summary("pass", passed, 0)
    return _summary("not-checked")


def _validate_shares(shares: list[Share], word_count: int) -> None:
    for index, share in enumerate(shares):
        if not is_int(share.share_number):
            raise ValueError(f"Share #{index + 1} share number must be an integer inside GF(2053).")
        if share.share_number <= 0 or share.share_number >= FIELD_PRIME:
            raise ValueError(
                f"Share #{index + 1} is missing a valid share number (1-{FIELD_PRIME - 1})."
            )
        if len(share.word_shares) != word_count:
            raise ValueError(
                f"Share #{share.share_number} does not contain {word_count} word values."
            )
        for word_index, value in enumerate(share.word_shares):
            if not is_int(value):
                raise ValueError(
                    f"Word share #{word_index + 1} (share {share.share_number}) "
                    "must be an integer inside GF(2053)."
                )
            if value < 0 or value >= FIELD_PRIME:
                raise ValueError(
                    f"Word share #{word_index + 1} (share {share.share_number}) "
                    f"must be between 0 and {FIELD_PRIME - 1}."
                )


def _ensure_distinct(shares: list[Share]) -> None:
    seen: set[int] = set()
    for share in shares:
        if share.share_number in seen:
            raise ValueError("Duplicate share numbers detected.")
        seen.add(share.share_number)


def _apply_rbt(
    report: RecoveryReport,
    payloads: Sequence[DecodedSharePayload | None] | None,
    manifest_header: DecodedManifestHeader | None,
    word_count: int,
    recovered_words: list[int],
) -> None:
    pending: list[tuple[str, str, str, str]] = []
    if payloads is not None:
        for metadata in payloads:
            if metadata is None or metadata.word_count != word_count:
                continue
            kind = "Full" if metadata.profile == PROFILE_FULL else "Compact"
            pending.append(
                (
                    metadata.profile,
                    metadata.session_batch_id_hex.upper(),
                    metadata.rbt_hex.upper(),
                    f"Share #{metadata.share_number} {kind} payload",
                )
            )
    if manifest_header is not None and manifest_header.word_count == word_count:
        pending.append(
            (
                manifest_header.profile,
                manifest_header.session_batch_id_hex.upper(),
                manifest_header.rbt_hex.upper(),
                "Manifest Header (SB)",
            )
        )
    usable = []
    for profile, batch_hex, rbt_hex, label in pending:
        if profile == PROFILE_FULL and (
            _HEX_FULL_BATCH.fullmatch(batch_hex) is None or _HEX_FULL_RBT.fullmatch(rbt_hex) is None
        ):
            continue
        if profile == PROFILE_COMPACT and (
            _HEX_COMPACT_BATCH.fullmatch(batch_hex) is None
            or _HEX_COMPACT_RBT.fullmatch(rbt_hex) is None
        ):
            continue
        if profile not in (PROFILE_FULL, PROFILE_COMPACT):
            continue
        usable.append((profile, batch_hex, rbt_hex, label))
    if not usable:
        return
    canonical = bytearray(build_canonical_secret_material(recovered_words))
    scratch: list[bytearray] = [canonical]
    try:
        for profile, batch_hex, rbt_hex, label in usable:
            batch = hex_to_bytes(batch_hex, f"Recovered {profile} Session Batch ID")
            scratch.append(batch)
            expected = bytearray(
                derive_rbt(bytes(canonical), bytes(batch), 12 if profile == PROFILE_FULL else 6)
            )
            scratch.append(expected)
            status = (
                "pass"
                if constant_time_string_equal(bytes_to_hex(bytes(expected)), rbt_hex)
                else "fail"
            )
            source = "manifest-header" if label.startswith("Manifest") else "share-payload"
            report.rbt.outcomes.append(RbtOutcome(profile, [source], label, status))
            if profile not in report.rbt.checked_profiles:
                report.rbt.checked_profiles.append(profile)
        has_match = any(outcome.status == "pass" for outcome in report.rbt.outcomes)
        has_mismatch = any(outcome.status == "fail" for outcome in report.rbt.outcomes)
        report.rbt.status = "pass" if has_match else "fail"
        report.rbt.has_conflict = has_match and has_mismatch
        if has_mismatch:
            report.rbt_artifacts = _summary(
                "fail",
                sum(1 for outcome in report.rbt.outcomes if outcome.status == "pass"),
                sum(1 for outcome in report.rbt.outcomes if outcome.status == "fail"),
            )
        else:
            report.rbt_artifacts = _summary("pass", len(report.rbt.outcomes), 0)
    finally:
        for buffer in scratch:
            clear_sensitive_array(buffer)


def _present_payloads(
    payload_metadata: Sequence[DecodedSharePayload | None] | None,
) -> list[DecodedSharePayload]:
    if payload_metadata is None:
        return []
    return [payload for payload in payload_metadata if payload is not None]


def _payload_integrity(
    payload_metadata: Sequence[DecodedSharePayload | None] | None,
    shares: list[Share],
    word_count: int,
) -> StatusSummary:
    present = _present_payloads(payload_metadata)
    if payload_metadata is None or len(present) == 0:
        return _summary("not-checked")
    try:
        validate_recovery_payload_set(list(payload_metadata), shares, word_count)
    except ValueError:
        return _summary("fail", 0, len(present))
    return _summary("pass", len(present), 0)


def _manifest_header_family(
    manifest_header: DecodedManifestHeader | None,
    payload_metadata: Sequence[DecodedSharePayload | None] | None,
) -> StatusSummary:
    if manifest_header is None:
        return _summary("not-checked")
    present = _present_payloads(payload_metadata)
    if len(present) == 0:
        return _summary("not-checked")
    if all(session_header_agrees(manifest_header, payload) for payload in present):
        return _summary("pass", 1, 0)
    return _summary("fail", 0, 1)


def _manifest_audit_family(
    audit_evidence_hex: Sequence[str | None] | None,
    payload_metadata: Sequence[DecodedSharePayload | None] | None,
) -> StatusSummary:
    if audit_evidence_hex is None:
        return _summary("not-checked")
    payloads = list(payload_metadata) if payload_metadata is not None else []
    passed = 0
    failed = 0
    for index, raw in enumerate(audit_evidence_hex):
        if raw is None or raw.strip() == "":
            continue
        try:
            evidence = decode_manifest_audit_evidence_hex(raw)
        except ValueError:
            failed += 1
            continue
        payload = payloads[index] if index < len(payloads) else None
        if payload is None:
            continue
        if audit_evidence_agrees(evidence, payload):
            passed += 1
        else:
            failed += 1
    if failed:
        return _summary("fail", passed, failed)
    if passed:
        return _summary("pass", passed, 0)
    return _summary("not-checked")


def _mat_family(shares: list[Share], mat_keys: Sequence[MatShareKeys] | None) -> StatusSummary:
    if mat_keys is None:
        return _summary("not-checked")
    if len(mat_keys) != len(shares):
        return _summary("fail", 0, 1)
    passed = 0
    failed = 0
    for share, entry in zip(shares, mat_keys, strict=True):
        row_count = len(share.word_shares) // WORDS_PER_ROW
        if entry.share_number != share.share_number or row_count == 0:
            failed += 1
            continue
        for column_index, column in enumerate(entry.columns):
            tags: list[int | None] = []
            if column_index < len(share.mat_tags):
                tags.extend(share.mat_tags[column_index])
            if len(tags) < row_count:
                tags.extend([None] * (row_count - len(tags)))
            pads: list[int | None] = []
            pads.extend(column.row_pads)
            if len(pads) < row_count:
                pads.extend([None] * (row_count - len(pads)))
            try:
                column_audit = audit_mat_column(
                    share.word_shares,
                    tags[:row_count],
                    column.weights,
                    pads[:row_count],
                )
            except ValueError:
                failed += 1
                continue
            passed += len(column_audit["matched_rows"])
            failed += len(column_audit["failed_rows"])
    if failed:
        return _summary("fail", passed, failed)
    if passed:
        return _summary("pass", passed, 0)
    return _summary("not-checked")


def _success(report: RecoveryReport) -> bool:
    if report.errors.generic is not None or report.recovered_mnemonic is None:
        return False
    if report.checksums.status == "fail" or report.bip39.status != "pass":
        return False
    if any(outcome.status == "fail" for outcome in report.rbt.outcomes):
        return False
    if report.rbt.has_conflict:
        return False
    return True


def recover_and_validate(
    shares: list[Share],
    word_count: int,
    wordlist: list[str] | None = None,
    *,
    payload_metadata: Sequence[DecodedSharePayload | None] | None = None,
    manifest_header: DecodedManifestHeader | None = None,
    audit_evidence_hex: Sequence[str | None] | None = None,
    mat_keys: Sequence[MatShareKeys] | None = None,
) -> RecoveryReport:
    """Interpolate a candidate and attach confidence and kit-health statuses.

    Payload integrity, SB, Manifest Audit, and MAT stay not-checked until that
    material is supplied. A valid SB with no share payload stays not-checked.
    """
    report = RecoveryReport()
    recovered_words: list[int] = []
    try:
        if len(shares) < 2:
            report.errors.generic = "At least two shares are required for recovery."
            return report
        if word_count not in (12, 15, 18, 21, 24):
            report.errors.generic = (
                "This tool currently supports only 12, 15, 18, 21, or 24-word mnemonics."
            )
            return report
        if word_count % WORDS_PER_ROW != 0:
            report.errors.generic = "Word count must be divisible by the words per row constant."
            return report
        _validate_shares(shares, word_count)
        _ensure_distinct(shares)
        share_numbers = [share.share_number for share in shares]
        multipliers = compute_lagrange_multipliers(share_numbers)
        sanity = 0
        for coef, share_number in zip(multipliers, share_numbers, strict=True):
            sanity = mod_add(sanity, mod_mul(coef, mod(share_number)))
        if sanity != 0:
            report.errors.generic = (
                "Lagrange coefficient sanity check failed. Verify share numbers and coefficients."
            )
            return report

        for index in range(word_count):
            points = [(share.share_number, share.word_shares[index]) for share in shares]
            recovered_words.append(lagrange_interpolate_at_zero(points))

        can_form = True
        for index, value in enumerate(recovered_words):
            if value < 1 or value > 2048:
                report.errors.generic = (
                    f'Recovered word #{index + 1} ("{value}") is outside the BIP39 range (1–2048). '
                    "Cannot form a valid mnemonic."
                )
                can_form = False
                break
        report.checksums = _checksum_family(shares, word_count)
        report.payload_integrity = _payload_integrity(payload_metadata, shares, word_count)
        report.manifest_header = _manifest_header_family(manifest_header, payload_metadata)
        report.manifest_audit = _manifest_audit_family(audit_evidence_hex, payload_metadata)
        report.mat = _mat_family(shares, mat_keys)
        if can_form:
            if wordlist is None:
                from mnemonic import Mnemonic

                wordlist = Mnemonic("english").wordlist
            mnemonic = " ".join(wordlist[index - 1] for index in recovered_words)
            report.recovered_mnemonic = mnemonic
            report.recovered_indices = recovered_words.copy()
            try:
                if validate_bip39_mnemonic(mnemonic, wordlist):
                    report.bip39 = _summary("pass", 1, 0)
                else:
                    report.errors.bip39 = True
                    report.bip39 = _summary("fail", 0, 1)
            except CryptoHardStopError:
                raise
            _apply_rbt(report, payload_metadata, manifest_header, word_count, recovered_words)
        report.confidence = _derive_confidence(report)
        report.kit_health = _derive_kit_health(
            [
                report.manifest_audit,
                report.mat,
                report.payload_integrity,
                report.checksums,
                report.manifest_header,
                report.rbt_artifacts,
            ]
        )
        report.success = _success(report)
        return report
    except CryptoHardStopError:
        raise
    except Exception as error:
        report.errors = RecoveryErrors(generic=str(error))
        report.success = False
        return report
    finally:
        clear_sensitive_array(recovered_words)


def recover_mnemonic(
    shares: list[Share],
    word_count: int,
    wordlist: list[str] | None = None,
    *,
    strict_validation: bool = True,
    payload_metadata: Sequence[DecodedSharePayload | None] | None = None,
    manifest_header: DecodedManifestHeader | None = None,
    audit_evidence_hex: Sequence[str | None] | None = None,
    mat_keys: Sequence[MatShareKeys] | None = None,
) -> RecoveryReport:
    """Same report as recover_and_validate. Read `.mnemonic` only when `.success` is true."""
    del strict_validation
    return recover_and_validate(
        shares,
        word_count,
        wordlist,
        payload_metadata=payload_metadata,
        manifest_header=manifest_header,
        audit_evidence_hex=audit_evidence_hex,
        mat_keys=mat_keys,
    )
