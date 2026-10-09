"""One-share Audit.

This module does not interpolate and does not return a mnemonic. Audit checks
one stored share against its own fields, an optional payload, SB/SA evidence,
and MAT.
"""

from .checksums import WORDS_PER_ROW, audit_optional_checksums, compute_row_total, is_supplied_field
from .envelope import (
    DecodedSharePayload,
    audit_evidence_agrees,
    decode_manifest_audit_evidence_hex,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    session_header_agrees,
)
from .mat import audit_mat_column
from .types import EvidenceState, RecoveryReport, Share, StatusSummary


def _summary(status: str, passed: int = 0, failed: int = 0) -> StatusSummary:
    return StatusSummary(status, passed, failed)


def _kit(report: RecoveryReport) -> EvidenceState:
    families = [
        report.manifest_audit,
        report.mat,
        report.payload_integrity,
        report.checksums,
        report.manifest_header,
        report.rbt_artifacts,
    ]
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


def _values_match(actual: list[int], expected: list[int]) -> bool:
    if len(actual) != len(expected):
        return False
    return all(
        is_supplied_field(value) and value == expected[index] for index, value in enumerate(actual)
    )


def payload_agrees_with_share(
    share: Share,
    payload: DecodedSharePayload,
    threshold: int | None,
) -> bool:
    """Stored fields must match the payload. A missing field is a disagreement."""
    gic = share.global_integrity_check_share
    return (
        is_supplied_field(threshold)
        and threshold == payload.threshold
        and share.share_number == payload.share_number
        and list(share.word_shares) == list(payload.word_shares)
        and _values_match(share.checksum_shares, payload.checksum_shares)
        and _values_match(share.column_checksum_shares, payload.column_checksum_shares)
        and is_supplied_field(gic)
        and gic == payload.global_integrity_check_share
    )


def audit_share(
    share: Share,
    *,
    payload_hex: str | None = None,
    threshold: int | None = None,
    manifest_header_hex: str | None = None,
    audit_evidence_hex: str | None = None,
    mat_weights: list[int] | None = None,
    mat_row_pads: list[int | None] | None = None,
    mat_tags: list[int | None] | None = None,
) -> RecoveryReport:
    """Check one share in place. Never calls Lagrange and never sets a mnemonic.

    A payload is an integrity pass only when the threshold, share number, words,
    row checksums, column checksums, and printed GIC all agree with it. A valid
    SB stays not-checked until a share payload is available to cross-check.
    """
    report = RecoveryReport()
    word_count = len(share.word_shares)
    row_count = word_count // WORDS_PER_ROW if word_count else 0
    if row_count and word_count % WORDS_PER_ROW == 0:
        audit = audit_optional_checksums(
            share.share_number,
            share.word_shares,
            list(share.checksum_shares),
            list(share.column_checksum_shares),
            share.global_integrity_check_share,
            row_count,
            compute_row_total(row_count),
        )
        problems = (
            len(audit["row_fails"]) + len(audit["col_fails"]) + (1 if audit["gic_fail"] else 0)
        )
        supplied = sum(1 for value in share.checksum_shares if is_supplied_field(value))
        supplied += sum(1 for value in share.column_checksum_shares if is_supplied_field(value))
        if is_supplied_field(share.global_integrity_check_share):
            supplied += 1
        if problems:
            report.checksums = _summary("fail", 0, problems)
        elif supplied:
            report.checksums = _summary("pass", 1, 0)

    decoded = None
    if payload_hex is not None:
        try:
            decoded = decode_share_payload_hex(payload_hex)
        except ValueError:
            report.payload_integrity = _summary("fail", 0, 1)
        else:
            if payload_agrees_with_share(share, decoded, threshold):
                report.payload_integrity = _summary("pass", 1, 0)
            else:
                report.payload_integrity = _summary("fail", 0, 1)

    if manifest_header_hex is not None:
        try:
            header = decode_manifest_header_payload_hex(manifest_header_hex)
        except ValueError:
            report.manifest_header = _summary("fail", 0, 1)
        else:
            if decoded is None:
                report.manifest_header = _summary("not-checked")
            elif session_header_agrees(header, decoded):
                report.manifest_header = _summary("pass", 1, 0)
            else:
                report.manifest_header = _summary("fail", 0, 1)

    if audit_evidence_hex is not None:
        try:
            evidence = decode_manifest_audit_evidence_hex(audit_evidence_hex)
        except ValueError:
            report.manifest_audit = _summary("fail", 0, 1)
        else:
            if decoded is None:
                report.manifest_audit = _summary("not-checked")
            elif audit_evidence_agrees(evidence, decoded):
                report.manifest_audit = _summary("pass", 1, 0)
            else:
                report.manifest_audit = _summary("fail", 0, 1)

    if mat_weights is not None and mat_row_pads is not None and mat_tags is not None:
        try:
            column = audit_mat_column(share.word_shares, mat_tags, mat_weights, mat_row_pads)
            if column["failed_rows"]:
                report.mat = _summary(
                    "fail", len(column["matched_rows"]), len(column["failed_rows"])
                )
            elif column["checked_rows"]:
                report.mat = _summary("pass", len(column["matched_rows"]), 0)
        except ValueError:
            report.mat = _summary("fail", 0, 1)

    report.kit_health = _kit(report)
    report.success = False
    report.recovered_mnemonic = None
    report.recovered_indices = None
    return report
