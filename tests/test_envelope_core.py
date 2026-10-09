"""Frozen-vector envelope, flag, and recovery checks from the HTML core spec."""

import json

import pytest
from spec_repo import spec_root

from durashare_py import (
    Share,
    build_compact_share_payload,
    build_full_share_payload,
    build_manifest_header_payload,
    build_share_audit_payload,
    bytes_to_hex,
    compute_sha256,
    decode_manifest_audit_evidence_hex,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    derive_rbt,
    recover_and_validate,
    validate_recovery_payload_set,
)
from durashare_py.envelope import build_canonical_secret_material
from durashare_py.types import RbtOutcome

FULL_LENGTHS = {12: 75, 15: 81, 18: 87, 21: 93, 24: 99}
COMPACT_LENGTHS = {12: 35, 15: 40, 18: 44, 21: 49, 24: 53}
WALLET_FLAGS = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28]


def _vector() -> dict:
    raw = (spec_root() / "test_vectors" / "vectors.json").read_text(encoding="utf-8")
    payload = json.loads(raw)
    return next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")


def _blank_share(word_count: int, *, mat_tags: list[list[int]] | None = None) -> Share:
    row_count = word_count // 3
    return Share(
        share_number=1,
        word_shares=[(index + 1) % 2053 for index in range(word_count)],
        checksum_shares=[0] * row_count,
        column_checksum_shares=[0, 0, 0],
        global_integrity_check_share=0,
        mat_tags=[] if mat_tags is None else mat_tags,
    )


def _share_from_entry(entry: dict) -> Share:
    return Share(
        share_number=entry["x"],
        word_shares=list(entry["word_values"]),
        checksum_shares=list(entry["row_checksums"]),
        column_checksum_shares=list(entry["column_checksums"]),
        global_integrity_check_share=entry["printed_gic"],
    )


def test_profile_lengths_ignore_mat_tags() -> None:
    full_batch = bytes(8)
    compact_batch = bytes(4)
    full_rbt = bytes(12)
    compact_rbt = bytes(6)
    for word_count, full_length in FULL_LENGTHS.items():
        with_mat = _blank_share(word_count, mat_tags=[[1, 2, 3], [4, 5, 6]])
        without_mat = _blank_share(word_count)
        full, _transport = build_full_share_payload(
            with_mat, 2, word_count, 5, full_batch, full_rbt
        )
        full_plain, _transport = build_full_share_payload(
            without_mat, 2, word_count, 5, full_batch, full_rbt
        )
        compact = build_compact_share_payload(
            with_mat, 2, word_count, 5, compact_batch, compact_rbt
        )
        compact_plain = build_compact_share_payload(
            without_mat, 2, word_count, 5, compact_batch, compact_rbt
        )
        assert len(full) == full_length
        assert len(compact) == COMPACT_LENGTHS[word_count]
        assert full == full_plain
        assert compact == compact_plain


def test_wallet_profile_codes_occupy_flag_bits_3_through_5() -> None:
    share = _blank_share(12)
    flags = []
    for code in range(6):
        full, _transport = build_full_share_payload(share, 2, 12, code, bytes(8), bytes(12))
        compact = build_compact_share_payload(share, 2, 12, code, bytes(4), bytes(6))
        flags.append([full[3], compact[3]])
    assert flags == [[flag, flag] for flag in WALLET_FLAGS]


def test_every_canonical_payload_decodes_including_spaced_compact_hex() -> None:
    vector = _vector()
    for entry in vector["shares"]:
        full = decode_share_payload_hex(entry["full_payload"]["payload_hex"])
        compact_hex = entry["compact_payload"]["payload_hex"]
        spaced = " ".join(
            compact_hex[index : index + 8] for index in range(0, len(compact_hex), 8)
        ).lower()
        compact = decode_share_payload_hex(spaced + " ")
        assert full.profile == "full"
        assert full.checks_derived is False
        assert full.word_shares == entry["word_values"]
        assert full.checksum_shares == entry["row_checksums"]
        assert full.column_checksum_shares == entry["column_checksums"]
        assert full.global_integrity_check_share == entry["printed_gic"]
        assert compact.profile == "compact"
        assert compact.checks_derived is True
        assert compact.word_shares == entry["word_values"]
        assert compact.checksum_shares == entry["row_checksums"]
        assert compact.column_checksum_shares == entry["column_checksums"]
        assert compact.global_integrity_check_share == entry["printed_gic"]


def test_decoder_rejects_transport_prefix_and_padding_corruption() -> None:
    vector = _vector()
    full_hex = vector["shares"][0]["full_payload"]["payload_hex"]
    last = full_hex[-1]
    corrupt_transport = full_hex[:-1] + ("1" if last == "0" else "0")
    wrong_prefix = "5342" + full_hex[4:]
    synthetic = _blank_share(15)
    compact = build_compact_share_payload(synthetic, 2, 15, 5, bytes(4), bytes(6))
    padded = bytes_to_hex(compact)
    corrupt_padding = padded[:-1] + "1"
    with pytest.raises(ValueError, match="Transport Hash mismatch"):
        decode_share_payload_hex(corrupt_transport)
    with pytest.raises(ValueError, match="Only SF \\(Full\\) and SC \\(Compact\\)"):
        decode_share_payload_hex(wrong_prefix)
    with pytest.raises(ValueError, match="non-zero padding bits"):
        decode_share_payload_hex(corrupt_padding)


def test_mixed_profile_rbt_passes_then_fails_when_tags_are_wiped() -> None:
    vector = _vector()
    canonical = build_canonical_secret_material(vector["mnemonic"]["indices_1_based"])
    full = decode_share_payload_hex(vector["shares"][0]["full_payload"]["payload_hex"])
    unrelated = decode_share_payload_hex(vector["shares"][1]["compact_payload"]["payload_hex"])
    compact_batch = bytes.fromhex(vector["rbt"]["full_session_batch_id_hex"])[:4]
    compact_rbt = derive_rbt(canonical, compact_batch, 6)
    same_session = build_compact_share_payload(
        _share_from_entry(vector["shares"][1]),
        2,
        12,
        5,
        compact_batch,
        compact_rbt,
    )
    mixed = decode_share_payload_hex(bytes_to_hex(same_session))
    shares = [
        Share(share_number=full.share_number, word_shares=list(full.word_shares)),
        Share(share_number=mixed.share_number, word_shares=list(mixed.word_shares)),
    ]
    passed = recover_and_validate(shares, 12, payload_metadata=[full, mixed])
    assert passed.rbt.status == "pass"
    assert passed.rbt.checked_profiles == ["full", "compact"]

    full.rbt_hex = "00" * 12
    mixed.rbt_hex = "00" * 6
    failed = recover_and_validate(shares, 12, payload_metadata=[full, mixed])
    assert failed.rbt.status == "fail"

    with pytest.raises(ValueError, match="session family"):
        validate_recovery_payload_set([full, unrelated])


def test_sb_and_sa_round_trip_canonical_metadata() -> None:
    vector = _vector()
    share = vector["shares"][0]
    full_batch = bytes.fromhex(vector["rbt"]["full_session_batch_id_hex"])
    compact_batch = bytes.fromhex(vector["rbt"]["compact_session_batch_id_hex"])
    full_rbt = bytes.fromhex(vector["rbt"]["full_rbt_hex"])
    compact_rbt = bytes.fromhex(vector["rbt"]["compact_rbt_hex"])
    full_header = decode_manifest_header_payload_hex(
        bytes_to_hex(build_manifest_header_payload("full", 12, full_batch, full_rbt))
    )
    compact_header = decode_manifest_header_payload_hex(
        bytes_to_hex(build_manifest_header_payload("compact", 12, compact_batch, compact_rbt))
    )
    full_hash = bytes.fromhex(share["full_payload"]["manifest_audit_hash_hex"])
    compact_hash = bytes.fromhex(share["compact_payload"]["manifest_audit_hash_hex"])
    full_audit = decode_manifest_audit_evidence_hex(
        bytes_to_hex(build_share_audit_payload("full", 12, 2, 1, full_hash))
    )
    compact_audit = decode_manifest_audit_evidence_hex(
        bytes_to_hex(build_share_audit_payload("compact", 12, 2, 1, compact_hash))
    )
    raw_hash = decode_manifest_audit_evidence_hex(share["full_payload"]["manifest_audit_hash_hex"])
    assert full_header.profile == "full"
    assert full_header.word_count == 12
    assert full_header.session_batch_id_hex == vector["rbt"]["full_session_batch_id_hex"]
    assert full_header.rbt_hex == vector["rbt"]["full_rbt_hex"]
    assert compact_header.profile == "compact"
    assert compact_header.session_batch_id_hex == vector["rbt"]["compact_session_batch_id_hex"]
    assert compact_header.rbt_hex == vector["rbt"]["compact_rbt_hex"]
    assert full_audit.kind == "sa"
    assert full_audit.profile == "full"
    assert full_audit.threshold == 2
    assert full_audit.share_number == 1
    assert full_audit.committed_hash_bytes == 32
    assert full_audit.committed_hash_hex == share["full_payload"]["manifest_audit_hash_hex"]
    assert compact_audit.kind == "sa"
    assert compact_audit.profile == "compact"
    assert compact_audit.committed_hash_bytes == 16
    assert (
        compact_audit.committed_hash_hex == share["compact_payload"]["manifest_audit_hash_hex"][:32]
    )
    assert raw_hash.kind == "hash"
    assert raw_hash.audit_hash_hex == share["full_payload"]["manifest_audit_hash_hex"]
    assert raw_hash.committed_hash_hex == share["full_payload"]["manifest_audit_hash_hex"]
    assert raw_hash.committed_hash_bytes == 32
    assert compute_sha256(bytes.fromhex(share["full_payload"]["payload_hex"])) == full_hash


def test_sb_alone_confirms_full_rbt_for_manual_words() -> None:
    vector = _vector()
    header = decode_manifest_header_payload_hex(
        bytes_to_hex(
            build_manifest_header_payload(
                "full",
                12,
                bytes.fromhex(vector["rbt"]["full_session_batch_id_hex"]),
                bytes.fromhex(vector["rbt"]["full_rbt_hex"]),
            )
        )
    )
    shares = [
        Share(share_number=entry["x"], word_shares=list(entry["word_values"]))
        for entry in vector["shares"][:2]
    ]
    report = recover_and_validate(shares, 12, manifest_header=header)
    assert report.rbt.status == "pass"
    assert report.rbt.checked_profiles == ["full"]


def test_conflicting_sb_still_interpolates_and_payload_rbt_stays_in_charge() -> None:
    vector = _vector()
    canonical = build_canonical_secret_material(vector["mnemonic"]["indices_1_based"])
    full = decode_share_payload_hex(vector["shares"][0]["full_payload"]["payload_hex"])
    compact_batch = bytes.fromhex(vector["rbt"]["full_session_batch_id_hex"])[:4]
    compact_rbt = derive_rbt(canonical, compact_batch, 6)
    mixed = decode_share_payload_hex(
        bytes_to_hex(
            build_compact_share_payload(
                _share_from_entry(vector["shares"][1]),
                2,
                12,
                5,
                compact_batch,
                compact_rbt,
            )
        )
    )
    header = decode_manifest_header_payload_hex(
        bytes_to_hex(build_manifest_header_payload("full", 12, bytes(8), bytes(12)))
    )
    shares = [
        Share(share_number=full.share_number, word_shares=list(full.word_shares)),
        Share(share_number=mixed.share_number, word_shares=list(mixed.word_shares)),
    ]
    report = recover_and_validate(
        shares, 12, payload_metadata=[full, mixed], manifest_header=header
    )
    phrase = " ".join(vector["mnemonic"]["words"])
    assert report.errors.generic is None
    assert report.recovered_mnemonic == phrase
    assert report.rbt.status == "pass"
    assert report.rbt.has_conflict is True
    assert report.rbt.checked_profiles == ["full", "compact"]
    assert report.rbt.outcomes == [
        RbtOutcome("full", ["share-payload"], f"Share #{full.share_number} Full payload", "pass"),
        RbtOutcome(
            "compact",
            ["share-payload"],
            f"Share #{mixed.share_number} Compact payload",
            "pass",
        ),
        RbtOutcome("full", ["manifest-header"], "Manifest Header (SB)", "fail"),
    ]
