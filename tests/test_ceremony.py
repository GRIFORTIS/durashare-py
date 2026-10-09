"""Ceremony paths that the vector file does not exercise by itself."""

import pytest

from durashare_py import (
    RngHardStopError,
    Share,
    assert_coefficient_batch_healthy,
    audit_share,
    build_manifest_header_payload,
    build_share_audit_payload,
    bytes_to_hex,
    clear_sharing_artifacts,
    create_sharing_artifacts,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    mod_pow,
    recover_and_validate,
    verify_mat_bindings,
)
from durashare_py.envelope import (
    DecodedManifestHeader,
    DecodedSharePayload,
    session_header_agrees,
)
from durashare_py.mat import recombine_mat_key_sets, split_mat_key_set
from durashare_py.randomness import assert_csprng_healthy, configure_random_source
from durashare_py.split import _recombine_share_keys
from durashare_py.types import MatColumn, MatShareKeys

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def test_split_key_mat_recombines_and_checks_out() -> None:
    artifacts = create_sharing_artifacts(MNEMONIC, 2, 3, mat_mode="dual", mat_custody="split")
    assert len(artifacts.manifests) == 2
    assert artifacts.manifests[0].kind == "split-a"
    assert artifacts.manifests[1].kind == "split-b"
    row_count = len(artifacts.shares[0].word_shares) // 3
    combined = _recombine_share_keys(
        artifacts.manifests[0].share_keys,
        artifacts.manifests[1].share_keys,
        row_count,
    )
    assert verify_mat_bindings(artifacts.shares, combined, "dual") is True
    whole = create_sharing_artifacts(MNEMONIC, 2, 3, mat_mode="single", mat_custody="whole")
    assert whole.manifests[0].kind == "whole"
    assert verify_mat_bindings(whole.shares, whole.manifests[0].share_keys, "single") is True


def test_mat_key_split_recombine_roundtrip() -> None:
    weights = [2, 4, 7]
    pads = [6, 8, 10, 12]
    key_a, key_b = split_mat_key_set(weights, pads, 4)
    combined_weights, combined_pads = recombine_mat_key_sets(key_a, key_b, 4)
    assert combined_weights == weights
    assert combined_pads == pads


def test_recovery_rbt_match_and_conflict() -> None:
    artifacts = create_sharing_artifacts(MNEMONIC, 2, 3)
    assert artifacts.shares[0].digital is not None
    payloads = [
        decode_share_payload_hex(bytes_to_hex(share.digital.full.payload))
        for share in artifacts.shares[:2]
        if share.digital is not None
    ]
    matched = recover_and_validate(artifacts.shares[:2], 12, payload_metadata=payloads)
    assert matched.success is True
    assert matched.rbt.status == "pass"
    assert matched.mnemonic == MNEMONIC

    payloads[1].rbt_hex = "00" * 12
    conflicted = recover_and_validate(artifacts.shares[:2], 12, payload_metadata=payloads)
    assert conflicted.success is False
    assert conflicted.rbt.has_conflict is True
    assert conflicted.recovered_mnemonic == MNEMONIC
    assert conflicted.mnemonic is None


def test_audit_and_recovery_follow_html_kit_checks() -> None:
    artifacts = create_sharing_artifacts(
        MNEMONIC,
        2,
        3,
        mat_mode="single",
        full_session_batch_id=bytes.fromhex("A1B2C3D4E5F60708"),
    )
    assert artifacts.session is not None
    share = artifacts.shares[0]
    assert share.digital is not None
    full_hex = bytes_to_hex(share.digital.full.payload)
    compact_header = bytes_to_hex(artifacts.session.compact.manifest_header_payload)
    full_header = bytes_to_hex(artifacts.session.full.manifest_header_payload)

    agreed = audit_share(
        share,
        payload_hex=full_hex,
        threshold=2,
        manifest_header_hex=compact_header,
    )
    assert agreed.payload_integrity.status == "pass"
    assert agreed.manifest_header.status == "pass"
    assert agreed.kit_health.state == "consistent"

    words_only = Share(share_number=share.share_number, word_shares=share.word_shares.copy())
    incomplete = audit_share(words_only, payload_hex=full_hex, threshold=2)
    assert incomplete.payload_integrity.status == "fail"
    assert incomplete.kit_health.state == "problems"

    missing_threshold = audit_share(share, payload_hex=full_hex)
    assert missing_threshold.payload_integrity.status == "fail"

    header_only = audit_share(
        Share(share_number=share.share_number, word_shares=share.word_shares.copy()),
        manifest_header_hex=full_header,
    )
    assert header_only.manifest_header.status == "not-checked"
    assert header_only.kit_health.state == "not-assessed"

    waiting = audit_share(share, payload_hex="00", manifest_header_hex=full_header)
    assert waiting.payload_integrity.status == "fail"
    assert waiting.manifest_header.status == "not-checked"

    wrong_rbt = bytearray(artifacts.session.full.rbt)
    wrong_rbt[0] ^= 0xFF
    mismatched_header = bytes_to_hex(
        build_manifest_header_payload("full", 12, artifacts.session.full.batch_id, bytes(wrong_rbt))
    )
    assert (
        audit_share(
            share, payload_hex=full_hex, threshold=2, manifest_header_hex=mismatched_header
        ).manifest_header.status
        == "fail"
    )

    wrong_sa = build_share_audit_payload(
        "full", 24, 3, share.share_number, share.digital.full.audit_hash
    )
    wrong_audit = audit_share(
        share,
        payload_hex=full_hex,
        threshold=2,
        audit_evidence_hex=bytes_to_hex(wrong_sa),
    )
    assert wrong_audit.manifest_audit.status == "fail"
    matching_sa = build_share_audit_payload(
        "full", 12, 2, share.share_number, share.digital.full.audit_hash
    )
    assert (
        audit_share(
            share, payload_hex=full_hex, threshold=2, audit_evidence_hex=bytes_to_hex(matching_sa)
        ).manifest_audit.status
        == "pass"
    )

    payloads = [
        decode_share_payload_hex(bytes_to_hex(item.digital.full.payload))
        for item in artifacts.shares[:2]
        if item.digital is not None
    ]
    header = decode_manifest_header_payload_hex(compact_header)
    recovered = recover_and_validate(
        artifacts.shares[:2],
        12,
        payload_metadata=payloads,
        manifest_header=header,
        audit_evidence_hex=[bytes_to_hex(matching_sa), None],
        mat_keys=artifacts.manifests[0].share_keys[:2],
    )
    assert recovered.payload_integrity.status == "pass"
    assert recovered.manifest_header.status == "pass"
    assert recovered.manifest_audit.status == "pass"
    assert recovered.mat.status == "pass"
    assert recovered.success is True

    second = artifacts.shares[1]
    assert second.digital is not None
    foreign = decode_share_payload_hex(bytes_to_hex(second.digital.full.payload))
    foreign.session_batch_id_hex = "0011223344556677"
    rejected = recover_and_validate(
        artifacts.shares[:2],
        12,
        payload_metadata=[payloads[0], foreign],
    )
    assert rejected.payload_integrity.status == "fail"
    assert rejected.recovered_mnemonic == MNEMONIC

    header_without_payload = recover_and_validate(
        artifacts.shares[:2],
        12,
        manifest_header=header,
    )
    assert header_without_payload.manifest_header.status == "not-checked"

    broken_share = artifacts.shares[0]
    broken_share.mat_tags[0][0] = (broken_share.mat_tags[0][0] + 1) % 2053
    mat_problem = recover_and_validate(
        artifacts.shares[:2],
        12,
        mat_keys=artifacts.manifests[0].share_keys[:2],
    )
    assert mat_problem.mat.status == "fail"
    assert mat_problem.recovered_mnemonic == MNEMONIC
    assert (
        recover_and_validate(
            artifacts.shares[:2],
            12,
            mat_keys=artifacts.manifests[0].share_keys[:1],
        ).mat.status
        == "fail"
    )

    unknown = DecodedManifestHeader("other", "", 1, 12, "AA", "BB")
    other_payload_header = DecodedManifestHeader("full", "", 1, 12, "AA", "BB")
    payload = DecodedSharePayload(
        profile="full",
        payload_hex="",
        protocol_version=1,
        word_count=12,
        wallet_profile_code=5,
        language_input=1,
        threshold=2,
        share_number=1,
        session_batch_id_hex="AA",
        rbt_hex="BB",
        audit_hash_hex="",
        transport_hash_hex="",
        word_shares=[],
        checksum_shares=[],
        column_checksum_shares=[],
        global_integrity_check_share=0,
        checks_derived=False,
    )
    assert session_header_agrees(unknown, payload) is False
    payload.profile = "other"
    assert session_header_agrees(other_payload_header, payload) is False
    header.word_count = 24
    word_count_mismatch = recover_and_validate(
        artifacts.shares[:2],
        12,
        payload_metadata=payloads,
        manifest_header=header,
    )
    assert word_count_mismatch.manifest_header.status == "fail"
    bad_evidence = recover_and_validate(
        artifacts.shares[:2],
        12,
        payload_metadata=payloads,
        audit_evidence_hex=["zz", ""],
    )
    assert bad_evidence.manifest_audit.status == "fail"
    waiting_audit = recover_and_validate(
        artifacts.shares[:2],
        12,
        audit_evidence_hex=[bytes_to_hex(share.digital.full.audit_hash), None],
    )
    assert waiting_audit.manifest_audit.status == "not-checked"
    empty_keys = MatShareKeys(share.share_number, [MatColumn(1, [1, 2], [1])])
    second_keys = MatShareKeys(second.share_number, [MatColumn(1, [1, 2], [1])])
    invalid_mat = recover_and_validate(
        artifacts.shares[:2],
        12,
        mat_keys=[empty_keys, second_keys],
    )
    assert invalid_mat.mat.status == "fail"


def test_coefficient_canary_and_identical_rng_burst() -> None:
    with pytest.raises(RngHardStopError, match="empty"):
        assert_coefficient_batch_healthy([])
    with pytest.raises(RngHardStopError, match="identical"):
        assert_coefficient_batch_healthy([4, 4])
    with pytest.raises(RngHardStopError, match="repeated"):
        assert_coefficient_batch_healthy([1, 1, 1, 1, 1, 1, 2])

    blob = bytes(range(256))
    configure_random_source(lambda n: blob[:n])
    with pytest.raises(RngHardStopError, match="identical"):
        assert_csprng_healthy()


def test_clear_sharing_artifacts_zeroes_owned_buffers() -> None:
    artifacts = create_sharing_artifacts(MNEMONIC, 2, 3, mat_mode="single")
    clear_sharing_artifacts(artifacts)
    assert artifacts.shares == []
    assert artifacts.session is None


def test_mod_pow_small() -> None:
    assert mod_pow(2, 10) == 1024
