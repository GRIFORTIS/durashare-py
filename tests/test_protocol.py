"""Frozen protocol vectors and the HTML v0.6.0 envelope, MAT, and audit surface."""

import json

import pytest
from spec_repo import spec_root

from durashare_py import (
    CryptoHardStopError,
    RngHardStopError,
    Share,
    audit_share,
    build_compact_share_payload,
    build_full_share_payload,
    build_manifest_header_payload,
    build_share_audit_payload,
    bytes_to_hex,
    compute_column_check_polynomials,
    compute_global_integrity_check_polynomial,
    compute_mat_tags,
    compute_row_check_polynomials,
    compute_sha256,
    configure_environment,
    create_sharing_artifacts,
    decode_manifest_audit_evidence_hex,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    derive_rbt,
    evaluate_polynomial,
    is_crypto_hard_stop_error,
    is_rng_hard_stop_error,
    lagrange_interpolate_at_zero,
    recover_and_validate,
    recover_mnemonic,
    split_bip39,
    validate_recovery_payload_set,
)
from durashare_py.envelope import build_canonical_secret_material

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def load_json(relative: str) -> dict:
    return json.loads((spec_root() / relative).read_text(encoding="utf-8"))


def _share_from_vector(entry: dict) -> Share:
    return Share(
        share_number=entry["x"],
        word_shares=list(entry["word_values"]),
        checksum_shares=list(entry["row_checksums"]),
        column_checksum_shares=list(entry["column_checksums"]),
        global_integrity_check_share=entry["printed_gic"],
    )


def test_v070_arithmetic_matches_frozen_vector() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(
        item for item in payload["vectors"] if item["id"].endswith("2of3-12w-full-compact")
    )
    indices = vector["mnemonic"]["indices_1_based"]
    coefficients = vector["coefficients"]
    polys = [[secret, coeff] for secret, coeff in zip(indices, coefficients, strict=True)]
    row_polys = compute_row_check_polynomials(polys)
    column_polys = compute_column_check_polynomials(polys)
    gic_poly = compute_global_integrity_check_polynomial(polys)
    for entry in vector["shares"]:
        x = entry["x"]
        words = [evaluate_polynomial(poly, x) for poly in polys]
        rows = [evaluate_polynomial(poly, x) for poly in row_polys]
        columns = [evaluate_polynomial(poly, x) for poly in column_polys]
        gic = (evaluate_polynomial(gic_poly, x) + x) % 2053
        assert words == entry["word_values"]
        assert rows == entry["row_checksums"]
        assert columns == entry["column_checksums"]
        assert gic == entry["printed_gic"]


def test_v070_envelopes_match_frozen_bytes() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")
    full_batch = bytes.fromhex(vector["rbt"]["full_session_batch_id_hex"])
    compact_batch = bytes.fromhex(vector["rbt"]["compact_session_batch_id_hex"])
    full_rbt = bytes.fromhex(vector["rbt"]["full_rbt_hex"])
    compact_rbt = bytes.fromhex(vector["rbt"]["compact_rbt_hex"])
    canonical = build_canonical_secret_material(vector["mnemonic"]["indices_1_based"])
    assert canonical.hex().upper() == vector["rbt"]["canonical_secret_material_hex"]
    assert derive_rbt(canonical, full_batch, 12) == full_rbt
    assert derive_rbt(canonical, compact_batch, 6) == compact_rbt
    for entry in vector["shares"]:
        share = _share_from_vector(entry)
        full_payload, transport = build_full_share_payload(share, 2, 12, None, full_batch, full_rbt)
        compact_payload = build_compact_share_payload(
            share, 2, 12, None, compact_batch, compact_rbt
        )
        assert bytes_to_hex(full_payload) == entry["full_payload"]["payload_hex"]
        assert bytes_to_hex(transport) == entry["full_payload"]["transport_hash_hex"]
        assert bytes_to_hex(compact_payload) == entry["compact_payload"]["payload_hex"]
        assert (
            bytes_to_hex(compute_sha256(full_payload))
            == entry["full_payload"]["manifest_audit_hash_hex"]
        )
        assert (
            bytes_to_hex(compute_sha256(compact_payload))
            == entry["compact_payload"]["manifest_audit_hash_hex"]
        )
        decoded = decode_share_payload_hex(entry["full_payload"]["payload_hex"])
        assert decoded.word_shares == entry["word_values"]
        assert decoded.share_number == entry["x"]
        header = build_manifest_header_payload("full", 12, full_batch, full_rbt)
        decoded_header = decode_manifest_header_payload_hex(bytes_to_hex(header))
        assert decoded_header.session_batch_id_hex == vector["rbt"]["full_session_batch_id_hex"]
        audit_hash = compute_sha256(full_payload)
        sa = build_share_audit_payload("full", 12, 2, entry["x"], audit_hash)
        evidence = decode_manifest_audit_evidence_hex(bytes_to_hex(sa))
        assert evidence.committed_hash_hex == bytes_to_hex(audit_hash)
        assert evidence.share_number == entry["x"]


def test_transport_hash_mismatch_returns_no_share() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")
    hex_payload = vector["shares"][0]["full_payload"]["payload_hex"]
    broken = hex_payload[:-2] + ("00" if not hex_payload.endswith("00") else "FF")
    with pytest.raises(ValueError, match="Transport Hash"):
        decode_share_payload_hex(broken)


def test_unknown_payload_version_hard_stops() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")
    raw = bytearray.fromhex(vector["shares"][0]["full_payload"]["payload_hex"])
    raw[2] = 0x02
    with pytest.raises(ValueError, match="Unsupported Share payload version"):
        decode_share_payload_hex(raw.hex())


def test_v050_recovery_still_yields_the_mnemonic() -> None:
    payload = load_json("previous_versions/v0.5.0/test_vectors/vectors.json")
    vector = payload["vectors"][0]
    shares = []
    for entry in vector["shares"][:2]:
        shares.append(
            Share(
                share_number=entry["x"],
                word_shares=list(entry["words"]),
                checksum_shares=list(entry["row_checksums"]),
                column_checksum_shares=list(entry["column_checksums"]),
                global_integrity_check_share=entry["printed_gic"],
            )
        )
    report = recover_and_validate(shares, 12)
    assert report.recovered_mnemonic == " ".join(vector["mnemonic"]["words"])
    assert report.success is False
    assert report.mnemonic is None
    assert report.checksums.status == "fail"


def test_v042_share_is_not_success() -> None:
    """A v0.4.2 table uses the same word shares and the old row-sum checksums."""
    shares = [
        Share(
            share_number=1,
            word_shares=[1681, 1470, 1343, 1, 2048, 850, 0, 2052, 415, 812, 1966, 509],
            checksum_shares=[388, 846, 414, 1234],
            global_integrity_check_share=830,
        ),
        Share(
            share_number=2,
            word_shares=[1682, 1469, 416, 2013, 705, 1421, 146, 1727, 362, 942, 35, 892],
            checksum_shares=[1514, 33, 182, 1869],
            global_integrity_check_share=1547,
        ),
    ]
    result = recover_mnemonic(shares, 12)
    assert result.success is False
    assert result.mnemonic is None
    assert result.recovered_mnemonic is not None


def test_deterministic_mat_vector() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "mat")
    words = [value for row in vector["row_values"] for value in row]
    for column in vector["mat_columns"]:
        tags = compute_mat_tags(words, column["weights"], column["row_pads"])
        assert tags == column["tags"]


def test_audit_does_not_interpolate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def boom(*_args: object, **_kwargs: object) -> int:
        calls.append(1)
        return 0

    monkeypatch.setattr("durashare_py.lagrange.lagrange_interpolate_at_zero", boom)
    monkeypatch.setattr("durashare_py.recover.lagrange_interpolate_at_zero", boom)
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")
    entry = vector["shares"][0]
    share = _share_from_vector(entry)
    mat = next(item for item in payload["vectors"] if item["type"] == "mat")
    column = mat["mat_columns"][0]
    report = audit_share(
        share,
        payload_hex=entry["full_payload"]["payload_hex"],
        threshold=2,
        audit_evidence_hex=entry["full_payload"]["manifest_audit_hash_hex"],
        mat_weights=column["weights"],
        mat_row_pads=column["row_pads"],
        mat_tags=column["tags"],
    )
    assert calls == []
    assert report.mnemonic is None
    assert report.recovered_mnemonic is None
    assert report.payload_integrity.status == "pass"
    assert report.checksums.status == "pass"
    assert report.mat.status == "pass"
    assert report.manifest_audit.status == "pass"
    assert lagrange_interpolate_at_zero is not None


def test_hash_known_answer_failure_returns_no_artifact() -> None:
    def broken_sha256(_data: bytes) -> bytes:
        return b"\x00" * 32

    configure_environment(sha256=broken_sha256)
    with pytest.raises(CryptoHardStopError) as caught:
        create_sharing_artifacts(
            ABANDON,
            2,
            3,
        )
    assert is_crypto_hard_stop_error(caught.value)


def test_rng_smoke_hard_stop() -> None:
    configure_environment(random_source=lambda n: bytes([0xA5]) * n)
    with pytest.raises(RngHardStopError) as caught:
        split_bip39(
            ABANDON,
            2,
            3,
        )
    assert is_rng_hard_stop_error(caught.value)


def test_rejection_cap_hard_stop() -> None:
    from durashare_py.randomness import get_random_field_element

    configure_environment(random_source=lambda n: b"\xff" * n)
    with pytest.raises(RngHardStopError, match="rejection sampling"):
        get_random_field_element()


def test_session_family_check() -> None:
    payload = load_json("test_vectors/vectors.json")
    vector = next(item for item in payload["vectors"] if item["type"] == "arithmetic-and-payload")
    full = decode_share_payload_hex(vector["shares"][0]["full_payload"]["payload_hex"])
    compact = decode_share_payload_hex(vector["shares"][1]["compact_payload"]["payload_hex"])
    with pytest.raises(ValueError, match="session family"):
        validate_recovery_payload_set([full, compact])


def test_rva_note_is_stored_unchecked() -> None:
    note = "not a wallet address"
    artifacts = create_sharing_artifacts(
        ABANDON,
        2,
        3,
        rva_note=note,
    )
    assert artifacts.rva_note == note
    assert artifacts.session is not None
    assert artifacts.session.rva_note == note


def test_parse_share_value_dual_forms() -> None:
    from durashare_py import parse_share_value

    assert parse_share_value("0001-abandon")["value"] == 1
    assert parse_share_value("abandon-0001")["value"] == 1
    assert parse_share_value("0001-ability")["reason"] == "mismatch"
