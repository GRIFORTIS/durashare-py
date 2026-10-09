"""Error and edge branches for the v0.7.0 library."""

import json

import pytest
from spec_repo import spec_root

from durashare_py import (
    Share,
    audit_mat_column,
    audit_share,
    compute_mat_tag,
    configure_environment,
    create_sharing_artifacts,
    decode_manifest_audit_evidence_hex,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    derive_rbt,
    hex_to_bytes,
    lagrange_interpolate_at_zero,
    normalize_share_value,
    pack_field_elements_12,
    parse_share_value,
    recover_mnemonic,
    split_bip39,
    sum_polynomials,
    unpack_field_elements_12,
    validate_recovery_payload_set,
)
from durashare_py.checksums import audit_optional_checksums
from durashare_py.envelope import build_share_audit_payload
from durashare_py.mat import normalize_mat_custody, normalize_mat_mode
from durashare_py.randomness import get_random_bytes, get_random_int_inclusive

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_constant_time_equal_rejects_out_of_range() -> None:
    from durashare_py import constant_time_bytes_equal, constant_time_equal

    assert constant_time_equal(-1, 1) is False
    assert constant_time_bytes_equal(b"aa", b"a") is False
    with pytest.raises(ValueError, match="callable"):
        configure_environment(random_source=123)


def test_pack_and_hash_guards() -> None:
    with pytest.raises(ValueError, match="at least one"):
        pack_field_elements_12([])
    with pytest.raises(ValueError, match="between 0 and"):
        pack_field_elements_12([2053])
    with pytest.raises(ValueError, match="positive element"):
        unpack_field_elements_12(b"\x00", 0)
    with pytest.raises(ValueError, match="even number"):
        hex_to_bytes("abc", "Sample")
    with pytest.raises(ValueError, match="4 or 8"):
        derive_rbt(b"\x01\x02", b"\x00\x00", 12)
    with pytest.raises(ValueError, match="6, 12, or 32"):
        derive_rbt(b"\x01\x02", b"\x00" * 8, 7)
    with pytest.raises(ValueError):
        get_random_int_inclusive(-1)
    with pytest.raises(ValueError):
        get_random_bytes(0)
    with pytest.raises(ValueError, match="integer"):
        normalize_share_value(True, "flag")
    with pytest.raises(ValueError, match="between 0 and"):
        normalize_share_value(2053, "flag")
    with pytest.raises(ValueError):
        lagrange_interpolate_at_zero([])
    with pytest.raises(ValueError, match="zero polynomials"):
        sum_polynomials([])
    with pytest.raises(ValueError, match="degree mismatch"):
        sum_polynomials([[1, 2], [1]])


def test_parse_share_value_edges() -> None:
    assert parse_share_value(None)["reason"] == "empty"
    assert parse_share_value("   ")["reason"] == "empty"
    assert parse_share_value("abandon")["value"] == 1
    assert parse_share_value("2052")["value"] == 2052
    assert parse_share_value("2053")["reason"] == "range"
    assert parse_share_value("12", allow_numeric=False)["reason"] == "numeric-not-allowed"
    assert parse_share_value("nope")["reason"] == "unknown"
    assert parse_share_value("a-b-c")["reason"] == "unknown"
    assert parse_share_value("0001-0001")["value"] == 1
    assert parse_share_value("9999-abandon")["reason"] == "range"
    assert parse_share_value("ability-0001")["reason"] == "mismatch"


def test_mat_guards() -> None:
    with pytest.raises(ValueError, match="none, single, or dual"):
        normalize_mat_mode("triple")
    with pytest.raises(ValueError, match="whole or split"):
        normalize_mat_custody("neither", "single")
    assert normalize_mat_custody("whole", "none") == "none"
    with pytest.raises(ValueError, match="three word"):
        compute_mat_tag([1, 2], [1, 2, 3], 1)
    with pytest.raises(ValueError, match="complete word-share"):
        audit_mat_column([1, 2], [1], [1, 2, 3], [1])


def test_payload_and_audit_rejects() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        decode_share_payload_hex(1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty"):
        decode_share_payload_hex("   ")
    with pytest.raises(ValueError, match="prefix"):
        decode_share_payload_hex("00")
    with pytest.raises(ValueError, match="SB prefix"):
        decode_manifest_header_payload_hex("00")
    with pytest.raises(ValueError, match="empty"):
        decode_manifest_audit_evidence_hex("  ")
    with pytest.raises(ValueError, match="32 bytes"):
        build_share_audit_payload("full", 12, 2, 1, b"\x00" * 16)
    with pytest.raises(ValueError, match="array"):
        validate_recovery_payload_set("nope")  # type: ignore[arg-type]
    share = Share(share_number=1, word_shares=[1, 1, 1])
    report = audit_share(share, payload_hex="00", manifest_header_hex="00", audit_evidence_hex="zz")
    assert report.payload_integrity.status == "fail"
    assert report.manifest_header.status == "fail"
    assert report.manifest_audit.status == "fail"
    assert report.mnemonic is None


def test_split_and_recover_guards() -> None:
    with pytest.raises(ValueError, match="integers"):
        split_bip39(ABANDON, True, 3)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least 2"):
        split_bip39(ABANDON, 1, 3)
    with pytest.raises(ValueError, match="cannot exceed"):
        split_bip39(ABANDON, 4, 3)
    with pytest.raises(ValueError, match="less than 2053"):
        split_bip39(ABANDON, 2, 2053)
    with pytest.raises(ValueError, match="string"):
        split_bip39(1, 2, 3)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty"):
        split_bip39("   ", 2, 3)
    with pytest.raises(ValueError, match="Invalid BIP39"):
        split_bip39("abandon " * 12, 2, 3)
    with pytest.raises(ValueError):
        create_sharing_artifacts(ABANDON, 2, 3, full_session_batch_id=b"\x01\x02")
    result = recover_mnemonic([], 12)
    assert result.errors.generic is not None
    odd = recover_mnemonic(
        [Share(1, [1, 2, 3] * 3), Share(2, [1, 2, 3] * 3)],
        9,
    )
    assert odd.success is False
    audit = audit_optional_checksums(1, [1, 1, 1], [None], [None, None, None], None, 1, 1)
    assert audit["gic_fail"] is False


def test_payload_set_disagreements() -> None:
    vector_payload = json.loads(
        (spec_root() / "test_vectors" / "vectors.json").read_text(encoding="utf-8")
    )
    payload_hex = vector_payload["vectors"][0]["shares"][0]["full_payload"]["payload_hex"]
    payload = decode_share_payload_hex(payload_hex)
    assert validate_recovery_payload_set([None]).has_payloads is False
    with pytest.raises(ValueError, match="invalid payload"):
        bad = decode_share_payload_hex(payload_hex)
        bad.threshold = 4
        validate_recovery_payload_set([bad])
    with pytest.raises(ValueError, match="edited after payload"):
        validate_recovery_payload_set([payload], shares=[Share(share_number=9, word_shares=[])])
    with pytest.raises(ValueError, match="Recovery form"):
        validate_recovery_payload_set([payload], expected_word_count=24)
    with pytest.raises(ValueError, match="duplicate"):
        validate_recovery_payload_set([payload, payload])
    with pytest.raises(ValueError, match="hexadecimal text"):
        decode_manifest_header_payload_hex(None)  # type: ignore[arg-type]


def test_mat_failure_clears_and_polynomial_rng_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> bool:
        raise ValueError("MAT consistency check failed for Share 1")

    monkeypatch.setattr("durashare_py.split.verify_mat_bindings", boom)
    with pytest.raises(ValueError, match="MAT consistency"):
        create_sharing_artifacts(ABANDON, 2, 3, mat_mode="single")

    from durashare_py.errors import RngHardStopError
    from durashare_py.polynomial import random_polynomial

    def fail() -> int:
        raise RngHardStopError("draw failed")

    monkeypatch.setattr("durashare_py.polynomial.get_random_field_element", fail)
    with pytest.raises(RngHardStopError):
        random_polynomial(1, 2)


def test_split_rejects_word_count_after_checksum_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("durashare_py.split.validate_bip39_mnemonic", lambda *_a, **_k: True)
    with pytest.raises(ValueError, match="12, 15, 18, 21, or 24"):
        split_bip39("abandon " * 9, 2, 3)
    with pytest.raises(ValueError, match="Unknown mnemonic word"):
        split_bip39("notaword " * 12, 2, 3)
    from durashare_py.split import verify_mat_bindings
    from durashare_py.types import MatShareKeys

    with pytest.raises(ValueError, match="matching lengths"):
        verify_mat_bindings([], [], "none")
    plain = Share(share_number=1, word_shares=[1, 1, 1], mat_mode="none")
    with pytest.raises(ValueError, match="mode"):
        verify_mat_bindings([plain], [MatShareKeys(1)], "single")
    zero = Share(share_number=0, word_shares=[1, 1, 1], mat_mode="none")
    with pytest.raises(ValueError, match="between 1 and"):
        verify_mat_bindings([zero], [MatShareKeys(0)], "none")
    with pytest.raises(ValueError, match="metadata"):
        verify_mat_bindings([plain], [MatShareKeys(2)], "none")
    single = Share(share_number=1, word_shares=[1, 1, 1], mat_mode="single", mat_tags=[])
    with pytest.raises(ValueError, match="metadata"):
        verify_mat_bindings([single], [MatShareKeys(1)], "single")
    from durashare_py.types import MatColumn

    words = [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4]
    ordered = Share(
        share_number=1,
        word_shares=words,
        mat_mode="single",
        mat_tags=[[1]],
    )
    with pytest.raises(ValueError, match="canonical order"):
        verify_mat_bindings(
            [ordered],
            [MatShareKeys(1, [MatColumn(2, [1, 1, 1], [1, 1, 1, 1])])],
            "single",
        )
    with pytest.raises(ValueError, match="length mismatch"):
        verify_mat_bindings(
            [ordered],
            [MatShareKeys(1, [MatColumn(1, [1, 1, 1], [1, 1, 1, 1])])],
            "single",
        )
    from durashare_py import compute_mat_tags

    tags = compute_mat_tags(words, [1, 1, 1], [1, 1, 1, 1])
    tags[0] = (tags[0] + 1) % 2053
    mismatched = Share(share_number=1, word_shares=words, mat_mode="single", mat_tags=[tags])
    with pytest.raises(ValueError, match="consistency check failed"):
        verify_mat_bindings(
            [mismatched],
            [MatShareKeys(1, [MatColumn(1, [1, 1, 1], [1, 1, 1, 1])])],
            "single",
        )
