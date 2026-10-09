"""Dual-path generation faults and recovery diagnostics."""

from durashare_py import (
    configure_random_source,
    generate_valid_mnemonic,
    get_random_field_element,
    indices_to_mnemonic,
    mnemonic_to_indices,
    recover_mnemonic,
    split_bip39,
)

TEST_MNEMONIC = "spin result brand ahead poet carpet unusual chronic denial festival toy autumn"


def test_row_checksum_mismatch_is_not_success() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    shares[0].checksum_shares[0] = (shares[0].checksum_shares[0] + 1) % 2053
    result = recover_mnemonic([shares[0], shares[1]], 12)
    assert result.success is False
    assert result.checksums.status == "fail"


def test_gic_mismatch_is_not_success() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    shares[0].global_integrity_check_share = (shares[0].global_integrity_check_share + 1) % 2053
    result = recover_mnemonic([shares[0], shares[1]], 12)
    assert result.success is False
    assert result.checksums.status == "fail"


def test_configurable_random_source_used() -> None:
    calls = 0

    def fake_random(byte_count: int) -> bytes:
        nonlocal calls
        calls += 1
        return bytes([1] * byte_count)

    configure_random_source(fake_random)
    value = get_random_field_element()
    assert calls >= 1
    assert value == int.from_bytes(bytes([1, 1, 1, 1]), "big") % 2053


def test_mnemonic_index_roundtrip() -> None:
    indices = mnemonic_to_indices(TEST_MNEMONIC)
    assert indices_to_mnemonic(indices) == TEST_MNEMONIC


def test_generate_valid_mnemonic_lengths() -> None:
    assert len(generate_valid_mnemonic(12).split()) == 12
    assert len(generate_valid_mnemonic(24).split()) == 24


def test_path_agreement_across_thresholds_and_lengths() -> None:
    for word_count, k, n in ((12, 2, 3), (12, 3, 5), (24, 2, 3)):
        mnemonic = generate_valid_mnemonic(word_count)
        shares = split_bip39(mnemonic, k, n)
        result = recover_mnemonic(shares[:k], word_count)
        assert result.success is True
        assert result.mnemonic == mnemonic


def test_word_share_tampering_fails_checksums() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    shares[0].word_shares[0] = (shares[0].word_shares[0] + 1) % 2053
    result = recover_mnemonic([shares[0], shares[1]], 12)
    assert result.success is False
    assert result.checksums.status == "fail"
