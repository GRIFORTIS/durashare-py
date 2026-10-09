"""Round-trip split and recover for the v0.7.0 share table."""

from durashare_py import recover_mnemonic, split_bip39

TEST_MNEMONIC = "spin result brand ahead poet carpet unusual chronic denial festival toy autumn"


def test_recover_any_threshold_pair() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    for left, right in ((0, 1), (0, 2), (1, 2)):
        result = recover_mnemonic([shares[left], shares[right]], 12)
        assert result.success is True
        assert result.mnemonic == TEST_MNEMONIC
        assert result.errors.bip39 is False


def test_recover_requires_two_shares() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    result = recover_mnemonic(shares[:1], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "At least two shares" in result.errors.generic


def test_duplicate_share_numbers_fail() -> None:
    shares = split_bip39(TEST_MNEMONIC, 2, 3)
    first = shares[0]
    result = recover_mnemonic([first, first], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "unique" in result.errors.generic.lower() or "Duplicate" in result.errors.generic
