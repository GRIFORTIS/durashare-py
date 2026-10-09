"""Recovery pre-flight and checksum diagnostics."""

from durashare_py import FIELD_PRIME, Share, recover_mnemonic, split_bip39

VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def test_recover_rejects_unsupported_wordcount() -> None:
    shares = split_bip39(VALID_MNEMONIC, 2, 3)
    result = recover_mnemonic(shares, 11)
    assert result.success is False
    assert result.errors.generic is not None
    assert "12, 15, 18, 21, or 24" in result.errors.generic


def test_recover_rejects_wrong_wordshare_length() -> None:
    share1 = Share(share_number=1, word_shares=[1, 2])
    share2 = Share(share_number=2, word_shares=[1, 2])
    result = recover_mnemonic([share1, share2], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "word" in result.errors.generic


def test_recover_rejects_duplicate_share_numbers() -> None:
    share = Share(share_number=1, word_shares=[0] * 12)
    result = recover_mnemonic([share, share], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "Duplicate" in result.errors.generic


def test_recover_rejects_non_integer_share_number() -> None:
    share1 = Share(share_number="1", word_shares=[0] * 12)  # type: ignore[arg-type]
    share2 = Share(share_number=2, word_shares=[0] * 12)
    result = recover_mnemonic([share1, share2], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "must be an integer" in result.errors.generic


def test_recover_rejects_share_number_zero() -> None:
    share1 = Share(share_number=0, word_shares=[0] * 12)
    share2 = Share(share_number=2, word_shares=[0] * 12)
    result = recover_mnemonic([share1, share2], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "1-2052" in result.errors.generic


def test_recover_rejects_share_number_2053() -> None:
    share1 = Share(share_number=2053, word_shares=[0] * 12)
    share2 = Share(share_number=2, word_shares=[0] * 12)
    result = recover_mnemonic([share1, share2], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "1-2052" in result.errors.generic


def test_recover_rejects_out_of_range_share_value() -> None:
    share1 = Share(share_number=1, word_shares=[FIELD_PRIME] + [0] * 11)
    share2 = Share(share_number=2, word_shares=[0] * 12)
    result = recover_mnemonic([share1, share2], 12)
    assert result.success is False
    assert result.errors.generic is not None
    assert "between 0 and" in result.errors.generic


def test_recover_checksum_mismatch_is_not_success() -> None:
    shares = split_bip39(VALID_MNEMONIC, 2, 3)
    shares[0].checksum_shares[0] = (shares[0].checksum_shares[0] + 1) % FIELD_PRIME
    result = recover_mnemonic(shares[:2], 12)
    assert result.success is False
    assert result.mnemonic is None
    assert result.checksums.status == "fail"
    assert result.recovered_mnemonic == VALID_MNEMONIC


def test_recover_bip39_failure_keeps_candidate_out_of_mnemonic(monkeypatch) -> None:
    shares = split_bip39(VALID_MNEMONIC, 2, 3)
    monkeypatch.setattr("durashare_py.recover.validate_bip39_mnemonic", lambda *_a, **_k: False)
    result = recover_mnemonic(shares[:2], 12)
    assert result.errors.bip39 is True
    assert result.success is False
    assert result.mnemonic is None
    assert result.recovered_mnemonic == VALID_MNEMONIC
