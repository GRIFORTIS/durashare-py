import pytest

from durashare_py import (
    generate_valid_mnemonic,
    indices_to_mnemonic,
    mnemonic_to_indices,
    parse_input,
)
from durashare_py.seed import validate_bip39_mnemonic


def test_mnemonic_index_roundtrip():
    mnemonic = generate_valid_mnemonic(12)
    indices = mnemonic_to_indices(mnemonic)
    rebuilt = indices_to_mnemonic(indices)
    assert rebuilt == mnemonic


def test_parse_input_words_indices_and_mixed():
    words, indices, kind = parse_input("abandon abandon abandon")
    assert kind == "words"
    assert indices == [1, 1, 1]

    words, indices, kind = parse_input("1 2 3")
    assert kind == "indices"
    assert words[0] == "abandon"
    assert indices[:3] == [1, 2, 3]

    words, indices, kind = parse_input("1 abandon 2")
    assert kind == "mixed"
    assert indices[0] == 1 and words[1] == "abandon"


def test_parse_input_rejects_unknown_or_out_of_range():
    with pytest.raises(ValueError):
        parse_input("notaword")
    with pytest.raises(ValueError):
        parse_input("3000")  # out of range (valid range is 1-2048)
    with pytest.raises(ValueError):
        parse_input("0")  # 0 is no longer valid (1-based indexing)


def test_validate_bip39_mnemonic_accepts_known_good_and_rejects_bad_inputs():
    # Known BIP39 test mnemonic (12 words)
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    assert validate_bip39_mnemonic(mnemonic) is True

    # Non-string inputs are rejected
    assert validate_bip39_mnemonic(None) is False  # type: ignore[arg-type]

    # Invalid length is rejected (11 words)
    assert validate_bip39_mnemonic("abandon " * 10 + "about") is False

    # Unknown word is rejected
    bad = mnemonic.replace("about", "notaword")
    assert validate_bip39_mnemonic(bad) is False


def test_generate_valid_mnemonic_rejects_unsupported_word_count():
    with pytest.raises(ValueError):
        generate_valid_mnemonic(11)
    assert len(generate_valid_mnemonic(15).split()) == 15


def test_indices_to_mnemonic_rejects_out_of_range_indices():
    with pytest.raises(ValueError):
        indices_to_mnemonic([0])
