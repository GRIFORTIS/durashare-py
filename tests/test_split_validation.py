import pytest

from durashare_py import FIELD_PRIME, split_bip39

VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def test_split_rejects_invalid_k_and_n():
    with pytest.raises(ValueError):
        split_bip39(VALID_MNEMONIC, 1, 3)
    with pytest.raises(ValueError):
        split_bip39(VALID_MNEMONIC, 4, 3)
    with pytest.raises(ValueError):
        split_bip39(VALID_MNEMONIC, 2, FIELD_PRIME)


def test_split_requires_integer_params():
    with pytest.raises(ValueError):
        split_bip39(VALID_MNEMONIC, 2.5, 3)
    with pytest.raises(ValueError):
        split_bip39(VALID_MNEMONIC, 2, "3")  # type: ignore


def test_split_unknown_word_in_custom_wordlist():
    custom_wordlist = ["foo"] * 2048
    with pytest.raises(ValueError):
        split_bip39("foo bar baz", 2, 3, wordlist=custom_wordlist)
