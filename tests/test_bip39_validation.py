import pytest
from mnemonic import Mnemonic

import durashare_py.recover as recover_module
import durashare_py.split as split_module
from durashare_py.seed import validate_bip39_mnemonic


def _normalize_mnemonic(text: str) -> str:
    # Must match library behavior (trim/collapse whitespace + lowercase)
    return " ".join(text.strip().lower().split())


def _strength_bits_for_word_count(word_count: int) -> int:
    # BIP39: ENT = (word_count / 3) * 32
    return (word_count // 3) * 32


def _flip_checksum_bits_keep_entropy(mnemonic: str, wordlist: list[str]) -> str:
    """
    Create a mnemonic that is guaranteed to fail BIP39 checksum validation while
    preserving the entropy bits and using only valid wordlist words.

    Strategy:
    - Parse the mnemonic into the 11-bit stream
    - Keep the ENT bits unchanged
    - Flip one checksum bit
    - Re-encode into 11-bit word indices
    """
    words = _normalize_mnemonic(mnemonic).split()
    word_count = len(words)
    if word_count % 3 != 0 or word_count < 12 or word_count > 24:
        raise ValueError("Unsupported word count for BIP39 flip helper.")

    indices_0_based = [wordlist.index(w) for w in words]
    binary_mnemonic = "".join(f"{idx:011b}" for idx in indices_0_based)

    checksum_len = word_count // 3
    entropy_bits = (word_count * 11) - checksum_len

    entropy_binary = binary_mnemonic[:entropy_bits]
    checksum_binary = binary_mnemonic[entropy_bits:]

    # Flip the first checksum bit (guaranteed mismatch vs derived checksum)
    flipped_first = "1" if checksum_binary[0] == "0" else "0"
    bad_checksum = flipped_first + checksum_binary[1:]

    bad_binary = entropy_binary + bad_checksum
    bad_indices_0_based = [int(bad_binary[i : i + 11], 2) for i in range(0, len(bad_binary), 11)]
    bad_words = [wordlist[idx] for idx in bad_indices_0_based]
    return " ".join(bad_words)


@pytest.mark.parametrize("word_count", [12, 15, 18, 21, 24])
def test_validate_bip39_mnemonic_parity_with_mnemonic_lib_on_valid_corpus(word_count: int) -> None:
    mnemo = Mnemonic("english")
    strength = _strength_bits_for_word_count(word_count)

    for _ in range(10):
        m = mnemo.generate(strength=strength)
        m_norm = _normalize_mnemonic(m)

        assert mnemo.check(m_norm) is True
        assert validate_bip39_mnemonic(m_norm, wordlist=mnemo.wordlist) is True


@pytest.mark.parametrize("word_count", [12, 15, 18, 21, 24])
def test_validate_bip39_parity_on_corrupted_checksum(word_count: int) -> None:
    mnemo = Mnemonic("english")
    strength = _strength_bits_for_word_count(word_count)

    for _ in range(10):
        m = mnemo.generate(strength=strength)
        m_norm = _normalize_mnemonic(m)
        bad = _flip_checksum_bits_keep_entropy(m_norm, mnemo.wordlist)

        assert mnemo.check(bad) is False
        assert validate_bip39_mnemonic(bad, wordlist=mnemo.wordlist) is False


def test_validate_bip39_mnemonic_parity_with_mnemonic_lib_on_normalization_variants() -> None:
    mnemo = Mnemonic("english")
    m = mnemo.generate(strength=_strength_bits_for_word_count(12))

    variant = f"   {m.upper()}   "
    norm = _normalize_mnemonic(variant)

    assert mnemo.check(norm) == validate_bip39_mnemonic(norm, wordlist=mnemo.wordlist)


def test_split_uses_validate_bip39_mnemonic(monkeypatch: pytest.MonkeyPatch) -> None:
    # If split is wired correctly, forcing validator to fail must reject even a valid mnemonic.
    monkeypatch.setattr(split_module, "validate_bip39_mnemonic", lambda *_a, **_k: False)

    mnemo = Mnemonic("english")
    m = mnemo.generate(strength=_strength_bits_for_word_count(12))

    with pytest.raises(ValueError, match="Invalid BIP39 mnemonic"):
        split_module.split_bip39(m, k=2, n=3)


def test_recover_uses_validate_bip39_mnemonic(monkeypatch: pytest.MonkeyPatch) -> None:
    mnemo = Mnemonic("english")
    m = mnemo.generate(strength=_strength_bits_for_word_count(12))

    shares = split_module.split_bip39(m, k=2, n=3)

    # If recovery is wired correctly, forcing validator to fail must surface a bip39 error.
    monkeypatch.setattr(recover_module, "validate_bip39_mnemonic", lambda *_a, **_k: False)
    result = recover_module.recover_mnemonic(shares[:2], word_count=12, strict_validation=True)
    assert result.errors.bip39 is True
