"""BIP39 helpers.

Wordlist positions are 0-based. DuraShare secrets are 1-based indices in 1..2048.
The conversion happens only at this boundary.
"""

from mnemonic import Mnemonic

from .envelope import compute_sha256
from .field import FIELD_PRIME
from .security import constant_time_string_equal

SUPPORTED_WORD_COUNTS = (12, 15, 18, 21, 24)


def _english_wordlist() -> list[str]:
    return Mnemonic("english").wordlist


def generate_valid_mnemonic(word_count: int) -> str:
    if word_count not in SUPPORTED_WORD_COUNTS:
        raise ValueError("Word count must be 12, 15, 18, 21, or 24.")
    strength = (word_count // 3) * 32
    return Mnemonic("english").generate(strength=strength)


def sanitize_mnemonic(mnemonic: str) -> str:
    if not isinstance(mnemonic, str):
        raise ValueError("Mnemonic must be a string.")
    normalized = " ".join(mnemonic.strip().lower().split())
    if not normalized:
        raise ValueError("Mnemonic cannot be empty.")
    return normalized


def mnemonic_to_indices(mnemonic: str, wordlist: list[str] | None = None) -> list[int]:
    if wordlist is None:
        wordlist = _english_wordlist()
    words = mnemonic.strip().lower().split()
    indices: list[int] = []
    for idx, word in enumerate(words):
        try:
            word_index = wordlist.index(word)
        except ValueError as err:
            raise ValueError(
                f'Word "{word}" at position {idx + 1} is not in the BIP39 wordlist'
            ) from err
        indices.append(word_index + 1)
    return indices


def indices_to_mnemonic(indices: list[int], wordlist: list[str] | None = None) -> str:
    if wordlist is None:
        wordlist = _english_wordlist()
    words: list[str] = []
    for pos, index in enumerate(indices, start=1):
        if index < 1 or index > len(wordlist):
            raise ValueError(f"Index {index} at position {pos} is out of range (1-{len(wordlist)})")
        words.append(wordlist[index - 1])
    return " ".join(words)


def parse_input(
    input_text: str, wordlist: list[str] | None = None
) -> tuple[list[str], list[int], str]:
    """Parse words or bare indices. Returns (words, indices, kind)."""
    if wordlist is None:
        wordlist = _english_wordlist()
    tokens = input_text.strip().lower().replace(",", " ").replace("\n", " ").split()
    words: list[str] = []
    indices: list[int] = []
    has_words = False
    has_indices = False
    for token in tokens:
        if token.isdigit():
            index = int(token, 10)
            if 1 <= index <= 2048:
                indices.append(index)
                words.append(wordlist[index - 1])
                has_indices = True
            else:
                raise ValueError(f"Index {index} is out of range (1-2048)")
        else:
            try:
                word_index = wordlist.index(token)
            except ValueError as err:
                raise ValueError(f'Word "{token}" is not in the BIP39 wordlist') from err
            words.append(token)
            indices.append(word_index + 1)
            has_words = True
    if has_words and has_indices:
        kind = "mixed"
    elif has_indices:
        kind = "indices"
    else:
        kind = "words"
    return words, indices, kind


def parse_share_value(
    raw: object,
    wordlist: list[str] | None = None,
    *,
    allow_numeric: bool = True,
) -> dict[str, object]:
    """Parse a word, a field element, or a 0001-word / word-0001 pair."""
    if wordlist is None:
        wordlist = _english_wordlist()
    if raw is None:
        return {"ok": False, "reason": "empty"}
    trimmed = str(raw).strip()
    if trimmed == "":
        return {"ok": False, "reason": "empty"}
    normalized = trimmed.lower()
    compact = "".join(normalized.split())
    if normalized in wordlist:
        return {"ok": True, "value": wordlist.index(normalized) + 1, "source": "word"}

    has_digits = any(character.isdigit() for character in compact)
    if compact.isdigit():
        if not allow_numeric:
            return {"ok": False, "reason": "numeric-not-allowed"}
        numeric = int(compact, 10)
        if 0 <= numeric < FIELD_PRIME:
            return {"ok": True, "value": numeric, "source": "number"}
        return {"ok": False, "reason": "range", "value": numeric}

    if not allow_numeric:
        reason = "numeric-not-allowed" if has_digits else "unknown"
        return {"ok": False, "reason": reason}

    def parse_token(token: str | None) -> dict[str, object] | None:
        if not token:
            return None
        if token.isdigit():
            return {"type": "number", "value": int(token, 10)}
        if token in wordlist:
            return {"type": "word", "value": wordlist.index(token) + 1}
        return None

    part_a: str | None = None
    part_b: str | None = None
    if "-" in compact:
        parts = [part for part in compact.split("-") if part]
        if len(parts) != 2:
            return {"ok": False, "reason": "unknown"}
        part_a, part_b = parts
    else:
        word_chars = "".join(character for character in compact if character.isalpha())
        number_chars = "".join(character for character in compact if character.isdigit())
        if word_chars and number_chars:
            part_a, part_b = word_chars, number_chars
        else:
            return {"ok": False, "reason": "unknown"}

    token_a = parse_token(part_a)
    token_b = parse_token(part_b)
    if token_a is None or token_b is None:
        return {"ok": False, "reason": "unknown"}

    def in_range(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < FIELD_PRIME

    if token_a["type"] == "number" and token_b["type"] == "number":
        if not in_range(token_a["value"]) or not in_range(token_b["value"]):
            left = token_a["value"]
            right = token_b["value"]
            largest = (
                left
                if isinstance(left, int) and isinstance(right, int) and left >= right
                else right
            )
            return {"ok": False, "reason": "range", "value": largest}
        if token_a["value"] != token_b["value"]:
            return {"ok": False, "reason": "mismatch"}
        return {"ok": True, "value": token_a["value"], "source": "number"}
    if token_a["type"] == "word" and token_b["type"] == "number":
        if not in_range(token_b["value"]):
            return {"ok": False, "reason": "range", "value": token_b["value"]}
        if token_a["value"] != token_b["value"]:
            return {"ok": False, "reason": "mismatch"}
        return {"ok": True, "value": token_b["value"], "source": "word-number"}
    if token_a["type"] == "number" and token_b["type"] == "word":
        if not in_range(token_a["value"]):
            return {"ok": False, "reason": "range", "value": token_a["value"]}
        if token_a["value"] != token_b["value"]:
            return {"ok": False, "reason": "mismatch"}
        return {"ok": True, "value": token_a["value"], "source": "number-word"}
    return {"ok": False, "reason": "unknown"}


def validate_bip39_mnemonic(mnemonic: str, wordlist: list[str] | None = None) -> bool:
    """Constant-time BIP39 checksum check. A hash hard-stop propagates."""
    if not isinstance(mnemonic, str):
        return False
    words = mnemonic.strip().lower().split()
    word_count = len(words)
    if word_count % 3 != 0 or word_count < 12 or word_count > 24:
        return False
    if wordlist is None:
        wordlist = _english_wordlist()
    try:
        indices_0_based = [wordlist.index(word) for word in words]
    except ValueError:
        return False
    binary_mnemonic = "".join(f"{idx:011b}" for idx in indices_0_based)
    checksum_length = word_count // 3
    entropy_bits = (word_count * 11) - checksum_length
    if entropy_bits % 8 != 0:
        return False
    entropy_binary = binary_mnemonic[:entropy_bits]
    checksum_binary = binary_mnemonic[entropy_bits:]
    entropy_bytes = bytes(int(entropy_binary[i : i + 8], 2) for i in range(0, entropy_bits, 8))
    hash_bytes = compute_sha256(entropy_bytes)
    hash_binary = "".join(f"{byte:08b}" for byte in hash_bytes)
    derived_checksum = hash_binary[:checksum_length]
    return constant_time_string_equal(derived_checksum, checksum_binary)
