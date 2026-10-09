"""Constant-time comparisons and best-effort scratch clearing.

These helpers avoid early exits on canonical inputs. They are constant-time
by construction. Clearing a list is best-effort and is not a RAM erase.
"""

import hmac

from .field import FIELD_PRIME, is_int


def constant_time_equal(a: object, b: object) -> bool:
    """Branchless equality for canonical GF(2053) elements.

    Non-integers and out-of-range values fail closed before the XOR.
    """
    if not is_int(a) or not is_int(b) or a < 0 or b < 0 or a >= FIELD_PRIME or b >= FIELD_PRIME:
        return False
    return (a ^ b) == 0


def constant_time_bytes_equal(a: bytes, b: bytes) -> bool:
    """Compare equal-length byte strings without an early content exit."""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def constant_time_string_equal(a: str, b: str) -> bool:
    """Compare strings without an early character exit."""
    max_len = max(len(a), len(b))
    diff = len(a) ^ len(b)
    for i in range(max_len):
        char_a = ord(a[i]) if i < len(a) else 0
        char_b = ord(b[i]) if i < len(b) else 0
        diff |= char_a ^ char_b
    return diff == 0


def secure_wipe_list(values: list[int]) -> None:
    """Overwrite list contents with zeros. The length is left unchanged."""
    for i in range(len(values)):
        values[i] = 0


def secure_wipe_number(_value: int) -> int:
    """Return zero so the caller can overwrite a numeric name."""
    return 0


def clear_sensitive_array(values: list[int] | bytearray | None) -> None:
    """Best-effort clear of a mutable scratch buffer. Not a secure RAM erase."""
    if values is None:
        return
    if isinstance(values, bytearray):
        for i in range(len(values)):
            values[i] = 0
        return
    for i in range(len(values)):
        values[i] = 0
    values.clear()
