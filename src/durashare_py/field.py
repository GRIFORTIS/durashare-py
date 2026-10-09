"""GF(2053) arithmetic for DuraShare."""

from typing import TypeGuard

FIELD_PRIME = 2053


def is_int(value: object) -> TypeGuard[int]:
    """True for integers. Booleans are rejected because they subclass int."""
    return isinstance(value, int) and not isinstance(value, bool)


def mod(value: int) -> int:
    """Reduce an integer into [0, 2052]."""
    result = value % FIELD_PRIME
    return result if result >= 0 else result + FIELD_PRIME


def mod_add(a: int, b: int) -> int:
    return mod(a + b)


def mod_sub(a: int, b: int) -> int:
    return mod(a - b)


def mod_mul(a: int, b: int) -> int:
    return mod(a * b)


def mod_inv(value: int) -> int:
    val = mod(value)
    if val == 0:
        raise ValueError("Attempted to invert zero in GF(2053).")

    t, new_t = 0, 1
    r, new_r = FIELD_PRIME, val
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise ValueError("Value is not invertible in GF(2053).")
    if t < 0:
        t += FIELD_PRIME
    return t


def mod_div(a: int, b: int) -> int:
    return mod_mul(a, mod_inv(b))


def mod_pow(a: int, n: int) -> int:
    return pow(a, n, FIELD_PRIME)


def normalize_share_value(value: object, label: str) -> int:
    """Require an integer inside GF(2053)."""
    if not is_int(value):
        raise ValueError(f"{label} must be an integer inside GF(2053).")
    if value < 0 or value >= FIELD_PRIME:
        raise ValueError(f"{label} must be between 0 and {FIELD_PRIME - 1}.")
    return value


class GF2053:
    """Legacy class-based interface for GF(2053) arithmetic."""

    PRIME = FIELD_PRIME

    add = staticmethod(mod_add)
    sub = staticmethod(mod_sub)
    mul = staticmethod(mod_mul)
    inv = staticmethod(mod_inv)
    div = staticmethod(mod_div)
    pow = staticmethod(mod_pow)
