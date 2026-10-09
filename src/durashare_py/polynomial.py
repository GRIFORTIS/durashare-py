"""Polynomial creation and evaluation in GF(2053)."""

from .field import mod, mod_add, mod_mul
from .randomness import get_random_field_element
from .security import clear_sensitive_array


def random_polynomial(secret: int, degree: int) -> list[int]:
    """Degree-(k-1) polynomial with the secret as the constant term.

    The caller runs the CSPRNG smoke test before the batch and the coefficient
    canary after every non-constant coefficient has been drawn.
    """
    coefficients = [mod(secret)]
    try:
        for _ in range(degree):
            coefficients.append(get_random_field_element())
        return coefficients
    except Exception:
        clear_sensitive_array(coefficients)
        raise


def evaluate_polynomial(coefficients: list[int], x: int) -> int:
    """Horner evaluation inside GF(2053)."""
    result = 0
    field_x = mod(x)
    for index in range(len(coefficients) - 1, -1, -1):
        result = mod_add(mod_mul(result, field_x), coefficients[index])
    return result
