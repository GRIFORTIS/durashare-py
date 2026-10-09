"""Lagrange interpolation at zero in GF(2053)."""

from .field import FIELD_PRIME, mod, mod_add, mod_inv, mod_mul, mod_sub, normalize_share_value


def lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """Recover f(0) from share points (x, y)."""
    if len(points) == 0:
        raise ValueError("Interpolation requires at least one point.")

    sum_val = 0
    for j in range(len(points)):
        numerator = 1
        denominator = 1
        xj = mod(points[j][0])
        yj = mod(points[j][1])
        for m in range(len(points)):
            if m == j:
                continue
            xm = mod(points[m][0])
            numerator = mod_mul(numerator, mod(FIELD_PRIME - xm))
            denominator = mod_mul(denominator, mod_sub(xj, xm))
        term = mod_mul(yj, mod_mul(numerator, mod_inv(denominator)))
        sum_val = mod_add(sum_val, term)
    return sum_val


def compute_lagrange_multipliers(share_numbers: list[int]) -> list[int]:
    """Lagrange coefficients at x = 0 for the given share indices."""
    if len(share_numbers) < 2:
        raise ValueError("At least two share numbers are required to compute multipliers.")

    normalized = [
        normalize_share_value(value, f"Share number {index + 1}")
        for index, value in enumerate(share_numbers)
    ]
    seen: set[int] = set()
    for value in normalized:
        if value == 0:
            raise ValueError("Share numbers cannot be zero.")
        if value in seen:
            raise ValueError("Share numbers must be unique.")
        seen.add(value)

    multipliers: list[int] = []
    for i, xi_raw in enumerate(normalized):
        numerator = 1
        denominator = 1
        xi = mod(xi_raw)
        for j, xj_raw in enumerate(normalized):
            if i == j:
                continue
            xj = mod(xj_raw)
            numerator = mod_mul(numerator, mod(FIELD_PRIME - xj))
            denominator = mod_mul(denominator, mod_sub(xi, xj))
        multipliers.append(mod_mul(numerator, mod_inv(denominator)))
    return multipliers
