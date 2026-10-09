"""Position-bound row checksums, column checksums, and printed GIC.

Generation uses the v0.7.0 formulas only. Path B polynomials must agree with
the direct sums before a share is returned.
"""

from collections.abc import Sequence
from typing import TypedDict

from .field import mod_add, normalize_share_value

WORDS_PER_ROW = 3
COLUMN_TAGS = (100, 200, 300)
COLUMN_TOTAL = 600


class ChecksumAudit(TypedDict):
    row_fails: list[int]
    col_fails: list[int]
    gic_fail: bool


def is_supplied_field(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def compute_row_total(row_count: int) -> int:
    return (row_count * (row_count + 1)) // 2


def _add_constant_term(polynomial: list[int], offset: int) -> list[int]:
    result = polynomial.copy()
    result[0] = mod_add(result[0], offset)
    return result


def compute_row_checks(word_indices: list[int]) -> list[int]:
    """Row checksum (w1 + w2 + w3 + row number) mod 2053. Row numbers start at 1."""
    row_count = len(word_indices) // WORDS_PER_ROW
    checks: list[int] = []
    for row in range(row_count):
        base = row * WORDS_PER_ROW
        total = mod_add(
            mod_add(word_indices[base], word_indices[base + 1]),
            word_indices[base + 2],
        )
        checks.append(mod_add(total, row + 1))
    return checks


def compute_column_checks(word_indices: list[int]) -> list[int]:
    """Column checksum with tags 100, 200, and 300."""
    row_count = len(word_indices) // WORDS_PER_ROW
    checks: list[int] = []
    for col in range(3):
        total = 0
        for row in range(row_count):
            total = mod_add(total, word_indices[row * WORDS_PER_ROW + col])
        checks.append(mod_add(total, COLUMN_TAGS[col]))
    return checks


def compute_global_integrity_check(word_indices: list[int]) -> int:
    """Unbound GIC: word sum + row total + column total. Share binding is added later."""
    row_count = len(word_indices) // WORDS_PER_ROW
    word_sum = 0
    for value in word_indices:
        word_sum = mod_add(word_sum, value)
    return mod_add(mod_add(word_sum, compute_row_total(row_count)), COLUMN_TOTAL)


def sum_polynomials(polynomials: list[list[int]]) -> list[int]:
    if len(polynomials) == 0:
        raise ValueError("Cannot sum zero polynomials")
    degree = len(polynomials[0])
    for index, poly in enumerate(polynomials[1:], start=1):
        if len(poly) != degree:
            raise ValueError(
                f"Polynomial degree mismatch: expected {degree - 1} but got {len(poly) - 1} "
                f"at index {index}"
            )
    result = [0] * degree
    for poly in polynomials:
        for i in range(degree):
            result[i] = mod_add(result[i], poly[i])
    return result


def compute_row_check_polynomials(word_polynomials: list[list[int]]) -> list[list[int]]:
    row_count = len(word_polynomials) // WORDS_PER_ROW
    row_polynomials: list[list[int]] = []
    for row in range(row_count):
        base = row * WORDS_PER_ROW
        summed = sum_polynomials(
            [
                word_polynomials[base],
                word_polynomials[base + 1],
                word_polynomials[base + 2],
            ]
        )
        row_polynomials.append(_add_constant_term(summed, row + 1))
    return row_polynomials


def compute_column_check_polynomials(word_polynomials: list[list[int]]) -> list[list[int]]:
    row_count = len(word_polynomials) // WORDS_PER_ROW
    column_polynomials: list[list[int]] = []
    for col in range(3):
        column_words = [word_polynomials[row * WORDS_PER_ROW + col] for row in range(row_count)]
        column_polynomials.append(
            _add_constant_term(sum_polynomials(column_words), COLUMN_TAGS[col])
        )
    return column_polynomials


def compute_global_integrity_check_polynomial(word_polynomials: list[list[int]]) -> list[int]:
    row_count = len(word_polynomials) // WORDS_PER_ROW
    summed = sum_polynomials(word_polynomials)
    with_rows = _add_constant_term(summed, compute_row_total(row_count))
    return _add_constant_term(with_rows, COLUMN_TOTAL)


def audit_optional_checksums(
    share_number: int,
    word_shares: list[int],
    checksum_shares: Sequence[int | None],
    column_checksum_shares: Sequence[int | None],
    global_integrity_check_share: int | None,
    row_count: int,
    row_total: int,
) -> ChecksumAudit:
    """Check supplied row, column, and GIC values. Missing values are not failures."""
    row_fails: list[int] = []
    col_fails: list[int] = []
    gic_fail = False
    word_sum = 0
    checksum_sum = 0
    column_checksum_sum = 0
    has_row_error = False
    has_column_error = False

    for row in range(row_count):
        base = row * WORDS_PER_ROW
        w0 = word_shares[base]
        w1 = word_shares[base + 1]
        w2 = word_shares[base + 2]
        word_sum = mod_add(mod_add(word_sum, w0), mod_add(w1, w2))
        checksum = checksum_shares[row] if row < len(checksum_shares) else None
        if not is_supplied_field(checksum):
            continue
        row_sum = mod_add(mod_add(mod_add(w0, w1), w2), row + 1)
        if row_sum != checksum:
            row_fails.append(row)
            has_row_error = True
        else:
            checksum_sum = mod_add(checksum_sum, checksum)

    for col in range(3):
        column_checksum = column_checksum_shares[col] if col < len(column_checksum_shares) else None
        if not is_supplied_field(column_checksum):
            continue
        column_sum = 0
        for row in range(row_count):
            column_sum = mod_add(column_sum, word_shares[row * WORDS_PER_ROW + col])
        if mod_add(column_sum, COLUMN_TAGS[col]) != column_checksum:
            col_fails.append(col)
            has_column_error = True
        else:
            column_checksum_sum = mod_add(column_checksum_sum, column_checksum)

    if not is_supplied_field(global_integrity_check_share):
        return {"row_fails": row_fails, "col_fails": col_fails, "gic_fail": gic_fail}

    gic = global_integrity_check_share
    from_words = mod_add(mod_add(mod_add(word_sum, row_total), COLUMN_TOTAL), share_number)
    gic_ok = gic == from_words
    all_rows = all(
        is_supplied_field(checksum_shares[row] if row < len(checksum_shares) else None)
        for row in range(row_count)
    )
    all_cols = len(column_checksum_shares) >= 3 and all(
        is_supplied_field(column_checksum_shares[col]) for col in range(3)
    )
    if all_rows and not has_row_error:
        from_rows = mod_add(mod_add(checksum_sum, COLUMN_TOTAL), share_number)
        gic_ok = gic_ok and gic == from_rows
    if all_cols and not has_column_error:
        from_cols = mod_add(mod_add(column_checksum_sum, row_total), share_number)
        gic_ok = gic_ok and gic == from_cols
    if not gic_ok:
        gic_fail = True
    return {"row_fails": row_fails, "col_fails": col_fails, "gic_fail": gic_fail}


def require_share_value(value: object, label: str) -> int:
    return normalize_share_value(value, label)
