"""Manual Authentication Layer.

MAT keys are human-readable manifest material. They are not written into payloads.
"""

from typing import TypedDict

from .field import mod_add, mod_inv, mod_mul, mod_sub, normalize_share_value
from .randomness import get_random_field_element
from .security import clear_sensitive_array, constant_time_equal

MAT_NONE = "none"
MAT_SINGLE = "single"
MAT_DUAL = "dual"
CUSTODY_NONE = "none"
CUSTODY_WHOLE = "whole"
CUSTODY_SPLIT = "split"
_WORDS_PER_ROW = 3


def normalize_mat_mode(value: str | None) -> str:
    mode = MAT_NONE if value is None else value
    if mode not in (MAT_NONE, MAT_SINGLE, MAT_DUAL):
        raise ValueError("MAT mode must be none, single, or dual.")
    return mode


def normalize_mat_custody(value: str | None, mat_mode: str) -> str:
    if mat_mode == MAT_NONE:
        return CUSTODY_NONE
    custody = CUSTODY_WHOLE if value is None else value
    if custody not in (CUSTODY_WHOLE, CUSTODY_SPLIT):
        raise ValueError("MAT custody must be whole or split when MAT is enabled.")
    return custody


def mat_column_count(mat_mode: str) -> int:
    if mat_mode == MAT_SINGLE:
        return 1
    if mat_mode == MAT_DUAL:
        return 2
    return 0


def _normalize_key_set(
    weights: list[int],
    row_pads: list[int],
    row_count: int,
    label: str = "MAT key set",
) -> tuple[list[int], list[int]]:
    if row_count <= 0:
        raise ValueError("MAT row count must be a positive integer.")
    if len(weights) != 3:
        raise ValueError(f"{label} must contain exactly three Share Weights.")
    if len(row_pads) != row_count:
        raise ValueError(f"{label} must contain exactly {row_count} Row Pads.")
    normalized_weights: list[int] = []
    normalized_pads: list[int] = []
    try:
        for index, value in enumerate(weights):
            normalized_weights.append(normalize_share_value(value, f"{label} weight u{index + 1}"))
        for index, value in enumerate(row_pads):
            normalized_pads.append(normalize_share_value(value, f"{label} Row Pad b{index + 1}"))
        return normalized_weights, normalized_pads
    except Exception:
        clear_sensitive_array(normalized_weights)
        clear_sensitive_array(normalized_pads)
        raise


def compute_mat_tag(word_row: list[int], weights: list[int], row_pad: int) -> int:
    if len(word_row) != _WORDS_PER_ROW:
        raise ValueError("A MAT row must contain exactly three word-share values.")
    if len(weights) != _WORDS_PER_ROW:
        raise ValueError("A MAT key must contain exactly three Share Weights.")
    total = normalize_share_value(row_pad, "MAT Row Pad")
    for index in range(_WORDS_PER_ROW):
        word_value = normalize_share_value(word_row[index], f"MAT word value {index + 1}")
        weight = normalize_share_value(weights[index], f"MAT Share Weight u{index + 1}")
        total = mod_add(total, mod_mul(weight, word_value))
    return total


def compute_mat_tags(word_shares: list[int], weights: list[int], row_pads: list[int]) -> list[int]:
    if len(word_shares) == 0 or len(word_shares) % _WORDS_PER_ROW != 0:
        raise ValueError("MAT requires a non-empty word-share array divisible into rows of three.")
    row_count = len(word_shares) // _WORDS_PER_ROW
    normalized_weights, normalized_pads = _normalize_key_set(weights, row_pads, row_count)
    tags: list[int] = []
    try:
        for row in range(row_count):
            base = row * _WORDS_PER_ROW
            word_row = word_shares[base : base + _WORDS_PER_ROW]
            tags.append(compute_mat_tag(word_row, normalized_weights, normalized_pads[row]))
        return tags
    except Exception:
        clear_sensitive_array(tags)
        raise
    finally:
        clear_sensitive_array(normalized_weights)
        clear_sensitive_array(normalized_pads)


def compute_mat_row_rank(word_shares: list[int], row_indices: list[int]) -> int:
    matrix: list[list[int]] = []
    try:
        for row_index in row_indices:
            base = row_index * _WORDS_PER_ROW
            matrix.append(
                [
                    normalize_share_value(word_shares[base], f"MAT row {row_index + 1} word 1"),
                    normalize_share_value(word_shares[base + 1], f"MAT row {row_index + 1} word 2"),
                    normalize_share_value(word_shares[base + 2], f"MAT row {row_index + 1} word 3"),
                ]
            )
        rank = 0
        for column in range(_WORDS_PER_ROW):
            if rank >= len(matrix):
                break
            pivot = rank
            while pivot < len(matrix) and matrix[pivot][column] == 0:
                pivot += 1
            if pivot == len(matrix):
                continue
            matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
            inverse = mod_inv(matrix[rank][column])
            for col in range(column, _WORDS_PER_ROW):
                matrix[rank][col] = mod_mul(matrix[rank][col], inverse)
            for row in range(len(matrix)):
                if row == rank or matrix[row][column] == 0:
                    continue
                factor = matrix[row][column]
                for col in range(column, _WORDS_PER_ROW):
                    matrix[row][col] = mod_sub(matrix[row][col], mod_mul(factor, matrix[rank][col]))
            rank += 1
            if rank == _WORDS_PER_ROW:
                break
        return rank
    finally:
        for matrix_row in matrix:
            clear_sensitive_array(matrix_row)


class MatColumnAudit(TypedDict):
    checked_rows: list[int]
    matched_rows: list[int]
    failed_rows: list[int]
    matching_rank: int


def audit_mat_column(
    word_shares: list[int],
    tags: list[int | None],
    weights: list[int],
    row_pads: list[int | None],
) -> MatColumnAudit:
    if len(word_shares) == 0 or len(word_shares) % _WORDS_PER_ROW != 0:
        raise ValueError("MAT audit requires complete word-share rows.")
    row_count = len(word_shares) // _WORDS_PER_ROW
    if len(weights) != _WORDS_PER_ROW:
        raise ValueError("MAT audit requires exactly three Share Weights.")
    if len(row_pads) != row_count:
        raise ValueError(f"MAT audit requires {row_count} Row Pad slots.")
    if len(tags) != row_count:
        raise ValueError(f"MAT audit requires {row_count} tag slots.")
    normalized_weights: list[int] = []
    matched_rows: list[int] = []
    failed_rows: list[int] = []
    checked_rows: list[int] = []
    try:
        for index, value in enumerate(word_shares):
            normalize_share_value(value, f"MAT audit word {index + 1}")
        for index, value in enumerate(weights):
            normalized_weights.append(
                normalize_share_value(value, f"MAT audit weight u{index + 1}")
            )
        for row in range(row_count):
            tag = tags[row]
            row_pad = row_pads[row]
            if tag is None or row_pad is None:
                continue
            normalized_tag = normalize_share_value(tag, f"MAT audit row {row + 1} tag")
            normalized_pad = normalize_share_value(row_pad, f"MAT audit row {row + 1} pad")
            base = row * _WORDS_PER_ROW
            expected = compute_mat_tag(
                word_shares[base : base + _WORDS_PER_ROW], normalized_weights, normalized_pad
            )
            checked_rows.append(row)
            if constant_time_equal(expected, normalized_tag):
                matched_rows.append(row)
            else:
                failed_rows.append(row)
        return {
            "checked_rows": checked_rows,
            "matched_rows": matched_rows,
            "failed_rows": failed_rows,
            "matching_rank": compute_mat_row_rank(word_shares, matched_rows),
        }
    finally:
        clear_sensitive_array(normalized_weights)


def generate_mat_key_set(row_count: int) -> tuple[list[int], list[int]]:
    if row_count <= 0:
        raise ValueError("MAT row count must be a positive integer.")
    weights = [get_random_field_element(), get_random_field_element(), get_random_field_element()]
    row_pads = [get_random_field_element() for _ in range(row_count)]
    return weights, row_pads


def split_mat_key_set(
    weights: list[int],
    row_pads: list[int],
    row_count: int,
) -> tuple[tuple[list[int], list[int]], tuple[list[int], list[int]]]:
    normalized_weights, normalized_pads = _normalize_key_set(weights, row_pads, row_count)
    key_a_weights: list[int] = []
    key_b_weights: list[int] = []
    key_a_pads: list[int] = []
    key_b_pads: list[int] = []
    try:
        for value in normalized_weights:
            mask = get_random_field_element()
            key_a_weights.append(mask)
            key_b_weights.append(mod_sub(value, mask))
        for value in normalized_pads:
            mask = get_random_field_element()
            key_a_pads.append(mask)
            key_b_pads.append(mod_sub(value, mask))
        return (key_a_weights, key_a_pads), (key_b_weights, key_b_pads)
    except Exception:
        clear_sensitive_array(key_a_weights)
        clear_sensitive_array(key_b_weights)
        clear_sensitive_array(key_a_pads)
        clear_sensitive_array(key_b_pads)
        raise
    finally:
        clear_sensitive_array(normalized_weights)
        clear_sensitive_array(normalized_pads)


def recombine_mat_key_sets(
    key_a: tuple[list[int], list[int]],
    key_b: tuple[list[int], list[int]],
    row_count: int,
) -> tuple[list[int], list[int]]:
    weights_a, pads_a = _normalize_key_set(key_a[0], key_a[1], row_count, "Manifest A MAT key set")
    weights_b: list[int] = []
    pads_b: list[int] = []
    try:
        weights_b, pads_b = _normalize_key_set(
            key_b[0], key_b[1], row_count, "Manifest B MAT key set"
        )
    except Exception:
        clear_sensitive_array(weights_a)
        clear_sensitive_array(pads_a)
        raise
    combined_weights: list[int] = []
    combined_pads: list[int] = []
    try:
        combined_weights = [
            mod_add(value, weights_b[index]) for index, value in enumerate(weights_a)
        ]
        combined_pads = [mod_add(value, pads_b[index]) for index, value in enumerate(pads_a)]
        return combined_weights, combined_pads
    except Exception:
        clear_sensitive_array(combined_weights)
        clear_sensitive_array(combined_pads)
        raise
    finally:
        clear_sensitive_array(weights_a)
        clear_sensitive_array(pads_a)
        clear_sensitive_array(weights_b)
        clear_sensitive_array(pads_b)
