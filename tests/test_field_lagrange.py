import pytest

from durashare_py.field import (
    FIELD_PRIME,
    mod,
    mod_add,
    mod_div,
    mod_inv,
    mod_mul,
    mod_sub,
)
from durashare_py.lagrange import (
    compute_lagrange_multipliers,
    lagrange_interpolate_at_zero,
)


def test_mod_wraparound_and_negatives():
    assert mod(2053) == 0
    assert mod(2055) == 2
    assert mod(-1) == FIELD_PRIME - 1
    assert mod(-2054) == 2052


def test_mod_add_sub_mul_div():
    assert mod_add(2000, 100) == 47  # wrap
    assert mod_sub(100, 200) == FIELD_PRIME - 100
    assert mod_mul(2, 1026) == FIELD_PRIME - 1
    assert mod_div(10, 2) == 5
    assert mod_div(-1, 1) == FIELD_PRIME - 1


def test_mod_inv_known_values_and_zero_error():
    assert mod_inv(2) == 1027
    assert mod_inv(1027) == 2
    with pytest.raises(ValueError):
        mod_inv(0)


def test_lagrange_interpolate_matches_known_secret():
    # From doc example: secret 1679 with points (1,82) (2,538)
    secret = lagrange_interpolate_at_zero([(1, 82), (2, 538)])
    assert secret == 1679


def test_lagrange_with_three_points_constant_term():
    # Polynomial f(x) = 123 + 7x => points (1,130), (2,137), (3,144)
    points = [(1, 130), (2, 137), (3, 144)]
    secret = lagrange_interpolate_at_zero(points)
    assert secret == 123


def test_compute_lagrange_multipliers_expected_values():
    assert compute_lagrange_multipliers([1, 2]) == [2, FIELD_PRIME - 1]
    assert compute_lagrange_multipliers([1, 3]) == [1028, 1026]


def test_compute_lagrange_multipliers_validation():
    with pytest.raises(ValueError):
        compute_lagrange_multipliers([])  # needs at least two
    with pytest.raises(ValueError):
        compute_lagrange_multipliers([1, 1])  # duplicates
    with pytest.raises(ValueError):
        compute_lagrange_multipliers([0, 2])  # zero not allowed
