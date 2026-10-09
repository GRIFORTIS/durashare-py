"""
Security utilities tests.

Note: Constant-time properties are guaranteed by design (XOR operations with no
branching on secret data). Empirical timing tests are unreliable due to Python
interpreter overhead, OS scheduling, and GC. This matches Bitcoin Core's approach:
constant-time by construction, verified through code review.
"""

from durashare_py.security import (
    constant_time_equal,
    constant_time_string_equal,
    secure_wipe_list,
    secure_wipe_number,
)


def test_constant_time_equal_integers():
    assert constant_time_equal(123, 123) is True
    assert constant_time_equal(123, 124) is False


def test_constant_time_string_equal():
    assert constant_time_string_equal("abc", "abc") is True
    assert constant_time_string_equal("abc", "abcd") is False
    assert constant_time_string_equal("abc", "abd") is False


def test_secure_wipe_helpers():
    data = [1, 2, 3]
    secure_wipe_list(data)
    assert data == [0, 0, 0]
    secret = 42
    secret = secure_wipe_number(secret)
    assert secret == 0
