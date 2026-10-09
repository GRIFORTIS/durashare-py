"""Exact v0.7.0 share table reproduced from published coefficients."""

from durashare_py.checksums import (
    compute_global_integrity_check_polynomial,
    compute_row_check_polynomials,
)
from durashare_py.field import mod_add
from durashare_py.polynomial import evaluate_polynomial

WORD_INDICES = [1680, 1471, 217, 42, 1338, 279, 1907, 324, 468, 682, 1844, 126]
COEFFICIENTS = [1, 2052, 1126, 2012, 710, 571, 146, 1728, 2000, 130, 122, 383]
EXPECTED = {
    1: {
        "word_shares": [1681, 1470, 1343, 1, 2048, 850, 0, 2052, 415, 812, 1966, 509],
        "checksum_shares": [389, 848, 417, 1238],
        "gic_share": 1440,
    },
    2: {
        "word_shares": [1682, 1469, 416, 2013, 705, 1421, 146, 1727, 362, 942, 35, 892],
        "checksum_shares": [1515, 35, 185, 1873],
        "gic_share": 104,
    },
    3: {
        "word_shares": [1683, 1468, 1542, 1972, 1415, 1992, 292, 1402, 309, 1072, 157, 1275],
        "checksum_shares": [588, 1275, 2006, 455],
        "gic_share": 821,
    },
}


def test_manual_polynomial_construction() -> None:
    word_polynomials = [
        [secret, coeff] for secret, coeff in zip(WORD_INDICES, COEFFICIENTS, strict=True)
    ]
    row_polys = compute_row_check_polynomials(word_polynomials)
    gic_poly = compute_global_integrity_check_polynomial(word_polynomials)
    for x, expected in EXPECTED.items():
        generated_words = [evaluate_polynomial(poly, x) for poly in word_polynomials]
        generated_rows = [evaluate_polynomial(poly, x) for poly in row_polys]
        gic_share = mod_add(evaluate_polynomial(gic_poly, x), x)
        assert generated_words == expected["word_shares"]
        assert generated_rows == expected["checksum_shares"]
        assert gic_share == expected["gic_share"]
