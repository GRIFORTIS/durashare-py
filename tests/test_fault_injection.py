from unittest.mock import patch

import pytest

import durashare_py.polynomial
from durashare_py import generate_valid_mnemonic, split_bip39


class TestFaultInjection:
    """
    Fault Injection Tests

    These tests simulate hardware faults (e.g. bit flips, memory corruption) to verify
    that the "Double-Check" integrity systems in split_bip39 correctly detect
    inconsistencies and abort the process.
    """

    def test_detects_row_checksum_path_mismatch(self):
        """
        Simulate a bit flip during polynomial evaluation (Path B).
        The direct summation (Path A) will remain correct.
        split_bip39 MUST detect the disagreement and raise ValueError.
        """
        mnemonic = generate_valid_mnemonic(12)

        # Get reference to original function
        original_evaluate = durashare_py.polynomial.evaluate_polynomial

        # Scenario: 12 words, 2-of-3 scheme.
        # Call sequence for Share 1 generation:
        # 1-12:  Word polynomials (creates share.wordShares -> Path A source)
        # 13-16: Row checksum polynomials (Path B source)
        # 17:    GIC polynomial (Path B source)

        # We target call #13 (First row, Path B calculation).
        # This makes the polynomial evaluation (Path B) disagree with the sum of words (Path A).

        TARGET_CALL = 13
        call_counter = 0

        def faulty_evaluate(poly, x):
            nonlocal call_counter
            call_counter += 1
            result = original_evaluate(poly, x)

            if call_counter == TARGET_CALL:
                return (result + 1) % 2053  # Inject fault: bit flip
            return result

        with patch("durashare_py.split.evaluate_polynomial", side_effect=faulty_evaluate):
            with pytest.raises(ValueError, match="Row checksum path mismatch"):
                split_bip39(mnemonic, 2, 3)

    def test_detects_gic_path_mismatch(self):
        """
        Target the Global Integrity Check calculation.
        This makes the GIC polynomial evaluation (Path B) disagree with the sum of all
        words (Path A).
        """
        mnemonic = generate_valid_mnemonic(12)
        original_evaluate = durashare_py.polynomial.evaluate_polynomial

        # 12 words + 4 rows + 3 columns = 19 calls. The 20th is GIC.
        TARGET_CALL = 20
        call_counter = 0

        def faulty_evaluate(poly, x):
            nonlocal call_counter
            call_counter += 1
            result = original_evaluate(poly, x)

            if call_counter == TARGET_CALL:
                return (result + 1) % 2053  # Inject fault
            return result

        with patch("durashare_py.split.evaluate_polynomial", side_effect=faulty_evaluate):
            with pytest.raises(ValueError, match="Global integrity path mismatch"):
                split_bip39(mnemonic, 2, 3)

    def test_detects_mismatch_on_subsequent_shares(self):
        """
        Scenario: Fault happens during Share 2 generation.
        """
        mnemonic = generate_valid_mnemonic(12)
        original_evaluate = durashare_py.polynomial.evaluate_polynomial

        # Share 1: 12 words + 4 rows + 3 columns + 1 GIC = 20 calls.
        # Share 2 row 1 is call 20 + 13.
        TARGET_CALL = 33
        call_counter = 0

        def faulty_evaluate(poly, x):
            nonlocal call_counter
            call_counter += 1
            result = original_evaluate(poly, x)

            if call_counter == TARGET_CALL:
                return (result + 1) % 2053
            return result

        with patch("durashare_py.split.evaluate_polynomial", side_effect=faulty_evaluate):
            with pytest.raises(ValueError, match="Row checksum path mismatch"):
                split_bip39(mnemonic, 2, 3)
