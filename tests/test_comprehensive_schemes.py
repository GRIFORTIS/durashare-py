import itertools

import pytest

from durashare_py import generate_valid_mnemonic, recover_mnemonic, split_bip39


class TestComprehensiveSchemes:
    @pytest.mark.parametrize("word_count", [12, 15, 18, 21, 24])
    @pytest.mark.parametrize("k, n", [(2, 3), (2, 4), (3, 5)])
    def test_all_combinations(self, word_count: int, k: int, n: int) -> None:
        mnemonic = generate_valid_mnemonic(word_count)
        shares = split_bip39(mnemonic, k, n)
        assert len(shares) == n
        for subset in itertools.combinations(shares, k):
            result = recover_mnemonic(list(subset), word_count)
            numbers = [share.share_number for share in subset]
            assert result.success is True, f"Failed recovery for k={k}, n={n}, shares {numbers}"
            assert result.mnemonic == mnemonic
