from durashare_py import (
    COLUMN_TAGS,
    COLUMN_TOTAL,
    WORDS_PER_ROW,
    compute_row_total,
    mod_add,
    split_bip39,
)


def test_split_checksums_self_consistent() -> None:
    mnemonic = "spin result brand ahead poet carpet unusual chronic denial festival toy autumn"
    shares = split_bip39(mnemonic, 2, 3)
    for share in shares:
        row_count = len(share.word_shares) // WORDS_PER_ROW
        word_sum = 0
        for row in range(row_count):
            base = row * WORDS_PER_ROW
            expected = mod_add(
                mod_add(
                    mod_add(share.word_shares[base], share.word_shares[base + 1]),
                    share.word_shares[base + 2],
                ),
                row + 1,
            )
            assert share.checksum_shares[row] == expected
            for offset in range(3):
                word_sum = mod_add(word_sum, share.word_shares[base + offset])
        for col in range(3):
            column_sum = 0
            for row in range(row_count):
                column_sum = mod_add(column_sum, share.word_shares[row * WORDS_PER_ROW + col])
            assert share.column_checksum_shares[col] == mod_add(column_sum, COLUMN_TAGS[col])
        expected_gic = mod_add(
            mod_add(mod_add(word_sum, compute_row_total(row_count)), COLUMN_TOTAL),
            share.share_number,
        )
        assert share.global_integrity_check_share == expected_gic
