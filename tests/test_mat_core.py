"""MAT known answers, rank, draw order, and fail-closed checks from the HTML core spec."""

import json
from collections.abc import Callable

import pytest
from spec_repo import spec_root

from durashare_py import (
    Share,
    audit_mat_column,
    clear_sharing_artifacts,
    compute_mat_tags,
    configure_environment,
    generate_mat_artifacts,
    recombine_mat_key_sets,
    verify_mat_bindings,
)
from durashare_py.types import MatColumn, MatShareKeys

CANONICAL_ROWS = [1681, 1470, 1343, 1, 2048, 850, 0, 2052, 415, 812, 1966, 509]
COLUMN_A = ([2, 4, 7], [6, 8, 10, 12], [172, 1834, 858, 745])
COLUMN_B = ([11, 13, 17], [19, 23, 29, 31], [914, 48, 912, 61])


def _synthetic(share_number: int, word: int = 1) -> Share:
    return Share(share_number=share_number, word_shares=[word] * 12)


def _sequential_source() -> tuple[Callable[[int], bytes], dict[str, int]]:
    state = {"next": 1, "draws": 0}

    def source(length: int) -> bytes:
        if length == 2:
            return b"\x00\x01"
        if length != 4:
            raise AssertionError(f"MAT draw requested {length} bytes")
        state["draws"] += 1
        value = state["next"]
        state["next"] += 1
        return value.to_bytes(4, "big")

    return source, state


def test_canonical_dual_mat_tags_match_html_and_the_frozen_vector() -> None:
    weights_a, pads_a, tags_a = COLUMN_A
    weights_b, pads_b, tags_b = COLUMN_B
    assert compute_mat_tags(CANONICAL_ROWS, weights_a, pads_a) == tags_a
    assert compute_mat_tags(CANONICAL_ROWS, weights_b, pads_b) == tags_b
    raw = (spec_root() / "test_vectors" / "vectors.json").read_text(encoding="utf-8")
    payload = json.loads(raw)
    vector = next(item for item in payload["vectors"] if item["type"] == "mat")
    by_weights = {tuple(column["weights"]): column["tags"] for column in vector["mat_columns"]}
    assert by_weights[tuple(weights_a)] == tags_a
    assert by_weights[tuple(weights_b)] == tags_b


def test_optional_mat_audit_reports_rank() -> None:
    weights, pads, tags = COLUMN_A
    rank_three_tags = tags.copy()
    rank_three_tags[3] = (rank_three_tags[3] + 1) % 2053
    rank_three = audit_mat_column(CANONICAL_ROWS, rank_three_tags, weights, pads)
    assert rank_three["matched_rows"] == [0, 1, 2]
    assert rank_three["failed_rows"] == [3]
    assert rank_three["matching_rank"] == 3

    identical = [1] * 12
    identical_tags = compute_mat_tags(identical, weights, pads)
    identical_tags[3] = (identical_tags[3] + 1) % 2053
    deficient = audit_mat_column(identical, identical_tags, weights, pads)
    assert deficient["matched_rows"] == [0, 1, 2]
    assert deficient["failed_rows"] == [3]
    assert deficient["matching_rank"] == 1

    partial_tags: list[int | None] = [tags[0], None, None, None]
    partial_pads: list[int | None] = [6, None, None, None]
    partial = audit_mat_column(CANONICAL_ROWS, partial_tags, weights, partial_pads)
    assert partial == {
        "checked_rows": [0],
        "matched_rows": [0],
        "failed_rows": [],
        "matching_rank": 1,
    }


def test_mat_audit_rejects_malformed_supplied_values_before_skipping_a_row() -> None:
    weights = [2, 4, 7]
    pads: list[int | None] = [None]
    with pytest.raises(ValueError, match="MAT audit row 1 tag must be an integer"):
        audit_mat_column([1, 2, 3], ["bad"], weights, pads)  # type: ignore[list-item]
    with pytest.raises(ValueError, match="MAT audit word 2 must be an integer"):
        audit_mat_column([1, "bad", 3], [None], weights, pads)  # type: ignore[list-item]
    source_weights: list[object] = [2, "invalid", 7]
    with pytest.raises(ValueError, match="must be an integer"):
        audit_mat_column([1, 2, 3], [19], source_weights, [6])  # type: ignore[arg-type]
    assert source_weights == [2, "invalid", 7]


def test_compute_mat_tags_leaves_caller_lists_unchanged_when_a_later_row_fails() -> None:
    words: list[object] = [1, 2, 3, 4, "invalid", 6]
    weights = [7, 8, 9]
    pads = [10, 11]
    with pytest.raises(ValueError, match="must be an integer"):
        compute_mat_tags(words, weights, pads)  # type: ignore[arg-type]
    assert words == [1, 2, 3, 4, "invalid", 6]
    assert weights == [7, 8, 9]
    assert pads == [10, 11]


def test_dual_whole_key_draw_order_and_in_place_clear() -> None:
    source, state = _sequential_source()
    configure_environment(random_source=source)
    artifacts = generate_mat_artifacts(
        [_synthetic(1), _synthetic(2, 2)],
        mat_mode="dual",
        mat_custody="whole",
    )
    held_tags = artifacts.shares[0].mat_tags[0]
    held_weights = artifacts.manifests[0].share_keys[0].columns[0].weights
    assert state["draws"] == 28
    assert [share.mat_mode for share in artifacts.shares] == ["dual", "dual"]
    assert [[len(column) for column in share.mat_tags] for share in artifacts.shares] == [
        [4, 4],
        [4, 4],
    ]
    assert all(not hasattr(share, "weights") for share in artifacts.shares)
    assert [manifest.kind for manifest in artifacts.manifests] == ["whole"]
    assert [
        [[len(column.weights), len(column.row_pads)] for column in entry.columns]
        for entry in artifacts.manifests[0].share_keys
    ] == [[[3, 4], [3, 4]], [[3, 4], [3, 4]]]
    assert list(held_weights) == [1, 2, 3]
    assert artifacts.manifests[0].share_keys[0].columns[0].row_pads == [4, 5, 6, 7]
    assert all(not hasattr(entry, "word_shares") for entry in artifacts.manifests[0].share_keys)
    clear_sharing_artifacts(artifacts)
    assert held_tags == []
    assert held_weights == []
    assert artifacts.shares == []
    assert artifacts.manifests == []


def test_split_key_doubles_draws_and_recombines_to_the_tag_keys() -> None:
    source, state = _sequential_source()
    configure_environment(random_source=source)
    artifacts = generate_mat_artifacts(
        [_synthetic(1), _synthetic(2, 2)],
        mat_mode="dual",
        mat_custody="split",
    )
    first = artifacts.shares[0]
    key_a = artifacts.manifests[0].share_keys[0].columns[0]
    key_b = artifacts.manifests[1].share_keys[0].columns[0]
    combined_weights, combined_pads = recombine_mat_key_sets(
        (key_a.weights, key_a.row_pads),
        (key_b.weights, key_b.row_pads),
        4,
    )
    assert state["draws"] == 56
    assert [manifest.kind for manifest in artifacts.manifests] == ["split-a", "split-b"]
    assert combined_weights == [1, 2, 3]
    assert combined_pads == [4, 5, 6, 7]
    assert compute_mat_tags(first.word_shares, combined_weights, combined_pads) == first.mat_tags[0]


def test_zero_mat_weights_and_pads_are_valid_field_elements() -> None:
    configure_environment(random_source=lambda length: bytes(length))
    artifacts = generate_mat_artifacts(
        [_synthetic(1, 2052)],
        mat_mode="single",
        mat_custody="whole",
    )
    column = artifacts.manifests[0].share_keys[0].columns[0]
    assert artifacts.shares[0].mat_tags[0] == [0, 0, 0, 0]
    assert column.weights == [0, 0, 0]
    assert column.row_pads == [0, 0, 0, 0]


def test_modified_tag_fails_consistency_without_returning_success() -> None:
    source, _state = _sequential_source()
    configure_environment(random_source=source)
    artifacts = generate_mat_artifacts([_synthetic(1, 42)], mat_mode="single", mat_custody="whole")
    artifacts.shares[0].mat_tags[0][0] = (artifacts.shares[0].mat_tags[0][0] + 1) % 2053
    with pytest.raises(ValueError, match="MAT consistency check failed for Share 1") as caught:
        verify_mat_bindings(
            artifacts.shares,
            artifacts.manifests[0].share_keys,
            "single",
        )
    assert "row 1" in str(caught.value)
    assert verify_mat_bindings is not None


def _verify_message(
    mutate: Callable[[list[Share], list[MatShareKeys]], None],
    mode: str | None,
) -> str:
    source, _state = _sequential_source()
    configure_environment(random_source=source)
    artifacts = generate_mat_artifacts([_synthetic(1, 42)], mat_mode="dual", mat_custody="whole")
    shares = [
        Share(
            share_number=share.share_number,
            word_shares=share.word_shares.copy(),
            mat_mode=share.mat_mode,
            mat_tags=[column.copy() for column in share.mat_tags],
        )
        for share in artifacts.shares
    ]
    keys = [
        MatShareKeys(
            entry.share_number,
            [
                MatColumn(column.column, column.weights.copy(), column.row_pads.copy())
                for column in entry.columns
            ],
        )
        for entry in artifacts.manifests[0].share_keys
    ]
    try:
        mutate(shares, keys)
        if mode is None:
            verify_mat_bindings(shares, keys)  # type: ignore[call-arg]
        else:
            returned = verify_mat_bindings(shares, keys, mode)
            return f"returned {returned}"
        return ""
    except ValueError as error:
        return str(error)
    finally:
        clear_sharing_artifacts(artifacts)


def test_mat_verification_fails_closed_for_malformed_inputs() -> None:
    messages = {
        "missing_mode": _verify_message(lambda _shares, _keys: None, None),
        "wrong_mode": _verify_message(
            lambda shares, _keys: shares[0].__setattr__("mat_mode", "single"),
            "dual",
        ),
        "truncated": _verify_message(
            lambda shares, keys: (shares[0].mat_tags.clear(), keys[0].columns.clear()),
            "dual",
        ),
        "non_array_tags": _verify_message(
            lambda shares, _keys: shares[0].__setattr__("mat_tags", None),
            "dual",
        ),
        "non_array_columns": _verify_message(
            lambda _shares, keys: keys[0].__setattr__("columns", None),
            "dual",
        ),
        "wrong_order": _verify_message(
            lambda _shares, keys: keys[0].columns[0].__setattr__("column", 2),
            "dual",
        ),
        "short_tags": _verify_message(lambda shares, _keys: shares[0].mat_tags[0].pop(), "dual"),
        "unsafe_alias": _verify_message(
            lambda shares, _keys: shares[0]
            .mat_tags[0]
            .__setitem__(0, shares[0].mat_tags[0][0] + 2**32),
            "dual",
        ),
        "string_tag": _verify_message(
            lambda shares, _keys: shares[0]
            .mat_tags[0]
            .__setitem__(0, str(shares[0].mat_tags[0][0])),
            "dual",
        ),
        "invalid_weight": _verify_message(
            lambda _shares, keys: keys[0].columns[0].weights.__setitem__(0, 2053),
            "dual",
        ),
        "fractional_pad": _verify_message(
            lambda _shares, keys: keys[0].columns[0].row_pads.__setitem__(0, 0.5),
            "dual",
        ),
        "invalid_share_number": _verify_message(
            lambda shares, _keys: shares[0].__setattr__("share_number", 0),
            "dual",
        ),
    }
    assert "explicit expected MAT mode" in messages["missing_mode"]
    assert "does not match" in messages["wrong_mode"]
    assert "metadata do not match" in messages["truncated"]
    assert "must be arrays" in messages["non_array_tags"]
    assert "must be arrays" in messages["non_array_columns"]
    assert "canonical order" in messages["wrong_order"]
    assert "length mismatch" in messages["short_tags"]
    assert "between 0 and 2052" in messages["unsafe_alias"]
    assert "must be an integer" in messages["string_tag"]
    assert "between 0 and 2052" in messages["invalid_weight"]
    assert "must be an integer" in messages["fractional_pad"]
    assert "between 1 and 2052" in messages["invalid_share_number"]
    assert all(not message.startswith("returned") for message in messages.values())


def test_recombine_rejects_malformed_manifest_b_and_leaves_caller_keys() -> None:
    key_a = ([1, 2, 3], [4, 5])
    key_b = ([6, 7, 8], [9, "invalid"])
    with pytest.raises(ValueError, match="Manifest B MAT key set Row Pad b2 must be an integer"):
        recombine_mat_key_sets(key_a, key_b, 2)  # type: ignore[arg-type]
    assert key_a == ([1, 2, 3], [4, 5])
    assert key_b == ([6, 7, 8], [9, "invalid"])
