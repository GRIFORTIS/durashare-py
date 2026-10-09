"""CSPRNG, coefficient-canary, rejection-cap, and PBKDF2 hard stops from the HTML spec."""

import hashlib
from collections.abc import Callable

import pytest

from durashare_py import (
    CryptoHardStopError,
    RngHardStopError,
    assert_coefficient_batch_healthy,
    assert_csprng_healthy,
    configure_environment,
    create_sharing_artifacts,
    get_random_field_element,
    is_rng_hard_stop_error,
    split_bip39,
)
from durashare_py import randomness as randomness_module

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
PAIR = [42, 42, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11]
SPARSE_SIX = [7, 100, 7, 101, 7, 102, 7, 103, 7, 104, 7, 105]


def _varying_smoke(call: int) -> bytes:
    burst = bytearray((index + call * 31) & 0xFF for index in range(256))
    burst[-1] ^= 1
    return bytes(burst)


def _scripted_source(
    field_values: list[int] | None,
    *,
    smoke: str = "varying",
    throw_on_field: int | None = None,
) -> tuple[Callable[[int], bytes], dict[str, int]]:
    state = {"smoke": 0, "field": 0}

    def source(length: int) -> bytes:
        if length == 2:
            return b"\x11\x22"
        if length == 256:
            state["smoke"] += 1
            if smoke == "zero":
                return bytes(length)
            if smoke == "ff":
                return b"\xff" * length
            if smoke == "sentinel":
                return b"\xa5" * length
            if smoke == "identical":
                return bytes((index * 17 + 3) & 0xFF for index in range(length))
            return _varying_smoke(state["smoke"])
        if length == 8:
            return bytes(range(8))
        if length != 4:
            raise AssertionError(f"unexpected random length {length}")
        state["field"] += 1
        if throw_on_field is not None and state["field"] == throw_on_field:
            raise RuntimeError("simulated mid-polynomial CSPRNG fault")
        if field_values is not None:
            if not field_values:
                raise AssertionError("field script exhausted")
            value = field_values.pop(0)
        else:
            value = (state["field"] * 17 + 3) % 2053
        return int(value).to_bytes(4, "big")

    return source, state


def test_constant_zero_ff_sentinel_and_identical_bursts_hard_stop_split() -> None:
    for smoke in ("zero", "ff", "sentinel", "identical"):
        source, _state = _scripted_source([], smoke=smoke)
        configure_environment(random_source=source)
        with pytest.raises(RngHardStopError):
            split_bip39(ABANDON, 2, 3)


def test_all_identical_coefficients_hard_stop_after_smoke() -> None:
    source, state = _scripted_source([0] * 12)
    configure_environment(random_source=source)
    with pytest.raises(RngHardStopError, match="identical"):
        split_bip39(ABANDON, 2, 3)
    assert state["field"] == 12
    assert state["smoke"] == 2


def test_sparse_frequency_six_hard_stops_split() -> None:
    source, _state = _scripted_source(SPARSE_SIX.copy())
    configure_environment(random_source=source)
    with pytest.raises(RngHardStopError, match="repeated"):
        split_bip39(ABANDON, 2, 3)


def test_coefficient_canary_frequency_rules() -> None:
    assert_coefficient_batch_healthy([1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    assert_coefficient_batch_healthy([9, 9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7])
    with pytest.raises(RngHardStopError) as contiguous:
        assert_coefficient_batch_healthy([9, 9, 9, 9, 9, 9, 1, 2, 3, 4])
    with pytest.raises(RngHardStopError) as sparse:
        assert_coefficient_batch_healthy([9, 1, 9, 2, 9, 3, 9, 4, 9, 5, 9, 6])
    with pytest.raises(RngHardStopError, match="identical"):
        assert_coefficient_batch_healthy([5, 5, 5])
    assert is_rng_hard_stop_error(contiguous.value)
    assert is_rng_hard_stop_error(sparse.value)


def test_one_repeated_pair_still_creates_dual_mat_shares() -> None:
    script = PAIR + [(index * 17 + 3) % 2053 for index in range(1, 80)]
    source, _state = _scripted_source(script)
    configure_environment(random_source=source)
    artifacts = create_sharing_artifacts(ABANDON, 2, 3, mat_mode="dual")
    assert len(artifacts.shares) == 3
    assert [len(share.word_shares) for share in artifacts.shares] == [12, 12, 12]


def test_throwing_source_and_replaced_source_fail_closed() -> None:
    def throwing(length: int) -> bytes:
        if length == 2:
            return b"\x01\x02"
        raise RuntimeError("simulated CSPRNG fault")

    configure_environment(random_source=throwing)
    with pytest.raises(RngHardStopError):
        assert_csprng_healthy()
    with pytest.raises(RngHardStopError):
        split_bip39(ABANDON, 2, 3)

    configure_environment(random_source=lambda length: bytes(length))
    randomness_module._random_source = 123  # type: ignore[assignment]
    with pytest.raises(RngHardStopError):
        assert_csprng_healthy()


def test_rejection_cap_is_eight_and_the_eighth_draw_is_accepted() -> None:
    draws = {"count": 0}

    def always_reject(length: int) -> bytes:
        if length == 2:
            return b"\x01\x02"
        if length != 4:
            raise AssertionError(length)
        draws["count"] += 1
        return b"\xff\xff\xff\xff"

    configure_environment(random_source=always_reject)
    with pytest.raises(RngHardStopError, match="rejection sampling"):
        get_random_field_element()
    assert draws["count"] == 8

    draws["count"] = 0

    def eighth(length: int) -> bytes:
        if length == 2:
            return b"\x01\x02"
        if length != 4:
            raise AssertionError(length)
        draws["count"] += 1
        value = 0xFFFFFFFF if draws["count"] < 8 else 123
        return value.to_bytes(4, "big")

    configure_environment(random_source=eighth)
    assert get_random_field_element() == 123
    assert draws["count"] == 8


def test_third_field_draw_hard_stops_with_no_shares() -> None:
    source, state = _scripted_source(None, throw_on_field=3)
    configure_environment(random_source=source)
    with pytest.raises(RngHardStopError):
        split_bip39(ABANDON, 2, 3)
    assert state["field"] == 3


def test_rng_hard_stop_helper_rejects_forgeries() -> None:
    assert is_rng_hard_stop_error(Exception("Secure randomness failed: forged")) is False
    assert is_rng_hard_stop_error(object()) is False  # type: ignore[arg-type]
    assert is_rng_hard_stop_error(RngHardStopError("real")) is True


def test_pbkdf2_known_answer_mismatch_hard_stops_before_artifacts() -> None:
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def pbkdf2(_password: bytes, _salt: bytes, _iterations: int, dklen: int) -> bytes:
        return b"\x00" * dklen

    configure_environment(sha256=sha256, pbkdf2_hmac_sha512=pbkdf2)
    with pytest.raises(
        CryptoHardStopError,
        match="PBKDF2-HMAC-SHA512 known-answer test did not match",
    ):
        create_sharing_artifacts(ABANDON, 2, 3)
