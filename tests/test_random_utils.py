import pytest

from durashare_py import FIELD_PRIME, configure_random_source, get_random_field_element
from durashare_py.errors import RngHardStopError


def test_configure_random_source_rejects_bad_provider() -> None:
    with pytest.raises(ValueError):
        configure_random_source(lambda n: "not-bytes")  # type: ignore[arg-type, return-value]


def test_rejection_sampling_retries_then_accepts() -> None:
    draws: list[bytes] = []

    def fake_random(byte_count: int) -> bytes:
        if byte_count != 4:
            return bytes(byte_count)
        if not draws:
            drawn = (0xFFFFFFFF).to_bytes(4, "big")
        else:
            drawn = (1).to_bytes(4, "big")
        draws.append(drawn)
        return drawn

    configure_random_source(fake_random)
    value = get_random_field_element()
    assert len(draws) >= 2
    assert 0 <= value < FIELD_PRIME


def test_eight_rejections_hard_stop() -> None:
    configure_random_source(lambda byte_count: b"\xff" * byte_count)
    with pytest.raises(RngHardStopError):
        get_random_field_element()
