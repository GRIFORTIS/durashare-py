"""CSPRNG access for ceremonies.

The only default source is secrets.token_bytes. A test double is explicit and
still has to pass the smoke test, the rejection cap, and the coefficient canary.
There is no non-crypto fallback and no silent redraw.
"""

import secrets
from collections.abc import Callable

from .errors import RngHardStopError
from .field import FIELD_PRIME, is_int
from .security import clear_sensitive_array

CSPRNG_SMOKE_BYTES = 256
CSPRNG_SENTINEL_BYTE = 0xA5
MAX_REJECTION_ATTEMPTS = 8
COEFF_BATCH_MAX_FREQUENCY = 6
_UINT32_BOUND = 0x100000000

RandomSource = Callable[[int], bytes]

_random_source: RandomSource | None = None


def configure_random_source(source: RandomSource | None) -> None:
    """Install a byte source, or restore secrets.token_bytes when source is None."""
    global _random_source
    if source is None:
        _random_source = None
        return
    if not callable(source):
        raise ValueError("random source must be callable")
    probe = source(2)
    if not isinstance(probe, (bytes, bytearray)) or len(probe) != 2:
        raise ValueError("random source must return exactly the requested bytes")
    _random_source = source


def _source() -> RandomSource:
    return _random_source if _random_source is not None else secrets.token_bytes


def fill_random(buffer: bytearray) -> None:
    """Sole write into the CSPRNG. A short or throwing source becomes a hard stop."""
    try:
        drawn = _source()(len(buffer))
    except RngHardStopError:
        raise
    except Exception as error:
        raise RngHardStopError(f"getRandomValues failed ({error}).") from error
    if not isinstance(drawn, (bytes, bytearray)) or len(drawn) != len(buffer):
        raise RngHardStopError(
            "getRandomValues failed (source returned the wrong number of bytes)."
        )
    buffer[:] = drawn


def _is_constant_filled(buffer: bytes | bytearray) -> bool:
    if len(buffer) == 0:
        return True
    first = buffer[0]
    return all(byte == first for byte in buffer)


def assert_csprng_healthy() -> None:
    """Fail closed before any coefficient draw.

    Catches a missing or no-op source, a constant burst, and two identical
    bursts. It does not prove the platform CSPRNG is strong.
    """
    burst1 = bytearray([CSPRNG_SENTINEL_BYTE]) * CSPRNG_SMOKE_BYTES
    burst2 = bytearray([CSPRNG_SENTINEL_BYTE]) * CSPRNG_SMOKE_BYTES
    try:
        fill_random(burst1)
        if _is_constant_filled(burst1) and burst1[0] == CSPRNG_SENTINEL_BYTE:
            raise RngHardStopError("getRandomValues did not overwrite the sentinel buffer.")
        if _is_constant_filled(burst1):
            raise RngHardStopError("getRandomValues returned a constant-filled byte burst.")
        fill_random(burst2)
        if _is_constant_filled(burst2) and burst2[0] == CSPRNG_SENTINEL_BYTE:
            raise RngHardStopError("getRandomValues did not overwrite the second sentinel buffer.")
        if _is_constant_filled(burst2):
            raise RngHardStopError("getRandomValues returned a second constant-filled byte burst.")
        if burst1 == burst2:
            raise RngHardStopError("two consecutive getRandomValues bursts were identical.")
    finally:
        clear_sensitive_array(burst1)
        clear_sensitive_array(burst2)


def assert_coefficient_batch_healthy(values: list[int]) -> None:
    """Ceremony canary. Does not redraw."""
    if len(values) == 0:
        raise RngHardStopError("coefficient batch is empty.")
    counts: dict[int, int] = {}
    max_frequency = 0
    for value in values:
        next_count = counts.get(value, 0) + 1
        counts[value] = next_count
        if next_count > max_frequency:
            max_frequency = next_count
    if len(values) >= 2 and max_frequency == len(values):
        raise RngHardStopError("all drawn coefficients were identical.")
    if max_frequency >= COEFF_BATCH_MAX_FREQUENCY:
        raise RngHardStopError(
            f"a coefficient value repeated {max_frequency} times "
            f"(limit {COEFF_BATCH_MAX_FREQUENCY - 1})."
        )


def get_random_int_inclusive(max_value: int) -> int:
    """Uniform integer in [0, max_value] from 32-bit rejection sampling."""
    if not is_int(max_value) or max_value < 0 or max_value > 0xFFFFFFFF:
        raise ValueError("max must be at most 2^32 - 1.")
    span = max_value + 1
    if span <= 0:
        raise ValueError("Invalid range for randomness.")
    limit = _UINT32_BOUND - (_UINT32_BOUND % span)
    buffer = bytearray(4)
    try:
        for _attempt in range(MAX_REJECTION_ATTEMPTS):
            fill_random(buffer)
            value = int.from_bytes(buffer, byteorder="big")
            if value < limit:
                return value % span
        raise RngHardStopError(
            f"rejection sampling failed after {MAX_REJECTION_ATTEMPTS} attempts."
        )
    finally:
        clear_sensitive_array(buffer)


def get_random_field_element() -> int:
    """Draw one uniform element of GF(2053)."""
    return get_random_int_inclusive(FIELD_PRIME - 1)


def get_random_bytes(length: int) -> bytes:
    if not is_int(length) or length <= 0 or length > 65536:
        raise ValueError("Random byte length must be an integer between 1 and 65536.")
    buffer = bytearray(length)
    try:
        fill_random(buffer)
        return bytes(buffer)
    except Exception:
        clear_sensitive_array(buffer)
        raise
    finally:
        clear_sensitive_array(buffer)
