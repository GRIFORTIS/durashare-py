"""Typed hard-stops for ceremony randomness and hash failures.

Callers must branch on the exception type. Message text is guidance for a
human operator, not a stable match key.
"""

RNG_HARD_STOP_GUIDANCE = (
    "Stop this ceremony. Do not trust any output from this run. "
    "Use another clean environment (for example a fresh Tails session). "
    "This check refuses dead or stuck RNGs; it cannot prove the platform CSPRNG is strong."
)

CRYPTO_HARD_STOP_GUIDANCE = (
    "Stop this ceremony. No Shares or digital envelopes were produced. "
    "Use the default Standard security level in a current vanilla Tails/Tor Browser session."
)


class RngHardStopError(Exception):
    """CSPRNG smoke, rejection cap, or coefficient-canary failure."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Secure randomness failed: {detail} {RNG_HARD_STOP_GUIDANCE}")
        self.detail = detail


class CryptoHardStopError(Exception):
    """SHA-256 or PBKDF2 known-answer or runtime failure."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Cryptographic runtime failed: {detail} {CRYPTO_HARD_STOP_GUIDANCE}")
        self.detail = detail


def is_rng_hard_stop_error(error: BaseException) -> bool:
    return isinstance(error, RngHardStopError)


def is_crypto_hard_stop_error(error: BaseException) -> bool:
    return isinstance(error, CryptoHardStopError)
