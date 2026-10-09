"""DuraShare Python library.

Implementation v0.6.0 matches the HTML tool's arithmetic, MAT, hexadecimal
envelopes, and one-share Audit against frozen protocol v0.7.0 vectors.
"""

from .audit import audit_share
from .checksums import (
    COLUMN_TAGS,
    COLUMN_TOTAL,
    WORDS_PER_ROW,
    audit_optional_checksums,
    compute_column_check_polynomials,
    compute_column_checks,
    compute_global_integrity_check,
    compute_global_integrity_check_polynomial,
    compute_row_check_polynomials,
    compute_row_checks,
    compute_row_total,
    sum_polynomials,
)
from .envelope import (
    assert_webcrypto_healthy,
    build_compact_share_payload,
    build_full_share_payload,
    build_manifest_header_payload,
    build_share_audit_payload,
    bytes_to_hex,
    compute_sha256,
    configure_hash_backend,
    decode_manifest_audit_evidence_hex,
    decode_manifest_header_payload_hex,
    decode_share_payload_hex,
    derive_rbt,
    hex_to_bytes,
    pack_field_elements_12,
    unpack_field_elements_12,
    validate_recovery_payload_set,
)
from .errors import (
    CryptoHardStopError,
    RngHardStopError,
    is_crypto_hard_stop_error,
    is_rng_hard_stop_error,
)
from .field import (
    FIELD_PRIME,
    GF2053,
    mod,
    mod_add,
    mod_div,
    mod_inv,
    mod_mul,
    mod_pow,
    mod_sub,
    normalize_share_value,
)
from .lagrange import compute_lagrange_multipliers, lagrange_interpolate_at_zero
from .mat import (
    audit_mat_column,
    compute_mat_tag,
    compute_mat_tags,
    recombine_mat_key_sets,
    split_mat_key_set,
)
from .polynomial import evaluate_polynomial
from .randomness import (
    assert_coefficient_batch_healthy,
    assert_csprng_healthy,
    configure_random_source,
    get_random_field_element,
)
from .recover import recover_and_validate, recover_mnemonic
from .security import (
    clear_sensitive_array,
    constant_time_bytes_equal,
    constant_time_equal,
    constant_time_string_equal,
    secure_wipe_list,
    secure_wipe_number,
)
from .seed import (
    generate_valid_mnemonic,
    indices_to_mnemonic,
    mnemonic_to_indices,
    parse_input,
    parse_share_value,
    validate_bip39_mnemonic,
)
from .split import (
    clear_sharing_artifacts,
    create_sharing_artifacts,
    generate_mat_artifacts,
    split_bip39,
    verify_mat_bindings,
)
from .types import RecoveryReport, Share

__version__ = "0.6.0"
__author__ = "GRIFORTIS"
__license__ = "MIT"


_UNSET = object()


def configure_environment(
    *,
    random_source: object = _UNSET,
    sha256: object = _UNSET,
    pbkdf2_hmac_sha512: object = _UNSET,
) -> None:
    """Install test doubles. ``None`` restores that provider's default.

    Omitted arguments are left unchanged. Smoke and known-answer checks still apply.
    """
    if random_source is not _UNSET:
        if random_source is not None and not callable(random_source):
            raise ValueError("random source must be callable")
        configure_random_source(random_source if callable(random_source) else None)
    if sha256 is not _UNSET or pbkdf2_hmac_sha512 is not _UNSET:
        sha_fn = sha256 if callable(sha256) else None
        kdf_fn = pbkdf2_hmac_sha512 if callable(pbkdf2_hmac_sha512) else None
        configure_hash_backend(
            sha_fn,
            kdf_fn,
            keep_sha256=sha256 is _UNSET,
            keep_pbkdf2=pbkdf2_hmac_sha512 is _UNSET,
        )


__all__ = [
    "COLUMN_TAGS",
    "COLUMN_TOTAL",
    "CryptoHardStopError",
    "FIELD_PRIME",
    "GF2053",
    "RecoveryReport",
    "RngHardStopError",
    "Share",
    "WORDS_PER_ROW",
    "__author__",
    "__license__",
    "__version__",
    "assert_coefficient_batch_healthy",
    "assert_csprng_healthy",
    "assert_webcrypto_healthy",
    "audit_mat_column",
    "audit_optional_checksums",
    "audit_share",
    "build_compact_share_payload",
    "build_full_share_payload",
    "build_manifest_header_payload",
    "build_share_audit_payload",
    "bytes_to_hex",
    "clear_sensitive_array",
    "clear_sharing_artifacts",
    "compute_column_check_polynomials",
    "compute_column_checks",
    "compute_global_integrity_check",
    "compute_global_integrity_check_polynomial",
    "compute_lagrange_multipliers",
    "compute_mat_tag",
    "compute_mat_tags",
    "compute_row_check_polynomials",
    "compute_row_checks",
    "compute_row_total",
    "compute_sha256",
    "configure_environment",
    "configure_random_source",
    "constant_time_bytes_equal",
    "constant_time_equal",
    "constant_time_string_equal",
    "create_sharing_artifacts",
    "decode_manifest_audit_evidence_hex",
    "decode_manifest_header_payload_hex",
    "decode_share_payload_hex",
    "derive_rbt",
    "evaluate_polynomial",
    "generate_mat_artifacts",
    "generate_valid_mnemonic",
    "get_random_field_element",
    "hex_to_bytes",
    "indices_to_mnemonic",
    "is_crypto_hard_stop_error",
    "is_rng_hard_stop_error",
    "lagrange_interpolate_at_zero",
    "mnemonic_to_indices",
    "mod",
    "mod_add",
    "mod_div",
    "mod_inv",
    "mod_mul",
    "mod_pow",
    "mod_sub",
    "normalize_share_value",
    "pack_field_elements_12",
    "parse_input",
    "parse_share_value",
    "recombine_mat_key_sets",
    "recover_and_validate",
    "recover_mnemonic",
    "secure_wipe_list",
    "secure_wipe_number",
    "split_bip39",
    "split_mat_key_set",
    "sum_polynomials",
    "unpack_field_elements_12",
    "validate_bip39_mnemonic",
    "validate_recovery_payload_set",
    "verify_mat_bindings",
]
