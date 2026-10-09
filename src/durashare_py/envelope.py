"""Full and Compact hexadecimal envelopes, SB/SA payloads, and RBT.

Hashing goes through hashlib. A known-answer mismatch raises CryptoHardStopError
and callers must not keep a partial artifact.
"""

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass

from .checksums import (
    WORDS_PER_ROW,
    audit_optional_checksums,
    compute_column_checks,
    compute_global_integrity_check,
    compute_row_checks,
    compute_row_total,
)
from .errors import CryptoHardStopError
from .field import FIELD_PRIME, is_int, mod_add, normalize_share_value
from .security import clear_sensitive_array, constant_time_bytes_equal
from .types import Share

PROTOCOL_VERSION = 0x01
BIP39_ENGLISH_INPUT = 0x01
RBT_ITERATIONS = 16384
SUPPORTED_MAX_SHARE_NUMBER = 5
PROFILE_FULL = "full"
PROFILE_COMPACT = "compact"
WALLET_GENERIC_CUSTOM = 5
WORD_COUNT_CODES = {12: 0, 15: 1, 18: 2, 21: 3, 24: 4}
WORD_COUNTS = (12, 15, 18, 21, 24)
PREFIX_SHARE_FULL = b"SF"
PREFIX_SHARE_COMPACT = b"SC"
PREFIX_MANIFEST_HEADER = b"SB"
PREFIX_SHARE_AUDIT = b"SA"

_SHA256_ABC = bytes.fromhex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
_RBT_KAT_MATERIAL = bytes.fromhex("016905BF0D902A53A1177731441D42AA73407E")
_RBT_KAT_SALT = bytes.fromhex("A1B2C3D4E5F60708")
_RBT_KAT_PREFIX = bytes.fromhex("3DE50771B03A018838A0D18E")

Sha256Fn = Callable[[bytes], bytes]
Pbkdf2Fn = Callable[[bytes, bytes, int, int], bytes]

_sha256_fn: Sha256Fn | None = None
_pbkdf2_fn: Pbkdf2Fn | None = None
_crypto_health_ok = False


def configure_hash_backend(
    sha256: Sha256Fn | None = None,
    pbkdf2_hmac_sha512: Pbkdf2Fn | None = None,
    *,
    keep_sha256: bool = False,
    keep_pbkdf2: bool = False,
) -> None:
    """Replace hashlib for tests. None restores the default unless keep_* is set."""
    global _sha256_fn, _pbkdf2_fn, _crypto_health_ok
    if not keep_sha256:
        _sha256_fn = sha256
    if not keep_pbkdf2:
        _pbkdf2_fn = pbkdf2_hmac_sha512
    _crypto_health_ok = False


def _sha256(data: bytes) -> bytes:
    if _sha256_fn is not None:
        return _sha256_fn(data)
    return hashlib.sha256(data).digest()


def _pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if _pbkdf2_fn is not None:
        return _pbkdf2_fn(password, salt, iterations, dklen)
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=dklen)


def assert_webcrypto_healthy() -> None:
    """SHA-256 and PBKDF2-HMAC-SHA512 known-answer tests. Cached after success."""
    global _crypto_health_ok
    if _crypto_health_ok:
        return
    try:
        sha_actual = _sha256(b"abc")
        if not constant_time_bytes_equal(sha_actual, _SHA256_ABC):
            raise CryptoHardStopError("the SHA-256 known-answer test did not match.")
        rbt_actual = _pbkdf2(_RBT_KAT_MATERIAL, _RBT_KAT_SALT, RBT_ITERATIONS, 32)
        if not constant_time_bytes_equal(rbt_actual[:12], _RBT_KAT_PREFIX):
            raise CryptoHardStopError("the PBKDF2-HMAC-SHA512 known-answer test did not match.")
    except CryptoHardStopError:
        raise
    except Exception as error:
        raise CryptoHardStopError(f"known-answer tests failed ({error}).") from error
    _crypto_health_ok = True


def compute_sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("SHA-256 input must be bytes.")
    assert_webcrypto_healthy()
    try:
        return _sha256(bytes(data))
    except CryptoHardStopError:
        raise
    except Exception as error:
        raise CryptoHardStopError(f"SHA-256 failed ({error}).") from error


def derive_rbt(canonical_material: bytes, session_batch_id: bytes, output_length: int) -> bytes:
    if not isinstance(canonical_material, (bytes, bytearray)) or len(canonical_material) < 2:
        raise ValueError("RBT canonical material must be a non-empty byte string.")
    if not isinstance(session_batch_id, (bytes, bytearray)) or len(session_batch_id) not in (4, 8):
        raise ValueError("RBT Session Batch ID must be 4 or 8 bytes.")
    if output_length not in (6, 12, 32):
        raise ValueError("RBT output length must be 6, 12, or 32 bytes.")
    assert_webcrypto_healthy()
    derived: bytearray | None = None
    try:
        raw = _pbkdf2(bytes(canonical_material), bytes(session_batch_id), RBT_ITERATIONS, 32)
        derived = bytearray(raw)
        return bytes(derived[:output_length])
    except CryptoHardStopError:
        raise
    except Exception as error:
        raise CryptoHardStopError(f"RBT derivation failed ({error}).") from error
    finally:
        clear_sensitive_array(derived)


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bytes(hex_text: str, label: str = "Hex value") -> bytearray:
    if (
        not isinstance(hex_text, str)
        or len(hex_text) % 2 != 0
        or re.fullmatch(r"[0-9A-Fa-f]*", hex_text) is None
    ):
        raise ValueError(f"{label} must contain an even number of hexadecimal characters.")
    return bytearray.fromhex(hex_text)


def pack_field_elements_12(values: list[int]) -> bytearray:
    if len(values) == 0:
        raise ValueError("12-bit packing requires at least one field element.")
    output = bytearray((len(values) * 12 + 7) // 8)
    bit_offset = 0
    try:
        for value_index, value in enumerate(values):
            if not is_int(value) or value < 0 or value >= FIELD_PRIME:
                raise ValueError(
                    f"Field element {value_index + 1} must be an integer "
                    f"between 0 and {FIELD_PRIME - 1}."
                )
            for bit in range(11, -1, -1):
                byte_index = bit_offset // 8
                bit_in_byte = 7 - (bit_offset % 8)
                output[byte_index] |= ((value >> bit) & 1) << bit_in_byte
                bit_offset += 1
        return output
    except Exception:
        clear_sensitive_array(output)
        raise


def unpack_field_elements_12(data: bytes, element_count: int) -> list[int]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("12-bit unpacking requires bytes.")
    if not is_int(element_count) or element_count <= 0:
        raise ValueError("12-bit unpacking requires a positive element count.")
    expected_length = (element_count * 12 + 7) // 8
    if len(data) != expected_length:
        raise ValueError(
            f"Packed field data must be exactly {expected_length} bytes "
            f"for {element_count} elements."
        )
    values: list[int] = []
    bit_offset = 0
    try:
        for value_index in range(element_count):
            value = 0
            for _bit in range(12):
                byte_index = bit_offset // 8
                bit_in_byte = 7 - (bit_offset % 8)
                value = (value << 1) | ((data[byte_index] >> bit_in_byte) & 1)
                bit_offset += 1
            if value >= FIELD_PRIME:
                raise ValueError(f"Decoded field element {value_index + 1} is outside GF(2053).")
            values.append(value)
        while bit_offset < len(data) * 8:
            byte_index = bit_offset // 8
            bit_in_byte = 7 - (bit_offset % 8)
            if ((data[byte_index] >> bit_in_byte) & 1) != 0:
                raise ValueError("Packed field data has non-zero padding bits.")
            bit_offset += 1
        return values
    except Exception:
        clear_sensitive_array(values)
        raise


def get_word_count_code(word_count: int) -> int:
    if word_count not in WORD_COUNT_CODES:
        raise ValueError("Word count must be 12, 15, 18, 21, or 24.")
    return WORD_COUNT_CODES[word_count]


def normalize_wallet_profile_code(value: int | None) -> int:
    code = WALLET_GENERIC_CUSTOM if value is None else value
    if not is_int(code) or code < 0 or code > WALLET_GENERIC_CUSTOM:
        raise ValueError("Wallet profile code must be an integer between 0 and 5.")
    return code


def build_share_flags(word_count: int, wallet_profile_code: int | None) -> int:
    return get_word_count_code(word_count) | (
        normalize_wallet_profile_code(wallet_profile_code) << 3
    )


def build_manifest_flags(word_count: int, profile: str) -> int:
    if profile not in (PROFILE_FULL, PROFILE_COMPACT):
        raise ValueError("Manifest profile must be full or compact.")
    profile_code = 1 if profile == PROFILE_FULL else 0
    return get_word_count_code(word_count) | (profile_code << 5)


def _encode_full_path(value: int, label: str) -> bytes:
    if not is_int(value) or value < 1 or value > 255:
        raise ValueError(f"{label} must be an integer between 1 and 255.")
    return bytes((value, 0))


def _encode_compact_path(value: int, label: str) -> bytes:
    if not is_int(value) or value < 1 or value > 255:
        raise ValueError(f"{label} must be an integer between 1 and 255.")
    return bytes((value,))


def _require_bytes(data: bytes, expected_length: int, label: str) -> bytes:
    if not isinstance(data, (bytes, bytearray)) or len(data) != expected_length:
        raise ValueError(f"{label} must be exactly {expected_length} bytes.")
    return bytes(data)


def validate_payload_share(share: Share, word_count: int) -> None:
    if not is_int(share.share_number) or share.share_number < 1 or share.share_number > 256:
        raise ValueError("Payload Share number must be an integer between 1 and 256.")
    if len(share.word_shares) != word_count:
        raise ValueError(f"Payload Share must contain exactly {word_count} word values.")
    row_count = word_count // WORDS_PER_ROW
    if len(share.checksum_shares) != row_count:
        raise ValueError(f"Payload Share must contain exactly {row_count} row checksums.")
    if len(share.column_checksum_shares) != 3:
        raise ValueError("Payload Share must contain exactly three column checksums.")
    if share.global_integrity_check_share is None:
        raise ValueError("Payload Share printed GIC must be an integer inside GF(2053).")
    normalize_share_value(share.global_integrity_check_share, "Payload Share printed GIC")


def _full_share_values(share: Share) -> list[int]:
    gic = share.global_integrity_check_share
    if gic is None:
        raise ValueError("Payload Share printed GIC must be an integer inside GF(2053).")
    return [
        *share.word_shares,
        *share.checksum_shares,
        *share.column_checksum_shares,
        gic,
    ]


def build_canonical_secret_material(input_symbols: list[int]) -> bytes:
    packed = pack_field_elements_12(input_symbols)
    try:
        return bytes((BIP39_ENGLISH_INPUT,)) + bytes(packed)
    finally:
        clear_sensitive_array(packed)


def build_full_share_payload(
    share: Share,
    threshold: int,
    word_count: int,
    wallet_profile_code: int | None,
    session_batch_id: bytes,
    rbt: bytes,
) -> tuple[bytes, bytes]:
    """Return (payload, transport_hash). Transport hash failure is a hard stop upstream."""
    validate_payload_share(share, word_count)
    share_data = pack_field_elements_12(_full_share_values(share))
    try:
        body = b"".join(
            (
                PREFIX_SHARE_FULL,
                bytes(
                    (
                        PROTOCOL_VERSION,
                        build_share_flags(word_count, wallet_profile_code),
                        BIP39_ENGLISH_INPUT,
                    )
                ),
                _encode_full_path(threshold, "Threshold"),
                _encode_full_path(share.share_number, "Share number"),
                _require_bytes(session_batch_id, 8, "Full Session Batch ID"),
                _require_bytes(rbt, 12, "Full RBT"),
                bytes(share_data),
            )
        )
    finally:
        clear_sensitive_array(share_data)
    digest = compute_sha256(body)
    transport_hash = digest[:16]
    return body + transport_hash, transport_hash


def build_compact_share_payload(
    share: Share,
    threshold: int,
    word_count: int,
    wallet_profile_code: int | None,
    session_batch_id: bytes,
    rbt: bytes,
) -> bytes:
    validate_payload_share(share, word_count)
    share_data = pack_field_elements_12(share.word_shares)
    try:
        return b"".join(
            (
                PREFIX_SHARE_COMPACT,
                bytes(
                    (
                        PROTOCOL_VERSION,
                        build_share_flags(word_count, wallet_profile_code),
                        BIP39_ENGLISH_INPUT,
                    )
                ),
                _encode_compact_path(threshold, "Threshold"),
                _encode_compact_path(share.share_number, "Share number"),
                _require_bytes(session_batch_id, 4, "Compact Session Batch ID"),
                _require_bytes(rbt, 6, "Compact RBT"),
                bytes(share_data),
            )
        )
    finally:
        clear_sensitive_array(share_data)


def build_manifest_header_payload(
    profile: str,
    word_count: int,
    session_batch_id: bytes,
    rbt: bytes,
) -> bytes:
    batch_length = 8 if profile == PROFILE_FULL else 4
    rbt_length = 12 if profile == PROFILE_FULL else 6
    return b"".join(
        (
            PREFIX_MANIFEST_HEADER,
            bytes((PROTOCOL_VERSION, build_manifest_flags(word_count, profile))),
            _require_bytes(session_batch_id, batch_length, f"{profile} Session Batch ID"),
            _require_bytes(rbt, rbt_length, f"{profile} RBT"),
        )
    )


def build_share_audit_payload(
    profile: str,
    word_count: int,
    threshold: int,
    share_number: int,
    audit_hash: bytes,
) -> bytes:
    if not isinstance(audit_hash, (bytes, bytearray)) or len(audit_hash) != 32:
        raise ValueError("Share Audit Hash must be exactly 32 bytes.")
    if profile not in (PROFILE_FULL, PROFILE_COMPACT):
        raise ValueError("Share Audit profile must be full or compact.")
    is_full = profile == PROFILE_FULL
    threshold_path = (
        _encode_full_path(threshold, "Threshold")
        if is_full
        else _encode_compact_path(threshold, "Threshold")
    )
    share_path = (
        _encode_full_path(share_number, "Share number")
        if is_full
        else _encode_compact_path(share_number, "Share number")
    )
    committed = bytes(audit_hash) if is_full else bytes(audit_hash[:16])
    return b"".join(
        (
            PREFIX_SHARE_AUDIT,
            bytes((PROTOCOL_VERSION, build_manifest_flags(word_count, profile))),
            threshold_path,
            share_path,
            committed,
        )
    )


def _decode_share_flags(flags: int) -> tuple[int, int]:
    if not is_int(flags) or flags < 0 or flags > 0xFF:
        raise ValueError("Payload flags byte is invalid.")
    word_count_code = flags & 0x07
    if word_count_code >= len(WORD_COUNTS):
        raise ValueError("Payload word-count flag is reserved.")
    wallet_profile_code = (flags >> 3) & 0x07
    if wallet_profile_code > WALLET_GENERIC_CUSTOM:
        raise ValueError("Payload wallet/profile flag is reserved.")
    if (flags & 0xC0) != 0:
        raise ValueError("Nested payloads are not supported by this HTML version.")
    return WORD_COUNTS[word_count_code], wallet_profile_code


def _decode_manifest_flags(flags: int) -> tuple[int, str]:
    if not is_int(flags) or flags < 0 or flags > 0xFF:
        raise ValueError("Manifest flags byte is invalid.")
    word_count_code = flags & 0x07
    if word_count_code >= len(WORD_COUNTS):
        raise ValueError("Manifest word-count flag is reserved.")
    if (flags & 0x18) != 0:
        raise ValueError("Nested Manifest payloads are not supported.")
    profile_code = (flags >> 5) & 0x03
    if profile_code > 1 or (flags & 0x80) != 0:
        raise ValueError("Manifest profile/reserved flags are invalid.")
    profile = PROFILE_FULL if profile_code == 1 else PROFILE_COMPACT
    return WORD_COUNTS[word_count_code], profile


@dataclass
class DecodedSharePayload:
    profile: str
    payload_hex: str
    protocol_version: int
    word_count: int
    wallet_profile_code: int
    language_input: int
    threshold: int
    share_number: int
    session_batch_id_hex: str
    rbt_hex: str
    audit_hash_hex: str
    transport_hash_hex: str
    word_shares: list[int]
    checksum_shares: list[int]
    column_checksum_shares: list[int]
    global_integrity_check_share: int
    checks_derived: bool


def decode_share_payload_hex(raw_payload: str) -> DecodedSharePayload:
    """Decode a Full or Compact share payload.

    A Transport Hash mismatch raises and does not return a partial share.
    """
    if not isinstance(raw_payload, str):
        raise ValueError("Share payload must be hexadecimal text.")
    normalized_hex = re.sub(r"\s+", "", raw_payload).upper()
    if normalized_hex == "":
        raise ValueError("Share payload is empty.")
    payload = hex_to_bytes(normalized_hex, "Share payload")
    try:
        if len(payload) < 17 or payload[0] != 0x53:
            raise ValueError("Share payload prefix is missing or invalid.")
        if payload[1] == 0x46:
            profile = PROFILE_FULL
        elif payload[1] == 0x43:
            profile = PROFILE_COMPACT
        else:
            raise ValueError("Only SF (Full) and SC (Compact) Share payloads are accepted.")
        if payload[2] != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported Share payload version 0x{payload[2]:02X}.")
        word_count, wallet_profile_code = _decode_share_flags(payload[3])
        if payload[4] != BIP39_ENGLISH_INPUT:
            raise ValueError("Only BIP39 English Share payloads are supported.")
        is_full = profile == PROFILE_FULL
        threshold = payload[5]
        share_number = payload[7] if is_full else payload[6]
        if threshold not in (2, 3):
            raise ValueError("Payload threshold must be 2 or 3 for this HTML version.")
        if (
            not is_int(share_number)
            or share_number < 1
            or share_number > SUPPORTED_MAX_SHARE_NUMBER
        ):
            raise ValueError(
                f"Payload Share number must be between 1 and {SUPPORTED_MAX_SHARE_NUMBER}."
            )
        if is_full and (payload[6] != 0 or payload[8] != 0):
            raise ValueError("Full payload flat-path reserved bytes must be zero.")

        row_count = word_count // WORDS_PER_ROW
        element_count = word_count + row_count + 4 if is_full else word_count
        share_data_length = (element_count * 12 + 7) // 8
        expected_length = 29 + share_data_length + 16 if is_full else 17 + share_data_length
        if len(payload) != expected_length:
            kind = "Full" if is_full else "Compact"
            raise ValueError(
                f"{kind} payload must be exactly {expected_length} bytes for {word_count} words."
            )

        batch_start = 9 if is_full else 7
        batch_end = batch_start + (8 if is_full else 4)
        rbt_end = batch_end + (12 if is_full else 6)
        share_data_end = rbt_end + share_data_length
        decoded_values = unpack_field_elements_12(payload[rbt_end:share_data_end], element_count)
        transport_hash_hex = ""
        if is_full:
            body = bytes(payload[: len(payload) - 16])
            supplied = bytes(payload[len(payload) - 16 :])
            digest = compute_sha256(body)
            if not constant_time_bytes_equal(digest[:16], supplied):
                raise ValueError("Full payload Transport Hash mismatch.")
            transport_hash_hex = bytes_to_hex(supplied)
        audit_digest = compute_sha256(bytes(payload))
        word_shares = decoded_values[:word_count]
        if is_full:
            row_end = word_count + row_count
            checksum_shares = decoded_values[word_count:row_end]
            column_checksum_shares = decoded_values[row_end : row_end + 3]
            global_integrity_check_share = decoded_values[row_end + 3]
            audit = audit_optional_checksums(
                share_number,
                word_shares,
                checksum_shares,
                column_checksum_shares,
                global_integrity_check_share,
                row_count,
                compute_row_total(row_count),
            )
            if audit["row_fails"] or audit["col_fails"] or audit["gic_fail"]:
                raise ValueError("Full payload arithmetic fields are internally inconsistent.")
            checks_derived = False
        else:
            checksum_shares = compute_row_checks(word_shares)
            column_checksum_shares = compute_column_checks(word_shares)
            global_integrity_check_share = mod_add(
                compute_global_integrity_check(word_shares),
                share_number,
            )
            checks_derived = True
        return DecodedSharePayload(
            profile=profile,
            payload_hex=normalized_hex,
            protocol_version=payload[2],
            word_count=word_count,
            wallet_profile_code=wallet_profile_code,
            language_input=payload[4],
            threshold=threshold,
            share_number=share_number,
            session_batch_id_hex=bytes_to_hex(bytes(payload[batch_start:batch_end])),
            rbt_hex=bytes_to_hex(bytes(payload[batch_end:rbt_end])),
            audit_hash_hex=bytes_to_hex(audit_digest),
            transport_hash_hex=transport_hash_hex,
            word_shares=word_shares,
            checksum_shares=checksum_shares,
            column_checksum_shares=column_checksum_shares,
            global_integrity_check_share=global_integrity_check_share,
            checks_derived=checks_derived,
        )
    finally:
        clear_sensitive_array(payload)


@dataclass
class DecodedManifestHeader:
    profile: str
    payload_hex: str
    protocol_version: int
    word_count: int
    session_batch_id_hex: str
    rbt_hex: str


def decode_manifest_header_payload_hex(raw_payload: str) -> DecodedManifestHeader:
    if not isinstance(raw_payload, str):
        raise ValueError("Manifest Header payload must be hexadecimal text.")
    normalized_hex = re.sub(r"\s+", "", raw_payload).upper()
    payload = hex_to_bytes(normalized_hex, "Manifest Header payload")
    try:
        if len(payload) < 4 or payload[0] != 0x53 or payload[1] != 0x42:
            raise ValueError("Manifest Header payload must use the SB prefix (5342).")
        if payload[2] != PROTOCOL_VERSION:
            raise ValueError("Unsupported Manifest Header payload version.")
        word_count, profile = _decode_manifest_flags(payload[3])
        expected_length = 24 if profile == PROFILE_FULL else 14
        if len(payload) != expected_length:
            kind = "Full" if profile == PROFILE_FULL else "Compact"
            raise ValueError(f"{kind} SB payload must be exactly {expected_length} bytes.")
        batch_end = 12 if profile == PROFILE_FULL else 8
        return DecodedManifestHeader(
            profile=profile,
            payload_hex=normalized_hex,
            protocol_version=payload[2],
            word_count=word_count,
            session_batch_id_hex=bytes_to_hex(bytes(payload[4:batch_end])),
            rbt_hex=bytes_to_hex(bytes(payload[batch_end:])),
        )
    finally:
        clear_sensitive_array(payload)


@dataclass
class DecodedAuditEvidence:
    kind: str
    audit_hash_hex: str = ""
    committed_hash_hex: str = ""
    committed_hash_bytes: int = 0
    profile: str = ""
    payload_hex: str = ""
    protocol_version: int = 0
    word_count: int = 0
    threshold: int = 0
    share_number: int = 0


def decode_manifest_audit_evidence_hex(raw_evidence: str) -> DecodedAuditEvidence:
    if not isinstance(raw_evidence, str):
        raise ValueError("Manifest Audit evidence must be hexadecimal text.")
    normalized_hex = re.sub(r"\s+", "", raw_evidence).upper()
    if normalized_hex == "":
        raise ValueError("Manifest Audit evidence is empty.")
    if len(normalized_hex) == 64 and re.fullmatch(r"[0-9A-F]{64}", normalized_hex):
        return DecodedAuditEvidence(
            kind="hash",
            audit_hash_hex=normalized_hex,
            committed_hash_hex=normalized_hex,
            committed_hash_bytes=32,
        )
    payload = hex_to_bytes(normalized_hex, "Share Audit payload")
    try:
        if len(payload) < 6 or payload[0] != 0x53 or payload[1] != 0x41:
            raise ValueError("Audit evidence must be a 32-byte Audit Hash or an SA payload (5341).")
        if payload[2] != PROTOCOL_VERSION:
            raise ValueError("Unsupported Share Audit payload version.")
        word_count, profile = _decode_manifest_flags(payload[3])
        is_full = profile == PROFILE_FULL
        expected_length = 40 if is_full else 22
        if len(payload) != expected_length:
            kind = "Full" if is_full else "Compact"
            raise ValueError(f"{kind} SA payload must be exactly {expected_length} bytes.")
        threshold = payload[4]
        share_number = payload[6] if is_full else payload[5]
        if threshold not in (2, 3):
            raise ValueError("SA payload threshold must be 2 or 3.")
        if share_number < 1 or share_number > SUPPORTED_MAX_SHARE_NUMBER:
            raise ValueError(
                f"SA payload Share number must be between 1 and {SUPPORTED_MAX_SHARE_NUMBER}."
            )
        if is_full and (payload[5] != 0 or payload[7] != 0):
            raise ValueError("Full SA flat-path reserved bytes must be zero.")
        hash_start = 8 if is_full else 6
        return DecodedAuditEvidence(
            kind="sa",
            committed_hash_hex=bytes_to_hex(bytes(payload[hash_start:])),
            committed_hash_bytes=32 if is_full else 16,
            profile=profile,
            payload_hex=normalized_hex,
            protocol_version=payload[2],
            word_count=word_count,
            threshold=threshold,
            share_number=share_number,
        )
    finally:
        clear_sensitive_array(payload)


def session_header_agrees(header: DecodedManifestHeader, payload: DecodedSharePayload) -> bool:
    """Match an SB header to a share payload the way the HTML tool does.

    The same profile compares the session id and the RBT. Mixed profiles compare
    the session family: the Full id must start with the Compact id.
    """
    if header.word_count != payload.word_count:
        return False
    header_batch = header.session_batch_id_hex.upper()
    payload_batch = payload.session_batch_id_hex.upper()
    if header.profile == payload.profile:
        return header_batch == payload_batch and header.rbt_hex.upper() == payload.rbt_hex.upper()
    if header.profile not in (PROFILE_FULL, PROFILE_COMPACT):
        return False
    if payload.profile not in (PROFILE_FULL, PROFILE_COMPACT):
        return False
    full_id = header_batch if header.profile == PROFILE_FULL else payload_batch
    compact_id = header_batch if header.profile == PROFILE_COMPACT else payload_batch
    return full_id.startswith(compact_id)


def audit_evidence_agrees(evidence: DecodedAuditEvidence, payload: DecodedSharePayload) -> bool:
    """A raw Audit Hash matches the payload hash. An SA payload must also match its metadata."""
    expected = payload.audit_hash_hex.upper()
    committed = evidence.committed_hash_hex.upper()
    width = evidence.committed_hash_bytes * 2
    if width <= 0 or len(committed) != width or len(expected) < width:
        return False
    try:
        hashes_match = constant_time_bytes_equal(
            bytes.fromhex(expected[:width]),
            bytes.fromhex(committed),
        )
    except ValueError:
        return False
    if not hashes_match:
        return False
    if evidence.kind == "hash":
        return True
    return (
        evidence.profile == payload.profile
        and evidence.word_count == payload.word_count
        and evidence.threshold == payload.threshold
        and evidence.share_number == payload.share_number
    )


@dataclass
class RecoveryPayloadSet:
    has_payloads: bool
    word_count: int | None = None
    threshold: int | None = None
    language_input: int | None = None
    wallet_profile_code: int | None = None
    full_batch_id_hex: str | None = None
    compact_batch_id_hex: str | None = None
    full_rbt_hex: str | None = None
    compact_rbt_hex: str | None = None


def validate_recovery_payload_set(
    payload_metadata: list[DecodedSharePayload | None],
    shares: list[Share] | None = None,
    expected_word_count: int | None = None,
) -> RecoveryPayloadSet:
    if not isinstance(payload_metadata, list):
        raise ValueError("Recovery payload metadata must be an array.")
    entries: list[DecodedSharePayload] = []
    for index, metadata in enumerate(payload_metadata):
        if metadata is None:
            continue
        if (
            metadata.profile not in (PROFILE_FULL, PROFILE_COMPACT)
            or metadata.word_count not in WORD_COUNTS
            or metadata.threshold not in (2, 3)
            or not is_int(metadata.share_number)
        ):
            raise ValueError(f"Share Input #{index + 1} has invalid payload metadata.")
        if (
            shares is not None
            and index < len(shares)
            and shares[index] is not None
            and shares[index].share_number != metadata.share_number
        ):
            raise ValueError(
                f"Share Input #{index + 1} was edited after payload import; "
                "its Share Number no longer matches the payload."
            )
        entries.append(metadata)
    if len(entries) == 0:
        return RecoveryPayloadSet(has_payloads=False)
    reference = entries[0]
    if expected_word_count is not None and reference.word_count != expected_word_count:
        raise ValueError("Payload word count does not match the Recovery form.")
    seen: set[int] = set()
    full_batch: str | None = None
    compact_batch: str | None = None
    full_rbt: str | None = None
    compact_rbt: str | None = None
    for entry in entries:
        if (
            entry.word_count != reference.word_count
            or entry.threshold != reference.threshold
            or entry.language_input != reference.language_input
            or entry.wallet_profile_code != reference.wallet_profile_code
        ):
            raise ValueError("Recovery payloads do not describe the same backup settings.")
        if entry.share_number in seen:
            raise ValueError("Recovery payloads contain duplicate Share Numbers.")
        seen.add(entry.share_number)
        if entry.profile == PROFILE_FULL:
            if full_batch is not None and full_batch != entry.session_batch_id_hex:
                raise ValueError("Full payload Session Batch IDs do not match.")
            if full_rbt is not None and full_rbt != entry.rbt_hex:
                raise ValueError("Full payload RBT values do not match.")
            full_batch = entry.session_batch_id_hex
            full_rbt = entry.rbt_hex
        else:
            if compact_batch is not None and compact_batch != entry.session_batch_id_hex:
                raise ValueError("Compact payload Session Batch IDs do not match.")
            if compact_rbt is not None and compact_rbt != entry.rbt_hex:
                raise ValueError("Compact payload RBT values do not match.")
            compact_batch = entry.session_batch_id_hex
            compact_rbt = entry.rbt_hex
    if full_batch and compact_batch and not full_batch.startswith(compact_batch):
        raise ValueError("Full and Compact payloads are not from the same session family.")
    return RecoveryPayloadSet(
        has_payloads=True,
        word_count=reference.word_count,
        threshold=reference.threshold,
        language_input=reference.language_input,
        wallet_profile_code=reference.wallet_profile_code,
        full_batch_id_hex=full_batch,
        compact_batch_id_hex=compact_batch,
        full_rbt_hex=full_rbt,
        compact_rbt_hex=compact_rbt,
    )
