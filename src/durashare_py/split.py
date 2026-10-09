"""Share generation.

A ceremony either returns a complete artifact or raises. Randomness, canary,
dual-path, and hash failures clear scratch and do not return shares.
"""

from .checksums import (
    COLUMN_TAGS,
    COLUMN_TOTAL,
    WORDS_PER_ROW,
    compute_column_check_polynomials,
    compute_global_integrity_check_polynomial,
    compute_row_check_polynomials,
    compute_row_total,
)
from .envelope import (
    PROFILE_COMPACT,
    PROFILE_FULL,
    build_canonical_secret_material,
    build_compact_share_payload,
    build_full_share_payload,
    build_manifest_header_payload,
    build_share_audit_payload,
    compute_sha256,
    derive_rbt,
    normalize_wallet_profile_code,
)
from .field import FIELD_PRIME, is_int, mod_add, normalize_share_value
from .mat import (
    compute_mat_tags,
    generate_mat_key_set,
    mat_column_count,
    normalize_mat_custody,
    normalize_mat_mode,
    recombine_mat_key_sets,
    split_mat_key_set,
)
from .polynomial import evaluate_polynomial, random_polynomial
from .randomness import assert_coefficient_batch_healthy, assert_csprng_healthy, get_random_bytes
from .security import clear_sensitive_array, constant_time_equal
from .seed import sanitize_mnemonic, validate_bip39_mnemonic
from .types import (
    DigitalProfile,
    DigitalSession,
    Manifest,
    MatColumn,
    MatShareKeys,
    SessionProfile,
    Share,
    ShareDigital,
    SharingArtifacts,
)


def _ensure_word_count(word_count: int) -> None:
    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError("This tool currently supports only 12, 15, 18, 21, or 24-word mnemonics.")


def _default_wordlist() -> list[str]:
    from mnemonic import Mnemonic

    return Mnemonic("english").wordlist


def split_bip39(
    mnemonic: str,
    k: int,
    n: int,
    wordlist: list[str] | None = None,
    *,
    include_input_symbols: bool = False,
) -> list[Share] | tuple[list[Share], list[int]]:
    """Split a BIP39 mnemonic into n shares with threshold k."""
    if not is_int(k) or not is_int(n):
        raise ValueError("Threshold (k) and total shares (n) must be integers.")
    if k < 2:
        raise ValueError("Threshold k must be at least 2.")
    if k > n:
        raise ValueError("Threshold k cannot exceed n.")
    if n >= FIELD_PRIME:
        raise ValueError("Total shares (n) must be less than 2053.")

    normalized = sanitize_mnemonic(mnemonic)
    if wordlist is None:
        wordlist = _default_wordlist()
    if not validate_bip39_mnemonic(normalized, wordlist):
        raise ValueError("Invalid BIP39 mnemonic: checksum verification failed.")

    words = normalized.split(" ")
    word_count = len(words)
    _ensure_word_count(word_count)
    word_indices: list[int] = []
    for word in words:
        try:
            index = wordlist.index(word)
        except ValueError as err:
            raise ValueError(f'Unknown mnemonic word: "{word}".') from err
        word_indices.append(index + 1)

    degree = k - 1
    word_polynomials: list[list[int]] = []
    coefficient_batch: list[int] = []
    row_check_polynomials: list[list[int]] | None = None
    column_check_polynomials: list[list[int]] | None = None
    global_polynomial: list[int] | None = None
    try:
        assert_csprng_healthy()
        for secret in word_indices:
            polynomial = random_polynomial(secret, degree)
            word_polynomials.append(polynomial)
            coefficient_batch.extend(polynomial[1:])
        assert_coefficient_batch_healthy(coefficient_batch)
        row_check_polynomials = compute_row_check_polynomials(word_polynomials)
        column_check_polynomials = compute_column_check_polynomials(word_polynomials)
        global_polynomial = compute_global_integrity_check_polynomial(word_polynomials)
        row_count = len(word_indices) // WORDS_PER_ROW
        shares: list[Share] = []
        for share_index in range(1, n + 1):
            word_shares = [evaluate_polynomial(poly, share_index) for poly in word_polynomials]
            checksum_shares: list[int] = []
            for row in range(row_count):
                base = row * WORDS_PER_ROW
                path_a = mod_add(
                    mod_add(
                        mod_add(word_shares[base], word_shares[base + 1]),
                        word_shares[base + 2],
                    ),
                    row + 1,
                )
                path_b = evaluate_polynomial(row_check_polynomials[row], share_index)
                if path_a != path_b:
                    raise ValueError(
                        f"Row checksum path mismatch at share {share_index}, row {row + 1}: "
                        f"Path A (sum)={path_a}, Path B (polynomial)={path_b}. "
                        "This indicates a hardware fault or memory corruption "
                        "during share generation."
                    )
                checksum_shares.append(path_a)

            column_checksum_shares: list[int] = []
            for col in range(3):
                column_path_a = 0
                for row in range(row_count):
                    column_path_a = mod_add(column_path_a, word_shares[row * WORDS_PER_ROW + col])
                column_path_a = mod_add(column_path_a, COLUMN_TAGS[col])
                column_path_b = evaluate_polynomial(column_check_polynomials[col], share_index)
                if column_path_a != column_path_b:
                    raise ValueError(
                        f"Column checksum path mismatch at share {share_index}, column {col + 1}: "
                        f"Path A (sum)={column_path_a}, Path B (polynomial)={column_path_b}. "
                        "This indicates a hardware fault or memory corruption "
                        "during share generation."
                    )
                column_checksum_shares.append(column_path_a)

            global_path_a = mod_add(
                mod_add(
                    sum(word_shares) % FIELD_PRIME,
                    compute_row_total(row_count),
                ),
                COLUMN_TOTAL,
            )
            global_path_b = evaluate_polynomial(global_polynomial, share_index)
            if global_path_a != global_path_b:
                raise ValueError(
                    f"Global integrity path mismatch at share {share_index}: "
                    f"Path A (sum)={global_path_a}, Path B (polynomial)={global_path_b}. "
                    "This indicates a hardware fault or memory corruption "
                    "during share generation."
                )
            shares.append(
                Share(
                    share_number=share_index,
                    word_shares=word_shares,
                    checksum_shares=checksum_shares,
                    column_checksum_shares=column_checksum_shares,
                    global_integrity_check_share=mod_add(global_path_a, share_index),
                )
            )
        if include_input_symbols:
            return shares, word_indices.copy()
        return shares
    finally:
        clear_sensitive_array(word_indices)
        for poly in word_polynomials:
            clear_sensitive_array(poly)
        clear_sensitive_array(coefficient_batch)
        if row_check_polynomials is not None:
            for poly in row_check_polynomials:
                clear_sensitive_array(poly)
        if column_check_polynomials is not None:
            for poly in column_check_polynomials:
                clear_sensitive_array(poly)
        clear_sensitive_array(global_polynomial)


def _clone_share_for_mat(share: Share, mat_mode: str) -> Share:
    return Share(
        share_number=share.share_number,
        word_shares=share.word_shares.copy(),
        checksum_shares=share.checksum_shares.copy(),
        column_checksum_shares=share.column_checksum_shares.copy(),
        global_integrity_check_share=share.global_integrity_check_share,
        mat_mode=mat_mode,
        mat_tags=[],
    )


def _clear_share_keys(share_keys: list[MatShareKeys] | None) -> None:
    if share_keys is None:
        return
    for entry in share_keys:
        for column in entry.columns:
            clear_sensitive_array(column.weights)
            clear_sensitive_array(column.row_pads)
        entry.columns.clear()
    share_keys.clear()


def verify_mat_bindings(
    shares: list[Share],
    share_keys: list[MatShareKeys],
    expected_mat_mode: str | None = None,
) -> bool:
    if expected_mat_mode is None:
        raise ValueError("MAT verification requires an explicit expected MAT mode.")
    mat_mode = normalize_mat_mode(expected_mat_mode)
    expected_columns = mat_column_count(mat_mode)
    if len(shares) == 0 or len(shares) != len(share_keys):
        raise ValueError("MAT Shares and Manifest entries must have matching lengths.")
    for share, key_entry in zip(shares, share_keys, strict=True):
        if share.mat_mode != mat_mode:
            raise ValueError("MAT Share mode does not match the expected MAT mode.")
        if (
            not is_int(share.share_number)
            or share.share_number <= 0
            or share.share_number >= FIELD_PRIME
        ):
            raise ValueError(f"MAT Share number must be between 1 and {FIELD_PRIME - 1}.")
        if not isinstance(share.mat_tags, list) or not isinstance(key_entry.columns, list):
            raise ValueError("MAT Share tags and Manifest columns must be arrays.")
        if share.share_number != key_entry.share_number:
            raise ValueError("MAT Share and Manifest metadata do not match.")
        if len(share.mat_tags) != expected_columns or len(key_entry.columns) != expected_columns:
            raise ValueError("MAT Share and Manifest metadata do not match.")
        for column_index, column in enumerate(key_entry.columns):
            if column.column != column_index + 1:
                raise ValueError("MAT Manifest columns must be complete and in canonical order.")
            expected_tags = compute_mat_tags(share.word_shares, column.weights, column.row_pads)
            actual_tags = share.mat_tags[column_index]
            try:
                if len(expected_tags) != len(actual_tags):
                    raise ValueError("MAT tag column length mismatch.")
                for row, expected in enumerate(expected_tags):
                    actual = normalize_field(
                        actual_tags[row], share.share_number, column_index, row
                    )
                    if not constant_time_equal(expected, actual):
                        raise ValueError(
                            f"MAT consistency check failed for Share {share.share_number}, "
                            f"column {column_index + 1}, row {row + 1}."
                        )
            finally:
                clear_sensitive_array(expected_tags)
    return True


def normalize_field(value: int, share_number: int, column_index: int, row: int) -> int:
    return normalize_share_value(
        value,
        f"MAT Share {share_number} column {column_index + 1} row {row + 1} tag",
    )


def generate_mat_artifacts(
    shares: list[Share],
    *,
    mat_mode: str | None = None,
    mat_custody: str | None = None,
) -> SharingArtifacts:
    if len(shares) == 0:
        raise ValueError("MAT generation requires at least one arithmetic Share.")
    mode = normalize_mat_mode(mat_mode)
    custody = normalize_mat_custody(mat_custody, mode)
    column_count = mat_column_count(mode)
    word_count = len(shares[0].word_shares)
    if word_count <= 0 or word_count % WORDS_PER_ROW != 0:
        raise ValueError("MAT generation requires complete word-share rows.")
    row_count = word_count // WORDS_PER_ROW
    output_shares: list[Share] = []
    for share in shares:
        if len(share.word_shares) != word_count:
            raise ValueError("All Shares must contain the same number of word values.")
        output_shares.append(_clone_share_for_mat(share, mode))
    complete_keys = [MatShareKeys(share.share_number, []) for share in output_shares]
    split_a: list[MatShareKeys] | None = None
    split_b: list[MatShareKeys] | None = None
    if column_count == 0:
        return SharingArtifacts(
            shares=output_shares,
            manifests=[Manifest("none", mode, custody, complete_keys)],
        )
    try:
        for share_index, share in enumerate(output_shares):
            for column_number in range(1, column_count + 1):
                weights, row_pads = generate_mat_key_set(row_count)
                complete_keys[share_index].columns.append(
                    MatColumn(column_number, weights, row_pads)
                )
                share.mat_tags.append(compute_mat_tags(share.word_shares, weights, row_pads))
        verify_mat_bindings(output_shares, complete_keys, mode)
        if custody == "whole":
            return SharingArtifacts(
                shares=output_shares,
                manifests=[Manifest("whole", mode, custody, complete_keys)],
            )
        split_a = []
        split_b = []
        for entry in complete_keys:
            entry_a = MatShareKeys(entry.share_number, [])
            entry_b = MatShareKeys(entry.share_number, [])
            split_a.append(entry_a)
            split_b.append(entry_b)
            for column in entry.columns:
                key_a, key_b = split_mat_key_set(column.weights, column.row_pads, row_count)
                entry_a.columns.append(MatColumn(column.column, key_a[0], key_a[1]))
                entry_b.columns.append(MatColumn(column.column, key_b[0], key_b[1]))
        reconstructed = _recombine_share_keys(split_a, split_b, row_count)
        try:
            verify_mat_bindings(output_shares, reconstructed, mode)
        finally:
            _clear_share_keys(reconstructed)
        _clear_share_keys(complete_keys)
        return SharingArtifacts(
            shares=output_shares,
            manifests=[
                Manifest("split-a", mode, custody, split_a),
                Manifest("split-b", mode, custody, split_b),
            ],
        )
    except Exception:
        _clear_share_keys(complete_keys)
        _clear_share_keys(split_a)
        _clear_share_keys(split_b)
        clear_sharing_artifacts(SharingArtifacts(output_shares, []))
        raise


def _recombine_share_keys(
    share_keys_a: list[MatShareKeys],
    share_keys_b: list[MatShareKeys],
    row_count: int,
) -> list[MatShareKeys]:
    if len(share_keys_a) != len(share_keys_b):
        raise ValueError("Split MAT Manifests must contain matching Share entries.")
    combined: list[MatShareKeys] = []
    try:
        for entry_a, entry_b in zip(share_keys_a, share_keys_b, strict=True):
            if entry_a.share_number != entry_b.share_number or len(entry_a.columns) != len(
                entry_b.columns
            ):
                raise ValueError("Split MAT Manifest Share entries do not match.")
            combined_entry = MatShareKeys(entry_a.share_number, [])
            combined.append(combined_entry)
            for column_a, column_b in zip(entry_a.columns, entry_b.columns, strict=True):
                if column_a.column != column_b.column:
                    raise ValueError("Split MAT Manifest column entries do not match.")
                weights, pads = recombine_mat_key_sets(
                    (column_a.weights, column_a.row_pads),
                    (column_b.weights, column_b.row_pads),
                    row_count,
                )
                combined_entry.columns.append(MatColumn(column_a.column, weights, pads))
        return combined
    except Exception:
        _clear_share_keys(combined)
        raise


def clear_sharing_artifacts(artifacts: SharingArtifacts | None) -> None:
    """Best-effort clear of artifact buffers held by the caller. Not a RAM erase."""
    if artifacts is None:
        return
    for share in artifacts.shares:
        clear_sensitive_array(share.word_shares)
        clear_sensitive_array(share.checksum_shares)
        clear_sensitive_array(share.column_checksum_shares)
        for tags in share.mat_tags:
            clear_sensitive_array(tags)
        share.mat_tags.clear()
        share.digital = None
        share.global_integrity_check_share = 0
    artifacts.shares.clear()
    for manifest in artifacts.manifests:
        _clear_share_keys(manifest.share_keys)
    artifacts.manifests.clear()
    artifacts.session = None


def _attach_envelopes(
    shares: list[Share],
    input_symbols: list[int],
    threshold: int,
    *,
    wallet_profile_code: int | None,
    full_session_batch_id: bytes | None,
    rva_note: str | None,
) -> DigitalSession:
    if len(shares) == 0:
        raise ValueError("Digital envelopes require at least one Share.")
    if len(input_symbols) == 0:
        raise ValueError("Digital envelopes require canonical input symbols.")
    word_count = len(input_symbols)
    _ensure_word_count(word_count)
    profile_code = normalize_wallet_profile_code(wallet_profile_code)
    full_batch = (
        bytearray(get_random_bytes(8))
        if full_session_batch_id is None
        else bytearray(full_session_batch_id)
    )
    if len(full_batch) != 8:
        clear_sensitive_array(full_batch)
        raise ValueError("Full Session Batch ID must be exactly 8 bytes.")
    compact_batch = bytearray(full_batch[:4])
    canonical = bytearray(build_canonical_secret_material(input_symbols))
    try:
        full_rbt = bytearray(derive_rbt(bytes(canonical), bytes(full_batch), 12))
        compact_rbt = bytearray(derive_rbt(bytes(canonical), bytes(compact_batch), 6))
        session = DigitalSession(
            protocol_version=0x01,
            language_input=0x01,
            word_count=word_count,
            threshold=threshold,
            wallet_profile_code=profile_code,
            full=SessionProfile(
                bytes(full_batch),
                bytes(full_rbt),
                build_manifest_header_payload(
                    PROFILE_FULL, word_count, bytes(full_batch), bytes(full_rbt)
                ),
            ),
            compact=SessionProfile(
                bytes(compact_batch),
                bytes(compact_rbt),
                build_manifest_header_payload(
                    PROFILE_COMPACT, word_count, bytes(compact_batch), bytes(compact_rbt)
                ),
            ),
            rva_note=rva_note,
        )
        for share in shares:
            full_payload, transport_hash = build_full_share_payload(
                share,
                threshold,
                word_count,
                profile_code,
                bytes(full_batch),
                bytes(full_rbt),
            )
            compact_payload = build_compact_share_payload(
                share,
                threshold,
                word_count,
                profile_code,
                bytes(compact_batch),
                bytes(compact_rbt),
            )
            full_audit = compute_sha256(full_payload)
            compact_audit = compute_sha256(compact_payload)
            share.digital = ShareDigital(
                full=DigitalProfile(
                    payload=full_payload,
                    transport_hash=transport_hash,
                    audit_hash=full_audit,
                    audit_payload=build_share_audit_payload(
                        PROFILE_FULL, word_count, threshold, share.share_number, full_audit
                    ),
                ),
                compact=DigitalProfile(
                    payload=compact_payload,
                    audit_hash=compact_audit,
                    audit_payload=build_share_audit_payload(
                        PROFILE_COMPACT, word_count, threshold, share.share_number, compact_audit
                    ),
                ),
            )
        return session
    except Exception:
        for share in shares:
            share.digital = None
        raise
    finally:
        clear_sensitive_array(full_batch)
        clear_sensitive_array(compact_batch)
        clear_sensitive_array(canonical)


def create_sharing_artifacts(
    mnemonic: str,
    k: int,
    n: int,
    wordlist: list[str] | None = None,
    *,
    mat_mode: str | None = None,
    mat_custody: str | None = None,
    wallet_profile_code: int | None = None,
    full_session_batch_id: bytes | None = None,
    rva_note: str | None = None,
) -> SharingArtifacts:
    """Arithmetic split, then MAT, then session envelopes."""
    produced = split_bip39(mnemonic, k, n, wordlist, include_input_symbols=True)
    assert isinstance(produced, tuple)
    arithmetic_shares, input_symbols = produced
    artifacts: SharingArtifacts | None = None
    try:
        artifacts = generate_mat_artifacts(
            arithmetic_shares, mat_mode=mat_mode, mat_custody=mat_custody
        )
        artifacts.session = _attach_envelopes(
            artifacts.shares,
            input_symbols,
            k,
            wallet_profile_code=wallet_profile_code,
            full_session_batch_id=full_session_batch_id,
            rva_note=rva_note,
        )
        artifacts.rva_note = rva_note
        return artifacts
    except Exception:
        clear_sharing_artifacts(artifacts)
        raise
    finally:
        clear_sharing_artifacts(SharingArtifacts(arithmetic_shares, []))
        clear_sensitive_array(input_symbols)
