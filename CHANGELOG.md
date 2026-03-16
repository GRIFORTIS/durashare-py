# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Centralize community health references (SECURITY / CONTRIBUTING) to the org-wide defaults in `GRIFORTIS/.github`.
- Update author email to `contact@grifortis.com` and maintainer email to `renato.lopez@grifortis.com` in `pyproject.toml`.

### Removed
- Repo-local `.github/SECURITY.md` and `.github/CONTRIBUTING.md` in favor of org-wide defaults.

### Tests
- Add recovery validation test covering non-integer `share_number` rejection (improves patch coverage / CI signal)

## [0.4.2] - 2026-02-04

### Documentation
- Align repository wording/structure with the HTML/JS implementations (badges, disclaimer, section order)
- Update canonical links to point to `schiavinato-sharing` (spec repo), removing legacy spec-repo references

### Fixed
- Reject invalid share numbers during recovery (must be integer \(1..2052\); no silent modulo wraparound/collisions)
- Add recovery validation tests for invalid share numbers (0 and out-of-range)

### Changed
- Move utility scripts into `scripts/` (and remove the previous root-level copies)
- Remove QR grid SVG templates from this repo (they live under `schiavinato-sharing/docs/`)

## [0.4.1] - 2026-02-01

### Security
- Use constant-time checksum-bit comparison during BIP39 mnemonic validation in split and recovery (JS v0.4.1 parity)

## [0.4.0] - 2026-01-29

### Versioning Note (Alignment)
- This repository is aligned to **v0.4.0** to match the specification + whitepaper release.

### Indexing Policy (CRITICAL)
- **BIP39-native indexing remains 0-based** (wordlist positions \(0..2047\)).
- **Schiavinato Sharing math is 1-based** (word indices \(1..2048\)) and is what is used as secrets in GF(2053).
- Any \(+1/-1\) conversion is allowed **only** at the BIP39 <-> Schiavinato boundary (wordlist position <-> Schiavinato word index).

### Changed - Share Display Format (merged)
- Share values use dual-reference format for clarity:
  - Value 0: displayed as `0000-0000`
  - Values 1-2048: displayed as `####-word` / `word-####` (implementation-specific presentation)
  - Values 2049-2052: displayed as `2049-2049`, `2050-2050`, etc. (GF(2053) overflow values)

### Added
- Dual-path checksum validation (Path A sums vs Path B polynomials) during split and recovery
- Checksum polynomial helpers (`sum_polynomials`, row/global checksum polynomials)
- Security utilities for constant-time comparisons and best-effort wiping
- Configurable randomness source for deterministic/testing scenarios
- Mnemonic/seed helpers (`generate_valid_mnemonic`, `mnemonic_to_indices`, `indices_to_mnemonic`, `parse_input`)
- **GIC Binding**: Global Integrity Check is now bound to share number `x` (printed GIC = sum + x mod 2053)
- Native BIP39 checksum validation with constant-time checksum-bit comparison (canonical HTML parity)

### Changed
- Recovery reports now surface `rowPathMismatch` and `globalPathMismatch` for checksum path disagreements
- Public API exports extended to match JS v0.4.0 surface
- **Terminology standardization**: "Global Checksum" renamed to "Global Integrity Check (GIC)" across all code, tests, and documentation
- Property name: `global_checksum_verification_share` → `global_integrity_check_share` (breaking change)
- Function name: `compute_global_checksum()` → `compute_global_integrity_check()` (breaking change)

### Fixed
- Mnemonic sanitization now lowercases input before validation/splitting (canonical HTML parity)

### Tests/Docs
- Added dual-path checksum mismatch tests and random-source coverage
- Updated README to reflect new helpers and version

## [0.3.0] - 2025-12-06

### Changed
- Checksum shares are now computed deterministically as the sum of word shares (mod 2053) rather than using independent random polynomials
- This change enables share integrity validation during the splitting process
- Recovery algorithm unchanged - all existing shares remain recoverable
- Maintains all LSSS security properties

### Benefits
- Users can verify share integrity during manual splitting
- Row checksum share = sum of 3 word shares in that row (mod 2053)
- Global checksum share = sum of all word shares (mod 2053)
- Catches arithmetic errors before share distribution
- Zero impact on recovery time or process

### Security Note
- No information leakage (checksums are deterministic functions of words)
- Threshold property preserved (still requires k shares for recovery)
- Entropy source unchanged (word polynomials remain random)

### Migration
- No API changes required
- Shares created with earlier versions remain recoverable by v0.3.0
- Shares created with v0.3.0 remain recoverable by earlier versions
- The only difference is checksum computation method during split

## [0.1.0] - 2025-11-23

### Added
- Initial release of Schiavinato Sharing Python library
- Core GF(2053) field arithmetic operations
- Polynomial creation and evaluation
- Lagrange interpolation for secret reconstruction
- BIP39 mnemonic splitting with configurable k-of-n threshold
- BIP39 mnemonic recovery with comprehensive validation
- Row and global checksum computation and verification
- Type hints for all public APIs
- Support for both 12-word and 24-word mnemonics
- Compatible with Python 3.9+

### Security
- Uses `mnemonic` library for BIP39 validation
- Cryptographically secure random number generation via `secrets` module
- Rejection sampling to avoid modulo bias in random number generation

### Documentation
- Comprehensive README with API reference
- Docstrings on all public functions
- Security considerations and best practices
- Examples for common use cases

---

## Links

- **Repository**: [schiavinato-sharing-py](https://github.com/GRIFORTIS/schiavinato-sharing-py)
- **JavaScript Library**: [schiavinato-sharing-js](https://github.com/GRIFORTIS/schiavinato-sharing-js)
- **Canonical protocol + specs**: [schiavinato-sharing](https://github.com/GRIFORTIS/schiavinato-sharing)
- **Organization**: [GRIFORTIS](https://github.com/GRIFORTIS)

---

[Unreleased]: https://github.com/GRIFORTIS/schiavinato-sharing-py/compare/v0.4.2...main
[0.4.2]: https://github.com/GRIFORTIS/schiavinato-sharing-py/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/GRIFORTIS/schiavinato-sharing-py/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/GRIFORTIS/schiavinato-sharing-py/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/GRIFORTIS/schiavinato-sharing-py/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/GRIFORTIS/schiavinato-sharing-py/releases/tag/v0.1.0
