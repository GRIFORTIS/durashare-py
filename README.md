# Schiavinato Sharing (Python)

[![Security: Experimental](https://img.shields.io/badge/Security-⚠️%20EXPERIMENTAL%20⚠️-red)](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
[![CI](https://github.com/GRIFORTIS/schiavinato-sharing-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/schiavinato-sharing-py/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GRIFORTIS/schiavinato-sharing-py/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/schiavinato-sharing-py/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/GRIFORTIS/schiavinato-sharing-py/graph/badge.svg)](https://codecov.io/gh/GRIFORTIS/schiavinato-sharing-py)
[![PyPI version](https://img.shields.io/pypi/v/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![Python versions](https://img.shields.io/pypi/pyversions/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> ## ⚠️ WARNING: EXPERIMENTAL SOFTWARE ⚠️
> 
>DO NOT USE IT FOR REAL FUNDS!
>
> Schiavinato Sharing specification and implementations have NOT been audited. Use for testing, learning, and experimentation only. See [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md) for details.
>
>We invite **cryptographers** and **developers** to review the spec and software. See [CONTRIBUTING](https://github.com/GRIFORTIS/.github/blob/main/CONTRIBUTING.md) to know more.

Python implementation of **Schiavinato Sharing**: dual-mode (manual + software) \(k\)-of-\(n\) threshold secret sharing for **BIP39 mnemonics** over **GF(2053)**. Designed for offline/air-gapped workflows, with manual-fallback compatibility.

---

## What is this?

**Schiavinato Sharing** is a dual-mode (**manual + software**) \(k\)-of-\(n\) threshold secret sharing scheme for **BIP39 mnemonics**. It operates directly on the **1-indexed BIP39 word indices** over the prime field **GF(2053)**, so the recovered secret is a standard BIP39 mnemonic compatible with modern wallets.

**In this Python implementation, you can:**

- Split a BIP39 mnemonic into \(k\)-of-\(n\) shares (`Share`)
- Recover the original BIP39 mnemonic from \(k\) shares (`RecoveryResult`)
- Validate inputs and share integrity during split/recovery to prevent silent mistakes

---

## Links

- **Canonical protocol + specs**: [schiavinato-sharing](https://github.com/GRIFORTIS/schiavinato-sharing)
- **Whitepaper**: [PDF (latest)](https://github.com/GRIFORTIS/schiavinato-sharing/releases/latest/download/WHITEPAPER.pdf) | [Releases (versioned PDF)](https://github.com/GRIFORTIS/schiavinato-sharing/releases) | [LaTeX](https://github.com/GRIFORTIS/schiavinato-sharing/blob/main/whitepaper/WHITEPAPER.tex)
- **Test Vectors**: [TEST_VECTORS](https://github.com/GRIFORTIS/schiavinato-sharing/blob/main/test_vectors/README.md)
- **Canonical security posture**: [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
- **HTML implementation**: [schiavinato-sharing-html](https://github.com/GRIFORTIS/schiavinato-sharing-html)
- **JavaScript implementation**: [schiavinato-sharing-js](https://github.com/GRIFORTIS/schiavinato-sharing-js)

---

## Security

This library implements well-established cryptographic principles but has **NOT** been professionally audited.

**Use only for**: testing, learning, experimentation.

**Canonical security posture**: [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)

---

## Verify Before Use (Required)

**CRITICAL**: Before using with real crypto seeds, verify the package and/or release artifacts haven't been tampered with.

### Option A: Verify release artifacts (recommended for highest assurance)

This repository's releases include:
- `CHECKSUMS-PYPI.txt` (+ detached signature `CHECKSUMS-PYPI.txt.asc`)
- Python package artifacts (`*.whl`, `*.tar.gz`) (+ optional detached signatures `*.asc`)

Import the GRIFORTIS public key and verify signatures before use.

```bash
curl -fsSL https://raw.githubusercontent.com/GRIFORTIS/schiavinato-sharing-py/main/GRIFORTIS-PGP-PUBLIC-KEY.asc | gpg --import
gpg --fingerprint security@grifortis.com
```

**Expected**: `7921 FD56 9450 8DA4 020E  671F 4CFE 6248 C57F 15DF`

Then verify release assets (examples):

```bash
gpg --verify CHECKSUMS-PYPI.txt.asc CHECKSUMS-PYPI.txt
sha256sum --check CHECKSUMS-PYPI.txt --ignore-missing
```

### Option B: Verify the PyPI artifacts (supply-chain sanity check)

- Pin exact versions and use lockfiles for repeatable installs
- Prefer offline installs from a locally verified wheel/sdist
---

## Installation

```bash
pip install schiavinato-sharing
```

---

## Quick Start

### Split a mnemonic

```python
from schiavinato_sharing import split_mnemonic

mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
shares = split_mnemonic(mnemonic, 2, 3)
print(shares[0].share_number)
```

### Recover a mnemonic

```python
from schiavinato_sharing import recover_mnemonic

result = recover_mnemonic(shares[:2], word_count=12, strict_validation=True)
if not result.success:
    raise RuntimeError(str(result.errors))
print(result.mnemonic)
```

---

## API Reference (high-level)

Stable entry points:
- `split_mnemonic(mnemonic, k, n, wordlist=None)`
- `recover_mnemonic(shares, word_count, strict_validation=True, wordlist=None)`

Advanced exports (field arithmetic, Lagrange helpers, checksum helpers, secure wipe utilities) are also available for integration/testing; see the package exports in `schiavinato_sharing/__init__.py`.

---

## Conformance Validation

This implementation is validated against canonical test vectors:
- [TEST_VECTORS](https://github.com/GRIFORTIS/schiavinato-sharing/blob/main/test_vectors/README.md)

---

## Functional Validation (Run Tests)

See [`TESTING`](./TESTING.md) for the full local testing checklist (CI parity).

---

## Compatibility

- **Spec version**: v0.4.0
- **Python**: 3.10+
---

## Contributing

See [CONTRIBUTING](https://github.com/GRIFORTIS/.github/blob/main/CONTRIBUTING.md).

---

## License

[MIT License](LICENSE)

