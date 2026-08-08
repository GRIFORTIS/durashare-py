# DuraShare (Python)

[![Security: Unaudited](https://img.shields.io/badge/Security-Unaudited-orange)](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
[![CI](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/GRIFORTIS/durashare-py/graph/badge.svg)](https://codecov.io/gh/GRIFORTIS/durashare-py)
[![PyPI version](https://img.shields.io/pypi/v/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![Python versions](https://img.shields.io/pypi/pyversions/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DuraShare **modifies existing, well-established cryptographic techniques** for human-friendly threshold backup. This library is thoroughly tested, published in good faith **as is**, and has **not** been independently audited. **Do not use with real funds.** See [Disclaimer](#disclaimer).

Python implementation of **DuraShare**: dual-mode (manual + software) \(k\)-of-\(n\) threshold secret sharing for **BIP39 mnemonics** over **GF(2053)**. Designed for offline/air-gapped workflows, with manual-fallback compatibility.

For the full use-case context — including humanitarian deployment scenarios, Tails OS integration, and the manual fallback rationale — see the [canonical specification](https://github.com/GRIFORTIS/durashare).

---

## What is this?

**DuraShare** is a dual-mode (**manual + software**) \(k\)-of-\(n\) threshold secret sharing scheme for **BIP39 mnemonics**. It operates directly on the **1-indexed BIP39 word indices** over the prime field **GF(2053)**, so the recovered secret is a standard BIP39 mnemonic compatible with modern wallets.

**In this Python implementation, you can:**

- Split a BIP39 mnemonic into \(k\)-of-\(n\) shares (`Share`)
- Recover the original BIP39 mnemonic from \(k\) shares (`RecoveryResult`)
- Validate inputs and share integrity during split/recovery to prevent silent mistakes

---

## Links

- **Canonical protocol + specs**: [durashare](https://github.com/GRIFORTIS/durashare)
- **Whitepaper**: [PDF (latest)](https://github.com/GRIFORTIS/durashare/releases/latest/download/WHITEPAPER.pdf) | [Releases (versioned PDF)](https://github.com/GRIFORTIS/durashare/releases) | [LaTeX](https://github.com/GRIFORTIS/durashare/blob/main/whitepaper/WHITEPAPER.tex)
- **Test Vectors**: [TEST_VECTORS](https://github.com/GRIFORTIS/durashare/blob/main/test_vectors/README.md)
- **Canonical security posture**: [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
- **HTML implementation**: [durashare-html](https://github.com/GRIFORTIS/durashare-html)
- **JavaScript implementation**: [durashare-js](https://github.com/GRIFORTIS/durashare-js)

---

## Security

This library implements well-established cryptographic principles and has **not** been independently audited. See [Disclaimer](#disclaimer).

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
curl -fsSL https://raw.githubusercontent.com/GRIFORTIS/durashare-py/main/GRIFORTIS-PGP-PUBLIC-KEY.asc | gpg --import
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
- [TEST_VECTORS](https://github.com/GRIFORTIS/durashare/blob/main/test_vectors/README.md)

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

## Disclaimer

This software has been thoroughly tested and is not known to contain errors. It is made available in good faith, as is, so use at your own risk. The author does not assume any responsibility for any damage, financial or other, that may result from using this software. It has not been independently audited. **Do not use with real funds.** See [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md).

