# DuraShare (Python)

[![Security: Unaudited](https://img.shields.io/badge/Security-Unaudited-orange)](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
[![CI](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/GRIFORTIS/durashare-py/graph/badge.svg)](https://codecov.io/gh/GRIFORTIS/durashare-py)
[![PyPI version](https://img.shields.io/pypi/v/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![Python versions](https://img.shields.io/pypi/pyversions/schiavinato-sharing.svg)](https://pypi.org/project/schiavinato-sharing/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## DuraShare

**DuraShare: BIP39-Native Threshold Backup over GF(2053) with Full Manual Fallback and Per-Share Audit**

DuraShare uses Shamir secret sharing to split a **standard BIP39** recovery phrase into **k-of-n** durable, human-readable shares in an offline, software-assisted experience, **while keeping all the math executable manually on paper**. It also allows **individual geographically distributed shares to be verified** before recovery, without gathering a threshold or revealing the secret.

DuraShare **modifies existing, well-established cryptographic techniques** for human-friendly threshold backup. Reference implementations are thoroughly tested, published in good faith **as is**, and have **not** been independently audited. See [Disclaimer](#disclaimer).

## What is this?

Python implementation for offline/air-gapped workflows, with manual-fallback compatibility.

**In this Python implementation, you can:**

- Split a BIP39 mnemonic into \(k\)-of-\(n\) shares (`Share`)
- Recover the original BIP39 mnemonic from \(k\) shares (`RecoveryResult`)
- Validate inputs and share integrity during split/recovery to prevent silent mistakes

---

## Links

- **Canonical specification**: [durashare](https://github.com/GRIFORTIS/durashare)
  - Standing review guide: [docs/review](https://github.com/GRIFORTIS/durashare/blob/main/docs/review.md)
- **Whitepaper**: [PDF (latest)](https://github.com/GRIFORTIS/durashare/releases/latest/download/WHITEPAPER.pdf) | [Releases](https://github.com/GRIFORTIS/durashare/releases) | [LaTeX](https://github.com/GRIFORTIS/durashare/blob/main/whitepaper/WHITEPAPER.tex)
- **Test vectors**: [TEST_VECTORS](https://github.com/GRIFORTIS/durashare/blob/main/test_vectors/README.md)
- **Related implementations**:
  - HTML (single-file, air-gapped): [durashare-html](https://github.com/GRIFORTIS/durashare-html)
  - JavaScript/TypeScript: [durashare-js](https://github.com/GRIFORTIS/durashare-js)
- **Security**: [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)

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

## People

### Renato Schiavinato Lopez — Founder & Protocol Author
- Creator of DuraShare.
- [LinkedIn](https://www.linkedin.com/in/renato-agile-coach/) · [GitHub](https://github.com/renatoslopes)

### Jeroen van de Graaf — Chief Scientist; Advisory Board
- Professor, DCC–UFMG. Cryptographer (ZK, MPC, privacy, applied protocols); PhD, Université de Montréal (1997).
- [DCC/UFMG](https://dcc.ufmg.br/professor/jeroen-van-de-graaf/) · [DBLP](https://dblp.org/pid/27/6925.html) · [Lattes](http://lattes.cnpq.br/0069989873499216) · [Google Scholar](https://scholar.google.com.br/citations?user=-w8olWwAAAAJ)

## License

[MIT License](LICENSE)

## Disclaimer

Software has been thoroughly tested and is not known to contain errors. It is made available in good faith, as is, so use at your own risk. The author does not assume any responsibility for any damage, financial or other, that may result from using this software. Reference implementations have not been independently audited. **Do not use with real funds.** See [SECURITY](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md).

---

**Maintained by**: [GRIFORTIS](https://github.com/GRIFORTIS)
