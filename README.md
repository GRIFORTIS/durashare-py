# DuraShare (Python)

[![Security: Unaudited](https://img.shields.io/badge/Security-Unaudited-orange)](https://github.com/GRIFORTIS/.github/blob/main/SECURITY.md)
[![CI](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/GRIFORTIS/durashare-py/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/GRIFORTIS/durashare-py/graph/badge.svg)](https://codecov.io/gh/GRIFORTIS/durashare-py)
[![PyPI version](https://img.shields.io/pypi/v/durashare_py.svg)](https://pypi.org/project/durashare_py/)
[![Python versions](https://img.shields.io/pypi/pyversions/durashare_py.svg)](https://pypi.org/project/durashare_py/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## DuraShare

**DuraShare: BIP39-Native Threshold Backup over GF(2053) with Full Manual Fallback and Per-Share Audit**

DuraShare uses Shamir secret sharing to split a **standard BIP39** recovery phrase into **k-of-n** durable, human-readable shares in an offline, software-assisted experience, **while keeping all the math executable manually on paper**. It also allows **individual geographically distributed shares to be verified** before recovery, without gathering a threshold or revealing the secret.

DuraShare **modifies existing, well-established cryptographic techniques** for human-friendly threshold backup. Reference implementations are thoroughly tested, published in good faith **as is**, and have **not** been independently audited. See [Disclaimer](#disclaimer).

## What is this?

Python implementation for offline/air-gapped workflows, with manual-fallback compatibility.

**In this Python implementation, you can:**

- Split a BIP39 mnemonic into \(k\)-of-\(n\) shares
- Recover a candidate mnemonic from \(k\) shares, with separate confidence and kit-health results
- Generate Manual Authentication (MAT) tags and Whole-Key or Split-Key manifests
- Build and decode Full and Compact hexadecimal share payloads, Manifest Session Headers (SB), and Share Audit payloads (SA)
- Audit one stored share from its fields, payload, SB/SA evidence, and MAT without recovering the seed

This library implements the same cryptographic subset as HTML v0.6.0. It does not render or scan Bech32m/QR codes, derive a wallet address, run a nested ceremony, or accept pre-encrypted numeric input.

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
pip install durashare_py
```

`schiavinato-sharing` 0.4.2 is the last release of the previous share format. This tree imports `durashare_py`.

---

## Quick Start

### Split a mnemonic

```python
from durashare_py import split_bip39

mnemonic = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
shares = split_bip39(mnemonic, 2, 3)
print(shares[0].share_number)
```

### Recover a mnemonic

```python
from durashare_py import recover_mnemonic

result = recover_mnemonic(shares[:2], word_count=12)
if not result.success:
    raise RuntimeError(result.errors.generic)
print(result.mnemonic)
```

`result.mnemonic` is set only when the supplied share-table checks, BIP39, and every supplied Recovery Binding Tag agree. `result.recovered_mnemonic` can still hold a candidate when those checks fail.

---

## API Reference (high-level)

Stable entry points:

- `split_bip39(mnemonic, k, n, wordlist=None)`
- `create_sharing_artifacts(...)` for MAT and hexadecimal envelopes
- `recover_and_validate(...)` and `recover_mnemonic(...)`
- `audit_share(...)` for one stored share, without interpolation

Field arithmetic, Lagrange helpers, checksum helpers, and best-effort wipe utilities are exported from `durashare_py`.

---

## Conformance Validation

This implementation is checked against frozen vectors from protocol tag `v0.7.0`:

- `test_vectors/vectors.json` for current arithmetic, MAT, Full/Compact payloads, SB/SA, Transport Hash, Manifest Audit Hash, Session Batch ID, and RBT
- `previous_versions/v0.5.0/test_vectors/vectors.json` for recovery of archived share tables

Set `DURASHARE_SPEC_REPO_PATH` to a local `durashare` checkout, or clone that repo next to this one.

---

## Functional Validation (Run Tests)

See [`TESTING`](./TESTING.md) for the full local testing checklist (CI parity).

---

## Compatibility

- **Implementation version**: 0.6.0, the same cryptographic subset as HTML v0.6.0
- **Frozen interoperability oracle**: protocol v0.7.0 vectors
- **Supported subset**: arithmetic share tables; position-bound row and column checksums; printed GIC; single- or dual-column MAT with Whole-Key or Split-Key manifests; Full/Compact hexadecimal share payloads; hexadecimal SB/SA payloads; Manifest Audit Hash; Session Batch ID; profile-length RBT; free-text RVA notes; one-share Audit without seed recovery
- **Recovery**: archived v0.5.0 share tables still yield a candidate mnemonic. Their column tags do not pass the v0.7.0 kit-health check
- **Out of scope**: Bech32m/QR, automatic wallet derivation, pre-encrypted numeric input, nested ceremonies, and complete parity with the living protocol
- **BIP39 word counts**: 12, 15, 18, 21, 24
- **Previous package**: `schiavinato-sharing` 0.4.2 is the last release of the v0.4.0 share format
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
