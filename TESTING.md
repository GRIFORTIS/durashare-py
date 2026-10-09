# Testing Guide (Python)

This document explains how to run the Python library tests locally and how conformance is validated.

---

## Quick start

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

---

## Full local check (CI parity)

```bash
ruff check .
black --check .
mypy -p durashare_py
pytest
```

---

## Conformance validation (canonical test vectors)

Conformance uses frozen files from protocol tag `v0.7.0`:

- `test_vectors/vectors.json` for current arithmetic, MAT, Full/Compact payloads, SB/SA, hashes, and RBT
- `previous_versions/v0.5.0/test_vectors/vectors.json` for recovery of archived share tables

Set `DURASHARE_SPEC_REPO_PATH` to a checkout of `GRIFORTIS/durashare` at that tag, or clone the spec repo next to this repository. CI checks out `GRIFORTIS/durashare` at ref `v0.7.0`.

When changing behavior, update tests so the implementation remains compatible with the vectors version it claims to support.

---

## Troubleshooting

### Environment issues

- Ensure you are in an activated virtualenv (`which python` should point to `venv/`).
- If type-checking fails, confirm you installed dev dependencies: `pip install -e ".[dev]"`.
