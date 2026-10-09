"""Locate the spec checkout used by conformance tests."""

import os
from pathlib import Path


def spec_root() -> Path:
    """Prefer DURASHARE_SPEC_REPO_PATH, then a sibling checkout named durashare."""
    env = os.environ.get("DURASHARE_SPEC_REPO_PATH")
    if env:
        root = Path(env)
    else:
        root = Path(__file__).resolve().parents[2] / "durashare"
    if not (root / "test_vectors" / "vectors.json").is_file():
        raise FileNotFoundError(
            "Canonical vectors not found. Set DURASHARE_SPEC_REPO_PATH to the spec repo."
        )
    return root
