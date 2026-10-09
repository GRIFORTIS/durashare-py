"""Basic tests for package initialization."""

import durashare_py


def test_version_exists():
    """Test that version is defined."""
    assert hasattr(durashare_py, "__version__")
    assert isinstance(durashare_py.__version__, str)


def test_author_exists():
    """Test that author is defined."""
    assert hasattr(durashare_py, "__author__")
    assert durashare_py.__author__ == "GRIFORTIS"


def test_license_exists():
    """Test that license is defined."""
    assert hasattr(durashare_py, "__license__")
    assert durashare_py.__license__ == "MIT"
