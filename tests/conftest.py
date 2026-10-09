"""Reset ceremony test doubles after every test."""

import pytest

from durashare_py import configure_environment


@pytest.fixture(autouse=True)
def _restore_ceremony_providers() -> None:
    configure_environment(random_source=None, sha256=None, pbkdf2_hmac_sha512=None)
    yield
    configure_environment(random_source=None, sha256=None, pbkdf2_hmac_sha512=None)
