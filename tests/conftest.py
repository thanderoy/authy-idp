import subprocess
import sys

import pytest
from django.core.cache import cache
from jwcrypto import jwk


@pytest.fixture(autouse=True)
def _clear_cache():
    # Rate limits, lockouts and the token blacklist live in the cache; keep
    # one test's counters from leaking into the next.
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def key_file(tmp_path):
    """Write a fresh RSA private key to tmp_path/<name> and return its path."""

    def make(name="oidc.key"):
        path = tmp_path / name
        path.write_bytes(
            jwk.JWK.generate(kty="RSA", size=2048).export_to_pem(
                private_key=True, password=None
            )
        )
        return path

    return make


@pytest.fixture
def load_settings(key_file):
    """Run ``probe`` in a fresh interpreter with production-like settings.

    Settings are evaluated at import, so environment-dependent behaviour can
    only be tested this way. The environment is fully controlled (no local
    .env values leak in): DEBUG=False, Redis configured and a valid signing
    key, each overridable through keyword arguments.
    """

    def run(probe, **env):
        base = {
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": "src",
            "DJANGO_SECRET_KEY": "x",
            "DEBUG": "False",
            "REDIS_URL": "redis://redis:6379/0",
            "OIDC_RSA_PRIVATE_KEY": "",
            "OIDC_RSA_PRIVATE_KEY_PATH": str(key_file("default.key")),
            "TRUSTED_PROXY_COUNT": "0",
            "DEFAULT_FROM_EMAIL": "noreply@example.test",
        }
        return subprocess.run(
            [sys.executable, "-c", probe],
            env={**base, **env},
            capture_output=True,
            text=True,
            check=False,
        )

    return run
