"""Settings guards that only apply with DEBUG=False.

Settings are evaluated at import, so each case loads them in a fresh
interpreter with a controlled environment.
"""

import subprocess
import sys

PROBE = (
    "import os;os.environ['DJANGO_SETTINGS_MODULE']='config.settings';"
    "from django.conf import settings as s;"
    "print(s.CACHES['default']['BACKEND'], s.SESSION_ENGINE)"
)


def load_settings(**env):
    base = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": "src",
        "DJANGO_SECRET_KEY": "x",
        "DEBUG": "False",
    }
    return subprocess.run(
        [sys.executable, "-c", PROBE],
        env={**base, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_production_refuses_to_start_without_redis():
    result = load_settings()
    assert result.returncode != 0
    assert "REDIS_URL is required" in result.stderr


def test_production_uses_redis_and_durable_sessions():
    result = load_settings(REDIS_URL="redis://redis:6379/0")
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "django.core.cache.backends.redis.RedisCache",
        "django.contrib.sessions.backends.cached_db",
    ]
