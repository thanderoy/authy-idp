"""Settings guards that only apply with DEBUG=False (see the load_settings
fixture in conftest.py)."""

PROBE = (
    "import os;os.environ['DJANGO_SETTINGS_MODULE']='config.settings';"
    "from django.conf import settings as s;"
    "print(s.CACHES['default']['BACKEND'], s.SESSION_ENGINE)"
)


def test_production_refuses_to_start_without_redis(load_settings):
    result = load_settings(PROBE, REDIS_URL="")
    assert result.returncode != 0
    assert "REDIS_URL is required" in result.stderr


def test_production_uses_redis_and_durable_sessions(load_settings):
    result = load_settings(PROBE)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "django.core.cache.backends.redis.RedisCache",
        "django.contrib.sessions.backends.cached_db",
    ]


def test_refuses_to_start_without_signing_key(load_settings):
    result = load_settings(PROBE, OIDC_RSA_PRIVATE_KEY_PATH="/nonexistent/oidc.key")
    assert result.returncode != 0
    assert "OIDC signing key not found at /nonexistent/oidc.key" in result.stderr


def test_signing_key_read_from_path_and_inactive_keys_published(
    load_settings, key_file
):
    probe = (
        "import os,json;os.environ['DJANGO_SETTINGS_MODULE']='config.settings';"
        "import django;django.setup();"
        "from django.test import Client;"
        "r=Client().get('/o/.well-known/jwks.json', secure=True);"
        "print(r.status_code, len(json.loads(r.content)['keys']))"
    )
    result = load_settings(
        probe,
        OIDC_RSA_PRIVATE_KEY_PATH=str(key_file("active.pem")),
        OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS=str(key_file("old.pem")),
        ALLOWED_HOSTS="testserver",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["200", "2"]


def test_log_dir_is_created(load_settings, tmp_path):
    log_dir = tmp_path / "fresh" / "logs"
    result = load_settings(PROBE, LOG_DIR=str(log_dir))
    assert result.returncode == 0, result.stderr
    assert log_dir.is_dir()
