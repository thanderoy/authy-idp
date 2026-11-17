import pytest
from django.test import RequestFactory, override_settings

from modules.utils.client_ip import get_client_ip
from modules.utils.middleware import RateLimitMiddleware


@pytest.fixture
def rf():
    return RequestFactory()


def test_direct_connection_uses_remote_addr(rf, settings):
    settings.TRUSTED_PROXY_COUNT = 0
    request = rf.get("/", REMOTE_ADDR="203.0.113.9", HTTP_X_FORWARDED_FOR="1.1.1.1")
    assert get_client_ip(request) == "203.0.113.9"


@override_settings(TRUSTED_PROXY_COUNT=1)
def test_one_proxy_takes_rightmost_entry(rf):
    # The client prepended a fake address; Traefik appended the real one.
    request = rf.get(
        "/",
        REMOTE_ADDR="172.18.0.2",
        HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.7",
    )
    assert get_client_ip(request) == "198.51.100.7"


@override_settings(TRUSTED_PROXY_COUNT=2)
def test_two_proxies_skip_the_inner_hop(rf):
    request = rf.get(
        "/",
        REMOTE_ADDR="10.0.0.2",
        HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.7, 10.0.0.1",
    )
    assert get_client_ip(request) == "198.51.100.7"


@override_settings(TRUSTED_PROXY_COUNT=1)
def test_missing_header_falls_back_to_remote_addr(rf):
    request = rf.get("/", REMOTE_ADDR="172.18.0.2")
    assert get_client_ip(request) == "172.18.0.2"


@pytest.mark.django_db
@override_settings(TRUSTED_PROXY_COUNT=1, DEBUG=False)
def test_rate_limit_is_per_client_not_per_proxy(rf):
    from django.contrib.auth.models import AnonymousUser
    from django.core.cache import cache

    cache.clear()
    middleware = RateLimitMiddleware(lambda r: None)

    def hit(client):
        request = rf.post(
            "/o/token/", REMOTE_ADDR="172.18.0.2", HTTP_X_FORWARDED_FOR=client
        )
        request.user = AnonymousUser()
        return middleware.process_request(request)

    for _ in range(RateLimitMiddleware.TOKEN_ENDPOINT_LIMIT):
        assert hit("198.51.100.7") is None
    assert hit("198.51.100.7").status_code == 429
    # A different client behind the same proxy is unaffected.
    assert hit("198.51.100.8") is None


@pytest.mark.django_db
@override_settings(
    SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    SECURE_SSL_REDIRECT=True,
    ALLOWED_HOSTS=["auth.example.com"],
    USE_X_FORWARDED_HOST=True,
)
def test_behind_tls_terminating_proxy_no_redirect_and_https_issuer(client):
    # Traefik talks plain HTTP to the app; without trusting the forwarded
    # proto every request would be redirected to https forever.
    response = client.get(
        "/o/.well-known/openid-configuration",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_X_FORWARDED_HOST="auth.example.com",
    )
    assert response.status_code == 200
    assert response.json()["issuer"].startswith("https://auth.example.com/")
    assert response.json()["token_endpoint"].startswith("https://")


def test_settings_trust_proxy_headers_only_when_configured():
    import subprocess
    import sys

    probe = (
        "import django,os;os.environ['DJANGO_SETTINGS_MODULE']='config.settings';"
        "from django.conf import settings as s;"
        "print(getattr(s,'SECURE_PROXY_SSL_HEADER',None), s.USE_X_FORWARDED_HOST)"
    )
    env = {"DJANGO_SECRET_KEY": "x", "PATH": "/usr/bin:/bin", "PYTHONPATH": "src"}
    direct = subprocess.run(
        [sys.executable, "-c", probe], env=env, capture_output=True, text=True
    )
    proxied = subprocess.run(
        [sys.executable, "-c", probe],
        env={**env, "TRUSTED_PROXY_COUNT": "1"},
        capture_output=True,
        text=True,
    )
    assert direct.stdout.strip() == "None False", direct.stderr
    assert proxied.stdout.strip() == "('HTTP_X_FORWARDED_PROTO', 'https') True"
