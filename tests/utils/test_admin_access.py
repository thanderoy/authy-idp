import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django_otp.plugins.otp_static.models import StaticDevice

from modules.utils.middleware import IPWhitelistMiddleware

User = get_user_model()
PASSWORD = "Adm1n-P@ssword-2026"


@pytest.fixture
def check(settings):
    settings.DEBUG = False
    settings.ADMIN_URL = "ops-console/"
    middleware = IPWhitelistMiddleware(lambda r: None)

    def run(ip, path="/ops-console/"):
        response = middleware.process_request(
            RequestFactory().get(path, REMOTE_ADDR=ip)
        )
        return 200 if response is None else response.status_code

    return run


class TestAdminIPWhitelist:
    def test_empty_whitelist_denies_in_production(self, check, settings):
        settings.ADMIN_IP_WHITELIST = []
        assert check("203.0.113.5") == 403

    def test_cidr_range_allows_members_only(self, check, settings):
        settings.ADMIN_IP_WHITELIST = ["10.8.0.0/24"]
        assert check("10.8.0.42") == 200
        assert check("10.8.1.42") == 403

    def test_star_allows_everyone_explicitly(self, check, settings):
        settings.ADMIN_IP_WHITELIST = ["*"]
        assert check("203.0.113.5") == 200

    def test_invalid_entry_is_ignored_not_fatal(self, check, settings):
        settings.ADMIN_IP_WHITELIST = ["not-an-ip", "10.8.0.1"]
        assert check("10.8.0.1") == 200

    def test_follows_configured_admin_url(self, check, settings):
        settings.ADMIN_IP_WHITELIST = []
        assert check("203.0.113.5", path="/admin/") == 200  # not the admin any more


@pytest.mark.django_db
class TestAdminRequiresOTP:
    """With ADMIN_REQUIRE_OTP (the default outside DEBUG) a password alone
    doesn't open the admin; a token from a confirmed device is needed too."""

    @pytest.fixture(autouse=True)
    def _open_whitelist(self, settings):
        settings.ADMIN_IP_WHITELIST = ["*"]

    @pytest.fixture
    def admin_user(self):
        return User.objects.create_superuser(
            "Ada", "Admin", "ada@example.com", PASSWORD
        )

    def _login(self, client, **extra):
        return client.post(
            "/admin/login/?next=/admin/",
            {"username": "ada@example.com", "password": PASSWORD, **extra},
        )

    def test_password_alone_is_refused(self, client, admin_user):
        response = self._login(client)
        assert response.status_code == 200  # login form shown again
        assert client.get("/admin/").status_code == 302

    def test_password_and_static_token_opens_admin(self, client, admin_user):
        device = StaticDevice.objects.create(user=admin_user, name="backup")
        device.token_set.create(token="bootstrap1")
        response = self._login(
            client, otp_device=device.persistent_id, otp_token="bootstrap1"
        )
        assert response.status_code == 302
        assert client.get("/admin/").status_code == 200

    def test_static_token_is_single_use(self, client, admin_user):
        device = StaticDevice.objects.create(user=admin_user, name="backup")
        device.token_set.create(token="bootstrap1")
        self._login(client, otp_device=device.persistent_id, otp_token="bootstrap1")
        client.logout()
        self._login(client, otp_device=device.persistent_id, otp_token="bootstrap1")
        assert client.get("/admin/").status_code == 302


@pytest.mark.django_db
class TestMetricsEndpoint:
    def test_served_to_whitelisted_scraper(self, client, settings):
        settings.METRICS_IP_WHITELIST = ["10.0.0.0/8"]
        response = client.get("/metrics", REMOTE_ADDR="10.1.2.3")
        assert response.status_code == 200
        assert b"django_http_requests" in response.content

    def test_refused_when_whitelist_empty(self, client, settings):
        settings.METRICS_IP_WHITELIST = []
        assert client.get("/metrics", REMOTE_ADDR="10.1.2.3").status_code == 403

    def test_refused_outside_whitelist(self, client, settings):
        settings.METRICS_IP_WHITELIST = ["10.0.0.0/8"]
        assert client.get("/metrics", REMOTE_ADDR="203.0.113.9").status_code == 403
