import base64

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from model_bakery import baker
from oauth2_provider.models import Application

from modules.utils import throttling

User = get_user_model()
PASSWORD = "Correct-H0rse-Battery"


@pytest.fixture
def user():
    return User.objects.create_user("A", "B", "a@example.com", PASSWORD, is_active=True)


def _login(client, password, email="a@example.com", ip="198.51.100.1"):
    return client.post(
        "/login/", {"username": email, "password": password}, REMOTE_ADDR=ip
    )


def test_hit_counts_within_window():
    assert [throttling.hit("k", 60) for _ in range(3)] == [1, 2, 3]
    throttling.reset("k")
    assert throttling.count("k") == 0


@pytest.mark.django_db
class TestAccountLockout:
    def test_correct_password_refused_after_too_many_failures(self, client, user):
        # Spread over IPs so only the per-account lockout is in play.
        for i in range(5):
            _login(client, "wrong", ip=f"198.51.100.{i}")
        response = _login(client, PASSWORD, ip="198.51.100.99")
        assert response.status_code == 200  # form re-rendered, not redirected
        assert "_auth_user_id" not in client.session

    def test_lockout_is_case_insensitive(self, client, user):
        for i in range(5):
            _login(client, "wrong", email="A@Example.com", ip=f"198.51.100.{i}")
        _login(client, PASSWORD, ip="198.51.100.99")
        assert "_auth_user_id" not in client.session

    def test_success_resets_counter(self, client, user):
        for i in range(4):
            _login(client, "wrong", ip=f"198.51.100.{i}")
        assert _login(client, PASSWORD).status_code == 302
        client.logout()
        for i in range(4):
            _login(client, "wrong", ip=f"198.51.100.{i}")
        assert _login(client, PASSWORD).status_code == 302

    def test_password_grant_is_locked_too(self, client, user):
        baker.make(
            Application,
            client_type="confidential",
            authorization_grant_type="password",
            client_id="cid",
            client_secret="sec",
            user=user,
        )
        auth = base64.b64encode(b"cid:sec").decode()
        for i in range(5):
            _login(client, "wrong", ip=f"198.51.100.{i}")
        response = client.post(
            "/o/token/",
            {
                "grant_type": "password",
                "username": "a@example.com",
                "password": PASSWORD,
            },
            HTTP_AUTHORIZATION=f"Basic {auth}",
        )
        assert response.status_code == 400
        assert "access_token" not in response.json()


@pytest.mark.django_db
class TestRouteLimits:
    @pytest.fixture(autouse=True)
    def _production_mode(self, settings):
        settings.DEBUG = False

    def test_login_posts_limited_per_ip(self, client, user):
        statuses = [
            _login(client, "wrong", email=f"u{i}@example.com").status_code
            for i in range(11)
        ]
        assert 429 not in statuses[:10]
        assert statuses[10] == 429

    def test_login_page_get_not_counted(self, client):
        for _ in range(20):
            assert client.get("/login/").status_code == 200


@pytest.mark.django_db
class TestPasswordResetFlood:
    def test_one_address_gets_at_most_three_mails_an_hour(self, client, user):
        for i in range(6):
            response = client.post(
                "/password_reset/",
                {"email": "a@example.com"},
                REMOTE_ADDR=f"198.51.100.{i}",
            )
            # Same answer whether or not the mail went out.
            assert response.status_code == 302
        assert len(mail.outbox) == 3
