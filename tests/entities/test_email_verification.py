import re

import pytest
from django.contrib.auth import get_user_model
from django.core import mail

from modules.entities.verification import email_verification_token
from modules.utils.oidc_validator import EnhancedAuthyOAuth2Validator

User = get_user_model()

REGISTER_PAYLOAD = {
    "first_name": "New",
    "last_name": "User",
    "email": "newuser@authy.io",
    "password1": "StrongP@ss2026!",
    "password2": "StrongP@ss2026!",
}


def _link_path(message):
    return re.search(r"https?://[^/]+(/verify-email/\S+/)", message.body).group(1)


@pytest.mark.django_db
class TestEmailVerification:
    def test_new_accounts_start_unverified(self):
        user = User.objects.create_user("A", "B", "a@example.com", "x")
        assert user.email_verified is False

    def test_registration_sends_verification_link(self, client):
        client.post("/register/", REGISTER_PAYLOAD)
        user = User.objects.get(email="newuser@authy.io")
        assert user.email_verified is False
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == ["newuser@authy.io"]
        assert "/verify-email/" in mail.outbox[0].body

    def test_link_verifies_once(self, client):
        client.post("/register/", REGISTER_PAYLOAD)
        path = _link_path(mail.outbox[0])

        assert client.get(path).status_code == 200
        assert User.objects.get(email="newuser@authy.io").email_verified is True
        # Single use: the hash includes email_verified.
        assert client.get(path).status_code == 400

    def test_link_dies_when_email_changes(self, client):
        user = User.objects.create_user("A", "B", "a@example.com", "x")
        token = email_verification_token.make_token(user)
        user.email = "b@example.com"
        user.save()
        assert not email_verification_token.check_token(user, token)

    def test_bad_link_is_rejected(self, client):
        response = client.get("/verify-email/bm9wZQ/not-a-token/")
        assert response.status_code == 400

    def test_resend_requires_post_and_login(self, client):
        assert client.post("/entities/console/verify-email/resend/").status_code == 302
        user = User.objects.create_user("A", "B", "a@example.com", "x", is_active=True)
        client.force_login(user)
        assert client.get("/entities/console/verify-email/resend/").status_code == 405
        client.post("/entities/console/verify-email/resend/")
        assert len(mail.outbox) == 1

    def test_resend_skipped_when_already_verified(self, client):
        user = User.objects.create_user(
            "A", "B", "a@example.com", "x", is_active=True, email_verified=True
        )
        client.force_login(user)
        client.post("/entities/console/verify-email/resend/")
        assert mail.outbox == []

    def test_token_claim_reflects_real_state(self, rf):
        from unittest.mock import MagicMock

        user = User.objects.create_user("A", "B", "a@example.com", "x")
        request = MagicMock(user=user)
        claims = EnhancedAuthyOAuth2Validator().get_additional_claims(request)
        assert claims["email_verified"] is False
