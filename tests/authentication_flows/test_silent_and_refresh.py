import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from model_bakery import baker
from oauth2_provider.models import Application

User = get_user_model()
VERIFIER = "s" * 50
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)
REDIRECT = "http://localhost/cb"


@pytest.fixture
def user():
    user = User.objects.create_user("A", "B", "a@example.com", "x", is_active=True)
    user.last_login = timezone.now()
    user.save()
    return user


def make_app(user, **extra):
    return baker.make(
        Application,
        client_type="confidential",
        authorization_grant_type="authorization-code",
        redirect_uris=REDIRECT,
        algorithm="RS256",
        client_id="cid",
        client_secret="sec",
        user=user,
        **extra,
    )


def authorize(client, **params):
    return client.get(
        "/o/authorize/",
        {
            "client_id": "cid",
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "scope": "openid",
            "state": "xyz",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            **params,
        },
    )


def query(response):
    return parse_qs(urlparse(response["Location"]).query)


@pytest.mark.django_db
class TestPromptNone:
    def test_signed_out_gets_login_required(self, client, user):
        make_app(user)
        response = authorize(client, prompt="none")
        assert response.status_code == 302
        assert query(response)["error"] == ["login_required"]

    def test_first_party_app_gets_code_silently(self, client, user):
        make_app(user, skip_authorization=True)
        client.force_login(user)
        response = authorize(client, prompt="none")
        assert response.status_code == 302
        assert "code" in query(response)
        assert query(response)["state"] == ["xyz"]

    def test_unconsented_app_gets_consent_required_not_a_page(self, client, user):
        make_app(user)
        client.force_login(user)
        response = authorize(client, prompt="none")
        assert response.status_code == 302
        assert response["Location"].startswith(REDIRECT)
        assert query(response)["error"] == ["consent_required"]
        assert query(response)["state"] == ["xyz"]

    def test_without_prompt_none_consent_page_still_shown(self, client, user):
        make_app(user)
        client.force_login(user)
        assert authorize(client).status_code == 200


@pytest.mark.django_db
def test_replayed_refresh_token_revokes_the_family(client, user):
    make_app(user, skip_authorization=True)
    client.force_login(user)
    code = query(authorize(client))["code"][0]
    basic = {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(b"cid:sec").decode()}

    def token(**data):
        return client.post("/o/token/", data, **basic)

    first = token(
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
    ).json()
    second = token(grant_type="refresh_token", refresh_token=first["refresh_token"])
    assert second.status_code == 200

    # An attacker replays the stolen, already-rotated token...
    assert (
        token(
            grant_type="refresh_token", refresh_token=first["refresh_token"]
        ).status_code
        == 400
    )
    # ...which also kills the legitimate client's current refresh token.
    current = token(
        grant_type="refresh_token", refresh_token=second.json()["refresh_token"]
    )
    assert current.status_code == 400
