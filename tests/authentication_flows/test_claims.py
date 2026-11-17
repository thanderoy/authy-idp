"""Claims released per scope, through the real authorize/token/userinfo
endpoints, for both the ID token and userinfo."""

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from model_bakery import baker
from oauth2_provider.models import Application

from modules.entities.models import Relationship
from tests.authentication_flows.test_silent_and_refresh import (
    CHALLENGE,
    REDIRECT,
    VERIFIER,
)

User = get_user_model()
ALWAYS = {"sub"}


@pytest.fixture
def tokens(client):
    user = User.objects.create_user(
        "Ada", "Lovelace", "ada@example.com", "x", is_active=True
    )
    user.last_login = timezone.now()
    user.save()
    group = User.objects.create_user(
        "Ops", "Team", "ops@example.com", "x", entity_type="GRP"
    )
    Relationship.objects.create(parent=group, child=user)
    baker.make(
        Application,
        client_type="confidential",
        authorization_grant_type="authorization-code",
        redirect_uris=REDIRECT,
        algorithm="RS256",
        client_id="cid",
        client_secret="sec",
        user=user,
        skip_authorization=True,
    )
    client.force_login(user)

    def issue(scope):
        location = client.get(
            "/o/authorize/",
            {
                "client_id": "cid",
                "redirect_uri": REDIRECT,
                "response_type": "code",
                "scope": scope,
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
            },
        )["Location"]
        body = client.post(
            "/o/token/",
            {
                "grant_type": "authorization_code",
                "code": parse_qs(urlparse(location).query)["code"][0],
                "redirect_uri": REDIRECT,
                "code_verifier": VERIFIER,
            },
            HTTP_AUTHORIZATION="Basic " + base64.b64encode(b"cid:sec").decode(),
        ).json()
        payload = body["id_token"].split(".")[1]
        id_token = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        userinfo = client.get(
            "/o/userinfo/", HTTP_AUTHORIZATION=f"Bearer {body['access_token']}"
        ).json()
        user_claims = set(userinfo)
        token_claims = set(id_token) - {
            "aud",
            "iat",
            "exp",
            "iss",
            "jti",
            "auth_time",
            "at_hash",
            "nonce",
        }
        return token_claims, user_claims, id_token, userinfo

    return issue


@pytest.mark.django_db
class TestClaimsFollowScopes:
    def test_openid_only_releases_sub(self, tokens):
        token_claims, user_claims, _, _ = tokens("openid")
        assert token_claims == ALWAYS
        assert user_claims == ALWAYS

    def test_profile_does_not_leak_email_or_groups(self, tokens):
        token_claims, user_claims, _, _ = tokens("openid profile")
        for claims in (token_claims, user_claims):
            assert {"name", "first_name", "last_name", "entity_type"} <= claims
            assert not {"email", "email_verified", "groups"} & claims

    def test_email_scope(self, tokens):
        token_claims, user_claims, id_token, _ = tokens("openid email")
        assert token_claims == user_claims == {"sub", "email", "email_verified"}
        assert id_token["email_verified"] is False

    def test_groups_are_names_in_both(self, tokens):
        _, _, id_token, userinfo = tokens("openid groups")
        assert id_token["groups"] == userinfo["groups"] == ["Ops Team"]
