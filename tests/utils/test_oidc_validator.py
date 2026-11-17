import pytest
import hashlib
from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.core.cache import cache
from oauthlib.common import Request
from modules.utils.oidc_validator import EnhancedAuthyOAuth2Validator

User = get_user_model()


@pytest.fixture
def validator():
    return EnhancedAuthyOAuth2Validator()


@pytest.fixture
def mock_request():
    req = MagicMock(spec=Request)
    req.scopes = ["openid", "profile", "email", "groups"]
    req.user = MagicMock()
    req.user.id = 1
    req.user.first_name = "Test"
    req.user.last_name = "User"
    req.user.email = "test@example.com"
    req.user.email_verified = True
    req.user.entity_type = "PSN"

    # Mock groups
    group_mock = MagicMock()
    group_mock.filter.return_value.values_list.return_value = [
        ("Group", "One"),
        ("Group", "Two"),
    ]
    req.user.parent_entities = group_mock
    req.client = MagicMock()
    req.client.client_id = "test-client"
    return req


@pytest.mark.django_db
class TestEnhancedValidator:
    def setup_method(self):
        cache.clear()

    def test_get_additional_claims(self, validator, mock_request):
        claims = validator.get_additional_claims(mock_request)
        assert claims["first_name"] == "Test"
        assert claims["email"] == "test@example.com"
        assert claims["entity_type"] == "PSN"
        assert claims["groups"] == ["Group One", "Group Two"]

    def test_validate_bearer_token_blacklisted(self, validator, mock_request):
        validator._blacklist_token("bad_token", "access_token")
        assert (
            validator.validate_bearer_token("bad_token", ["openid"], mock_request)
            is False
        )

    @patch(
        "oauth2_provider.oauth2_validators.OAuth2Validator.validate_bearer_token",
        return_value=True,
    )
    def test_validate_bearer_token_valid(self, mock_super, validator, mock_request):
        # We also want to map out _log_token_usage logic
        mock_request.META = {"REMOTE_ADDR": "127.0.0.1"}
        assert (
            validator.validate_bearer_token("good_token", ["openid"], mock_request)
            is True
        )
        assert (
            cache.get(f"token_last_used:{hashlib.sha256(b'good_token').hexdigest()}")
            == "127.0.0.1"
        )

    def test_validate_client_id_rate_limited(self, validator, mock_request):
        # Trigger lockout
        for _ in range(5):
            validator._record_failed_attempt("spam_client")
        assert validator.validate_client_id("spam_client", mock_request) is False

    @patch(
        "oauth2_provider.oauth2_validators.OAuth2Validator.validate_client_id",
        return_value=False,
    )
    def test_validate_client_id_failure_records_attempt(
        self, mock_super, validator, mock_request
    ):
        assert validator.validate_client_id("bad_client", mock_request) is False
        assert cache.get("failed_attempts:bad_client") == 1

    def test_validate_code_replay_attack(self, validator, mock_request):
        cache.set("auth_code_used:used_code", True)
        assert (
            validator.validate_code("client", "used_code", MagicMock(), mock_request)
            is False
        )

    @patch(
        "oauth2_provider.oauth2_validators.OAuth2Validator.validate_code",
        return_value=True,
    )
    def test_validate_code_success_caches_it(self, mock_super, validator, mock_request):
        assert (
            validator.validate_code("client", "fresh_code", MagicMock(), mock_request)
            is True
        )
        assert cache.get("auth_code_used:fresh_code") is True

    @patch("oauth2_provider.oauth2_validators.OAuth2Validator.save_bearer_token")
    def test_save_bearer_token(self, mock_super, validator, mock_request):
        token = {"access_token": "at", "refresh_token": "rt"}
        validator.save_bearer_token(token, mock_request)
        mock_super.assert_called_once()

    @patch("oauth2_provider.oauth2_validators.OAuth2Validator.revoke_token")
    def test_revoke_token_blacklists(self, mock_super, validator, mock_request):
        validator.revoke_token("rt", "refresh_token", mock_request)
        assert cache.get(f"blacklist:{hashlib.sha256(b'rt').hexdigest()}") is True
        mock_super.assert_called_once()

    def test_introspect_token_blacklisted(self, validator, mock_request):
        validator._blacklist_token("bad_token", "access_token")
        res = validator.introspect_token("bad_token", "access_token", mock_request)
        assert res["active"] is False

    @patch(
        "oauth2_provider.oauth2_validators.OAuth2Validator.introspect_token",
        return_value={"active": True},
    )
    def test_introspect_token_valid(self, mock_super, validator, mock_request):
        cache.set(f"token_issued:{hashlib.sha256(b'good').hexdigest()}", "time")
        res = validator.introspect_token("good", "access_token", mock_request)
        assert res["issued_at"] == "time"

    def test_log_token_usage_fallback_request(self, validator, mock_request):
        # Mock oauthlib request that wraps a django request
        django_req = MagicMock()
        django_req.META = {"REMOTE_ADDR": "192.168.1.1"}
        mock_request.request = django_req
        del mock_request.META

        validator._log_token_usage("token", mock_request)
        assert (
            cache.get(f"token_last_used:{hashlib.sha256(b'token').hexdigest()}")
            == "192.168.1.1"
        )
