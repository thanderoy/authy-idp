"""Enhanced OAuth2 Validator with additional security features"""

import hashlib
import logging
from typing import Dict, Any, Optional
from django.contrib.auth import get_user_model
from django.core.cache import cache
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.common import Request

from modules.utils.client_ip import get_client_ip

logger = logging.getLogger(__name__)
User = get_user_model()


def fingerprint(token: str) -> str:
    """Short, non-reversible tag for correlating a token across log lines."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


class EnhancedAuthyOAuth2Validator(OAuth2Validator):
    """Enhanced OAuth2 Validator with additional security and functionality"""

    # Which scope releases each claim. DOT applies this to both the ID token
    # and userinfo; a claim missing from the map is never released.
    oidc_claim_scope = {
        **OAuth2Validator.oidc_claim_scope,
        "first_name": "profile",
        "last_name": "profile",
        "entity_type": "profile",
        "groups": "groups",
    }

    # Rate limiting constants
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes in seconds

    def get_additional_claims(self, request) -> Dict[str, Any]:
        """
        Get additional claims to include in tokens.

        Args:
            request: The OAuth2 request object

        Returns:
            Dictionary of additional claims
        """
        user = request.user
        claims = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "email_verified": user.email_verified,
            "preferred_username": user.email,
            "name": f"{user.first_name} {user.last_name}".strip(),
        }

        # Add entity type if available
        if hasattr(user, "entity_type"):
            claims["entity_type"] = user.entity_type

        # Add groups if user has them (names, same in ID token and userinfo)
        if hasattr(user, "parent_entities"):
            groups = user.parent_entities.filter(entity_type="GRP").values_list(
                "first_name", "last_name"
            )
            claims["groups"] = [f"{first} {last}".strip() for first, last in groups]

        return claims

    def validate_bearer_token(self, token: str, scopes: list, request: Request) -> bool:
        """
        Validate bearer token with additional security checks.

        Args:
            token: The bearer token
            scopes: Required scopes
            request: The request object

        Returns:
            Boolean indicating if token is valid
        """
        # Check if token is blacklisted
        if self._is_token_blacklisted(token):
            logger.warning(f"Attempted use of blacklisted token: {fingerprint(token)}")
            return False

        # Perform standard validation
        is_valid = super().validate_bearer_token(token, scopes, request)

        if is_valid:
            # Log successful token validation for audit
            self._log_token_usage(token, request)

        return is_valid

    def validate_client_id(
        self, client_id: str, request: Request, *args, **kwargs
    ) -> bool:
        """
        Validate client ID with rate limiting.

        Args:
            client_id: The client ID to validate
            request: The request object

        Returns:
            Boolean indicating if client ID is valid
        """
        # Check if client is rate limited
        if self._is_client_rate_limited(client_id):
            logger.warning(f"Rate limited client attempted access: {client_id}")
            return False

        # Perform standard validation
        is_valid = super().validate_client_id(client_id, request, *args, **kwargs)

        if not is_valid:
            self._record_failed_attempt(client_id)

        return is_valid

    def validate_code(
        self, client_id: str, code: str, client: Any, request: Request, *args, **kwargs
    ) -> bool:
        """
        Validate authorization code with additional security.

        Args:
            client_id: The client ID
            code: The authorization code
            client: The client object
            request: The request object

        Returns:
            Boolean indicating if code is valid
        """
        # Check for code replay attacks
        code_key = f"auth_code_used:{code}"
        if cache.get(code_key):
            logger.error(
                f"Authorization code replay attack detected for client: {client_id}"
            )
            return False

        # Perform standard validation
        is_valid = super().validate_code(
            client_id, code, client, request, *args, **kwargs
        )

        if is_valid:
            # Mark code as used
            cache.set(code_key, True, timeout=600)  # 10 minutes

        return is_valid

    def save_bearer_token(
        self, token: Dict[str, Any], request: Request, *args, **kwargs
    ) -> None:
        """
        Save bearer token with additional metadata.

        Args:
            token: The token dictionary
            request: The request object
        """
        # Log token issuance for audit
        self._log_token_issuance(token, request)

        super().save_bearer_token(token, request, *args, **kwargs)

    def revoke_token(
        self, token: str, token_type_hint: str, request: Request, *args, **kwargs
    ) -> None:
        """
        Revoke token with cascading revocation.

        Args:
            token: The token to revoke
            token_type_hint: Hint about token type
            request: The request object
        """
        # Add to blacklist
        self._blacklist_token(token, token_type_hint)

        # Log revocation for audit
        self._log_token_revocation(token, request)

        super().revoke_token(token, token_type_hint, request, *args, **kwargs)

    def introspect_token(
        self, token: str, token_type_hint: str, request: Request, *args, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Introspect token with additional information.

        Args:
            token: The token to introspect
            token_type_hint: Hint about token type
            request: The request object

        Returns:
            Token introspection response
        """
        # Check blacklist first
        if self._is_token_blacklisted(token):
            return {"active": False, "reason": "token_revoked"}

        # Get standard introspection
        introspection = super().introspect_token(
            token, token_type_hint, request, *args, **kwargs
        )

        if introspection and introspection.get("active"):
            # Add additional metadata
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            introspection["issued_at"] = cache.get(f"token_issued:{token_hash}")
            introspection["last_used"] = cache.get(f"token_last_used:{token_hash}")

        return introspection

    def validate_silent_login(self, request: Request) -> bool:
        """prompt=none: is someone signed in?

        Always yes by the time oauthlib asks: DOT's AuthorizationView answers
        an unauthenticated prompt=none request with login_required itself.
        """
        return True

    def validate_silent_authorization(self, request: Request) -> bool:
        """prompt=none: has the user already consented?

        The user isn't on the oauthlib request at this point, so the decision
        is made in SilentAwareAuthorizationView, which returns
        consent_required instead of showing the consent page.
        """
        return True

    # Helper methods

    def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        key = f"blacklist:{hashlib.sha256(token.encode()).hexdigest()}"
        return cache.get(key) is not None

    def _blacklist_token(self, token: str, token_type: str) -> None:
        """Add token to blacklist"""
        timeout = 86400 if token_type == "refresh_token" else 3600
        key = f"blacklist:{hashlib.sha256(token.encode()).hexdigest()}"
        cache.set(key, True, timeout=timeout)

    def _is_client_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited"""
        attempts = cache.get(f"failed_attempts:{client_id}", 0)
        return attempts >= self.MAX_FAILED_ATTEMPTS

    def _record_failed_attempt(self, client_id: str) -> None:
        """Record a failed authentication attempt"""
        key = f"failed_attempts:{client_id}"
        attempts = cache.get(key, 0)
        cache.set(key, attempts + 1, timeout=self.LOCKOUT_DURATION)

    def _log_token_usage(self, token: str, request: Request) -> None:
        """Log token usage for audit"""
        remote_addr = "unknown"
        if hasattr(request, "META"):
            remote_addr = get_client_ip(request)
        elif hasattr(request, "request") and hasattr(request.request, "META"):
            remote_addr = get_client_ip(request.request)

        key = f"token_last_used:{hashlib.sha256(token.encode()).hexdigest()}"
        cache.set(key, remote_addr, timeout=3600)

    def _log_token_issuance(self, token: Dict[str, Any], request: Request) -> None:
        """Log token issuance for audit"""
        logger.info(
            f"Token issued to client {request.client.client_id} "
            f"for user {request.user.id if request.user else 'N/A'}"
        )

    def _log_token_revocation(self, token: str, request: Request) -> None:
        """Log token revocation for audit"""
        logger.info(
            f"Token revoked: {fingerprint(token)} by client {request.client.client_id if request.client else 'unknown'}"
        )
