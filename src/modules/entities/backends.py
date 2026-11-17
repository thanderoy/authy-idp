"""Authentication backend with per-account lockout.

It wraps ModelBackend, so the login form, the admin and the OAuth password
grant all go through the same lockout.
"""

import hashlib
import logging

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from modules.utils import throttling

logger = logging.getLogger(__name__)


def _key(username: str) -> str:
    digest = hashlib.sha256(username.strip().lower().encode()).hexdigest()
    return f"login_failures:{digest}"


def is_locked_out(username: str) -> bool:
    return throttling.count(_key(username)) >= settings.LOGIN_LOCKOUT_ATTEMPTS


class LockoutModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get("email")
        if not username:
            return super().authenticate(request, username, password, **kwargs)

        if is_locked_out(username):
            logger.warning("Login refused: account temporarily locked")
            # PermissionDenied stops Django trying the remaining backends.
            raise PermissionDenied

        user = super().authenticate(request, username, password, **kwargs)
        if user is None:
            throttling.hit(_key(username), settings.LOGIN_LOCKOUT_SECONDS)
        else:
            throttling.reset(_key(username))
        return user
