"""Authy OIDC URLs"""

import hashlib
import logging
import smtplib

from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views
from django.http import HttpResponseRedirect
from django_otp.admin import OTPAdminSite
from oauth2_provider import urls as oauth2_urls

from modules.entities.mixins import BrandedAuthMixin
from modules.entities.views import RegisterView, VerifyEmailView
from modules.utils import throttling
from modules.utils.authorization import SilentAwareAuthorizationView


logger = logging.getLogger(__name__)


# -- Branded auth views (inject app branding via client_id) ----------------


class BrandedLoginView(BrandedAuthMixin, auth_views.LoginView):
    redirect_authenticated_user = True


class BrandedLogoutView(BrandedAuthMixin, auth_views.LogoutView):
    next_page = "/"


class BrandedPasswordResetView(BrandedAuthMixin, auth_views.PasswordResetView):
    def form_valid(self, form):
        # Cap mails per target address so the form can't flood an inbox
        # from many IPs. Over the cap we skip sending but answer the same
        # way, so the response doesn't reveal anything.
        email = form.cleaned_data["email"].strip().lower()
        digest = hashlib.sha256(email.encode()).hexdigest()
        sent = throttling.hit(f"password_reset:{digest}", 3600)
        if sent > settings.PASSWORD_RESET_EMAILS_PER_HOUR:
            return HttpResponseRedirect(self.get_success_url())
        try:
            return super().form_valid(form)
        except (smtplib.SMTPException, OSError):
            # Same answer as success: a mail outage shouldn't be a 500, nor
            # reveal whether the address has an account.
            logger.exception("Could not send password reset email")
            return HttpResponseRedirect(self.get_success_url())


class BrandedPasswordResetDoneView(BrandedAuthMixin, auth_views.PasswordResetDoneView):
    pass


class BrandedPasswordResetConfirmView(
    BrandedAuthMixin, auth_views.PasswordResetConfirmView
):
    pass


class BrandedPasswordResetCompleteView(
    BrandedAuthMixin, auth_views.PasswordResetCompleteView
):
    pass


class BrandedRegisterView(BrandedAuthMixin, RegisterView):
    pass


# --------------------------------------------------------------------------

if settings.ADMIN_REQUIRE_OTP:
    # Admin login then asks for a TOTP or static backup token as well.
    admin.site.__class__ = OTPAdminSite

urlpatterns = [
    # Nothing lives at the root; send people to their account console
    # (which sends signed-out visitors on to the login page).
    path("", RedirectView.as_view(pattern_name="entities:console_profile")),
    path(settings.ADMIN_URL, admin.site.urls),
    # Shadows DOT's authorize URL (same path, matched first).
    path(
        "o/authorize/",
        SilentAwareAuthorizationView.as_view(),
        name="authorize",
    ),
    path("o/", include(oauth2_urls)),
    path("entities/", include("modules.entities.urls", namespace="entities")),
    path("register/", BrandedRegisterView.as_view(), name="register"),
    path(
        "verify-email/<uidb64>/<token>/",
        VerifyEmailView.as_view(),
        name="verify_email",
    ),
    path("login/", BrandedLoginView.as_view(), name="login"),
    path("logout/", BrandedLogoutView.as_view(), name="logout"),
    path(
        "password_reset/",
        BrandedPasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "password_reset/done/",
        BrandedPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        BrandedPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        BrandedPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]

if "django_prometheus" in settings.INSTALLED_APPS:
    # /metrics, restricted to METRICS_IP_WHITELIST by IPWhitelistMiddleware.
    urlpatterns.append(path("", include("django_prometheus.urls")))
