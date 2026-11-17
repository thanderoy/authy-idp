"""Email address verification.

A signed, single-use link proves the user controls the address. The token
hash includes the email and ``email_verified``, so the link stops working
once it has been used or the address changes.
"""

import logging
import smtplib

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.http import HttpRequest
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from modules.entities.models import Entity

logger = logging.getLogger(__name__)


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "modules.entities.verification.EmailVerificationTokenGenerator"

    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{user.email}{user.email_verified}{timestamp}"


email_verification_token = EmailVerificationTokenGenerator()


def send_verification_email(request: HttpRequest, user: Entity) -> bool:
    """Send the link; return False (and log) if the mail server fails, so a
    mail outage doesn't break sign-up. The user can resend from the console."""
    path = reverse(
        "verify_email",
        kwargs={
            "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": email_verification_token.make_token(user),
        },
    )
    context = {"user": user, "verify_url": request.build_absolute_uri(path)}
    subject = render_to_string("registration/verify_email_subject.txt", context).strip()
    body = render_to_string("registration/verify_email_email.txt", context)
    try:
        send_mail(subject, body, None, [user.email])
    except (smtplib.SMTPException, OSError):
        logger.exception("Could not send verification email to user %s", user.pk)
        return False
    return True
